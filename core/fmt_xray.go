package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/core"
	xdns "github.com/xtls/xray-core/features/dns"
	xoutbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"
)

var xrNonProxy = map[string]bool{"freedom": true, "direct": true, "blackhole": true, "block": true, "dns": true, "loopback": true}

var xrTOMLRe = regexp.MustCompile(`(?m)^\s*\[\[?\s*outbounds`)

var xrGeoRe = regexp.MustCompile(`(?i)geosite|geoip|\.dat\b|ext:`)

var xrStripKeys = []string{"inbounds", "env", "api", "metrics", "stats", "geodata"}

type xrFile struct {
	kind string
	docs []map[string]any
}

func xrLoad(f *vfile) (*xrFile, error) {
	t := strings.TrimSpace(string(pxStripJSONC(f.Data)))
	isTOML := f.Ext == "toml" || xrTOMLRe.MatchString(t)
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") && !isTOML {
		v, err := pxDecodeJSON(f.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		switch x := v.(type) {
		case map[string]any:
			return &xrFile{kind: "json", docs: []map[string]any{x}}, nil
		case []any:
			out := &xrFile{kind: "array"}
			for _, e := range x {
				m, _ := e.(map[string]any)
				out.docs = append(out.docs, m)
			}
			return out, nil
		}
		return nil, errors.New("not an Xray config")
	}
	var jb []byte
	var err error
	kind := "yaml"
	if isTOML {
		kind = "toml"
		jb, err = pxTOMLToJSON(f.Data)
	} else {
		jb, err = pxYAMLToJSON(f.Data)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", strings.ToUpper(kind), err)
	}
	v, err := pxDecodeJSON(jb)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an Xray config")
	}
	return &xrFile{kind: kind, docs: []map[string]any{m}}, nil
}

func xrCount(d map[string]any) (proxies, typed int) {
	for _, l := range []string{"outbounds", "inbounds"} {
		for _, o := range pxList(d, l) {
			m, ok := o.(map[string]any)
			if !ok {
				continue
			}
			if p := strings.ToLower(pxStr(m, "protocol")); p != "" {
				typed++
				if l == "outbounds" && !xrNonProxy[p] {
					proxies++
				}
			}
		}
	}
	return
}

type XrayConfigDetector struct{}

func (XrayConfigDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	t := f.Text()
	if !strings.Contains(t, "outbounds") && !strings.Contains(t, "inbounds") {
		return 0
	}
	if !strings.Contains(t, "protocol") {
		return 0
	}
	xf, err := xrLoad(f)
	if err != nil {
		if strings.Contains(t, "\"outbounds\"") && strings.Contains(t, "\"protocol\"") || xrTOMLRe.MatchString(t) {
			return 20
		}
		return 0
	}
	typed, proxies := 0, 0
	for _, d := range xf.docs {
		if d == nil {
			continue
		}
		p, ty := xrCount(d)
		proxies += p
		typed += ty
	}
	switch {
	case proxies > 0:
		return 80
	case typed > 0:
		return 55
	}
	return 0
}

type XrayConfigParser struct{}

func (XrayConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	xf, err := xrLoad(f)
	if err != nil {
		return nil, err
	}
	if xf.kind == "array" {
		out := make([]*Config, 0, len(xf.docs))
		for i, d := range xf.docs {
			if d == nil {
				out = append(out, invalidConfig(f, "Xray", fmt.Errorf("element %d is not a config object", i)))
				continue
			}
			out = append(out, xrParseDoc(f, fs, d, true)...)
		}
		return out, nil
	}
	return xrParseDoc(f, fs, xf.docs[0], false), nil
}

func xrProxyIdx(obs []any) []int {
	var out []int
	for i, o := range obs {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if p := strings.ToLower(pxStr(m, "protocol")); p != "" && !xrNonProxy[p] {
			out = append(out, i)
		}
	}
	return out
}

func xrPrepare(f *vfile, fs *vfs, doc map[string]any) (map[string]any, map[int][]*vfile) {
	d := pxCopyMap(doc)
	deps := map[int][]*vfile{}
	cur := 0
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ts, ok := x["tlsSettings"].(map[string]any); ok {
				delete(ts, "masterKeyLog")
				for _, c := range pxList(ts, "certificates") {
					cm, ok := c.(map[string]any)
					if !ok {
						continue
					}
					for _, pair := range [][2]string{{"certificateFile", "certificate"}, {"keyFile", "key"}} {
						p := pxStr(cm, pair[0])
						if p == "" {
							continue
						}
						cf := fs.Resolve(f, p)
						if cf == nil {
							continue
						}
						var lines []any
						for _, l := range strings.Split(strings.TrimSpace(cf.Text()), "\n") {
							lines = append(lines, l)
						}
						delete(cm, pair[0])
						cm[pair[1]] = lines
						deps[cur] = append(deps[cur], cf)
					}
				}
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	for i, o := range pxList(d, "outbounds") {
		cur = i
		walk(o)
	}
	return d, deps
}

func xrLogNone() map[string]any {
	return map[string]any{"loglevel": "none", "access": "none", "error": "none", "dnsLog": false}
}

func xrCheck(cfg map[string]any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xray: %v", r)
		}
	}()
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	c, err := serial.DecodeJSONConfig(bytes.NewReader(b))
	if err != nil {
		return err
	}
	pb, err := c.Build()
	if err != nil {
		return err
	}
	xrNewMu.Lock()
	inst, err := core.New(pb)
	xrNewMu.Unlock()
	if err != nil {
		return err
	}
	inst.Close()
	return nil
}

func xrValidate(doc map[string]any) error {
	cp := make(map[string]any, len(doc))
	for k, v := range doc {
		cp[k] = v
	}
	for _, k := range xrStripKeys {
		delete(cp, k)
	}
	cp["log"] = xrLogNone()
	return xrCheck(cp)
}

func xrStripGeo(doc map[string]any) map[string]any {
	cp := make(map[string]any, len(doc))
	for k, v := range doc {
		cp[k] = v
	}
	delete(cp, "dns")
	if r := pxMap(doc, "routing"); r != nil {
		nr := make(map[string]any, len(r))
		for k, v := range r {
			nr[k] = v
		}
		var rules []any
		for _, x := range pxList(r, "rules") {
			b, _ := json.Marshal(x)
			if xrGeoRe.Match(b) {
				continue
			}
			rules = append(rules, x)
		}
		nr["rules"] = rules
		cp["routing"] = nr
	}
	return cp
}

func xrDialer(ob map[string]any) string {
	ss := pxMap(ob, "streamSettings")
	if d := pxStr(pxMap(ss, "sockopt"), "dialerProxy"); d != "" {
		return d
	}
	return pxStr(pxMap(ob, "proxySettings"), "tag")
}

func xrChain(obs []any, ti int) ([]int, error) {
	tagIdx := map[string]int{}
	for i, o := range obs {
		if m, ok := o.(map[string]any); ok {
			if t := pxStr(m, "tag"); t != "" {
				if _, dup := tagIdx[t]; !dup {
					tagIdx[t] = i
				}
			}
		}
	}
	chain := []int{ti}
	seen := map[int]bool{ti: true}
	cur := ti
	for i := 0; i < 8; i++ {
		m, _ := obs[cur].(map[string]any)
		d := xrDialer(m)
		if d == "" {
			return chain, nil
		}
		j, ok := tagIdx[d]
		if !ok {
			return chain, fmt.Errorf("dialerProxy outbound %q not found", d)
		}
		if seen[j] {
			return chain, fmt.Errorf("dialerProxy loop at %q", d)
		}
		seen[j] = true
		chain = append(chain, j)
		cur = j
	}
	return chain, errors.New("dialerProxy chain too long")
}

func xrTestOutbound(ob map[string]any) (map[string]any, []string) {
	cp := pxCopyMap(ob)
	var notes []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if so, ok := x["sockopt"].(map[string]any); ok {
				for _, k := range []string{"mark", "interface"} {
					if pxHas(so, k) {
						delete(so, k)
						notes = append(notes, "sockopt."+k+" ignored during test")
					}
				}
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(cp)
	return cp, notes
}

var (
	xrNewMu   sync.Mutex
	xrChainMu sync.Mutex
	xrTagSeq  atomic.Uint64
)

type xrChainDialer struct {
	xrayDialer
	dc xdns.Client
	om xoutbound.Manager
}

func (d *xrChainDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	xrNewMu.Lock()
	internet.InitSystemDialer(d.dc, d.om)
	xrNewMu.Unlock()
	return d.xrayDialer.DialContext(ctx, network, addr)
}

func xrUniqueTags(obs []any) []any {
	seq := xrTagSeq.Add(1)
	out := make([]any, len(obs))
	ren := map[string]string{}
	for i, o := range obs {
		m := pxCopyMap(o.(map[string]any))
		if t := pxStr(m, "tag"); t != "" {
			nt := fmt.Sprintf("px%d-%s", seq, t)
			ren[t] = nt
			m["tag"] = nt
		}
		out[i] = m
	}
	for _, o := range out {
		so := pxMap(pxMap(o.(map[string]any), "streamSettings"), "sockopt")
		if d := pxStr(so, "dialerProxy"); d != "" {
			if nt, ok := ren[d]; ok {
				so["dialerProxy"] = nt
			}
		}
	}
	return out
}

func xrBuildChain(obs []any) (Dialer, error) {
	d, err := xrBuild(xrUniqueTags(obs))
	if err != nil {
		return nil, err
	}
	xd := d.(*xrayDialer)
	dc, _ := xd.inst.GetFeature(xdns.ClientType()).(xdns.Client)
	om, _ := xd.inst.GetFeature(xoutbound.ManagerType()).(xoutbound.Manager)
	if om == nil {
		xd.Close()
		return nil, errors.New("xray outbound manager unavailable")
	}
	return &xrChainDialer{xrayDialer: *xd, dc: dc, om: om}, nil
}

func xrBuild(obs []any) (Dialer, error) {
	cfg := map[string]any{"log": xrLogNone(), "outbounds": obs}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	c, err := serial.LoadJSONConfig(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	xrNewMu.Lock()
	inst, err := core.New(c)
	xrNewMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, err
	}
	return &xrayDialer{inst: inst}, nil
}

func xrSplitHostPort(s string) (string, int) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return strings.Trim(s, "[]"), 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func xrMeta(ob map[string]any) (nodeMeta, string) {
	var meta nodeMeta
	p := strings.ToLower(pxStr(ob, "protocol"))
	s := pxMap(ob, "settings")
	srv, user := s, s
	switch p {
	case "vless", "vmess":
		if vn := pxList(s, "vnext"); len(vn) > 0 {
			srv, _ = vn[0].(map[string]any)
			user = nil
			if us := pxList(srv, "users"); len(us) > 0 {
				user, _ = us[0].(map[string]any)
			}
		}
		meta.UUID = pxStr(user, "id")
	case "trojan", "shadowsocks", "socks", "http":
		if sv := pxList(s, "servers"); len(sv) > 0 {
			srv, _ = sv[0].(map[string]any)
			user = srv
			if us := pxList(srv, "users"); len(us) > 0 {
				user, _ = us[0].(map[string]any)
			}
		}
		if p == "socks" || p == "http" {
			meta.User = pxStr(user, "user")
			meta.Password = pxStr(user, "pass")
		} else {
			meta.Password = pxStr(srv, "password")
			meta.Extra = pxStr(srv, "method")
		}
	case "wireguard":
		if ps := pxList(s, "peers"); len(ps) > 0 {
			p0, _ := ps[0].(map[string]any)
			meta.Host, meta.Port = xrSplitHostPort(pxStr(p0, "endpoint"))
			meta.PublicKey = pxStr(p0, "publicKey")
		}
		meta.UDP = true
		meta.Transport = "udp"
	case "hysteria", "masque":
		meta.UDP = true
	}
	if p != "wireguard" {
		meta.Host = pxStr(srv, "address")
		meta.Port = pxInt(srv, "port")
	}
	ss := pxMap(ob, "streamSettings")
	if a := pxStr(ss, "address"); a != "" {
		meta.Host = a
	}
	if pp := pxInt(ss, "port"); pp > 0 {
		meta.Port = pp
	}
	netw := normNet(firstNonEmpty(pxStr(ss, "network"), pxStr(ss, "method")))
	if meta.Transport == "" {
		meta.Transport = netw
	}
	sec := strings.ToLower(pxStr(ss, "security"))
	if sec == "none" {
		sec = ""
	}
	meta.Security = sec
	ts := pxMap(ss, "tlsSettings")
	rs := pxMap(ss, "realitySettings")
	switch sec {
	case "tls":
		meta.SNI = pxStr(ts, "serverName")
	case "reality":
		meta.SNI = pxStr(rs, "serverName")
		meta.PublicKey = pxStr(rs, "publicKey", "password")
	}
	if p == "hysteria" {
		meta.Password = pxStr(pxMap(ss, "hysteriaSettings"), "auth")
	}
	alpn := pxStrs(ts["alpn"])
	switch netw {
	case "kcp", "quic", "h3", "hysteria":
		meta.UDP = true
	case "xhttp":
		if len(alpn) == 1 && strings.EqualFold(alpn[0], "h3") {
			meta.UDP = true
		}
	}
	for _, k := range []string{"wsSettings", "httpupgradeSettings", "xhttpSettings", "splithttpSettings"} {
		if o := pxMap(ss, k); o != nil {
			meta.Extra += "|" + pxStr(o, "path") + "|" + pxStr(o, "host")
		}
	}
	if o := pxMap(ss, "grpcSettings"); o != nil {
		meta.Extra += "|" + pxStr(o, "serviceName")
	}
	proto := p
	switch p {
	case "shadowsocks":
		proto = "ss"
		if strings.HasPrefix(strings.ToLower(pxStr(srv, "method")), "2022-") {
			proto = "ss2022"
		}
	case "socks":
		proto = "socks5"
	}
	return meta, proto
}

func xrHop(obs []any, chain []int) (nodeMeta, bool) {
	for k := len(chain) - 1; k >= 1; k-- {
		m, _ := obs[chain[k]].(map[string]any)
		if p := strings.ToLower(pxStr(m, "protocol")); p != "" && !xrNonProxy[p] {
			meta, _ := xrMeta(m)
			return meta, true
		}
	}
	return nodeMeta{}, false
}

func xrConfig(f *vfile, fs *vfs, doc map[string]any, ti int, name string, deps map[int][]*vfile) *Config {
	obs := pxList(doc, "outbounds")
	ob, _ := obs[ti].(map[string]any)
	meta, proto := xrMeta(ob)
	c := newConfig(f, "Xray", proto)
	c.Name = firstNonEmpty(name, pxStr(ob, "tag"), proto)
	c.Host, c.Port = meta.Host, meta.Port
	c.Transport, c.Security, c.SNI = meta.Transport, meta.Security, meta.SNI
	c.Username, c.Password, c.UUID, c.PublicKey = meta.User, meta.Password, meta.UUID, meta.PublicKey
	c.UDP, c.Extra = meta.UDP, meta.Extra
	if proto == "wireguard" {
		c.PrivateKey = pxStr(pxMap(ob, "settings"), "secretKey")
	}
	c.RawConfig, _ = json.Marshal(ob)
	chain, err := xrChain(obs, ti)
	if err != nil {
		c.Status = StateInvalid
		c.Error = shortErr(err)
		return c
	}
	var test []any
	for _, j := range chain {
		for _, d := range deps[j] {
			c.AddDep(fs, d, true)
		}
		m, _ := obs[j].(map[string]any)
		tm, notes := xrTestOutbound(m)
		pxWarnAll(c, notes)
		test = append(test, tm)
	}
	build := func() (Dialer, error) { return xrBuild(test) }
	if len(test) > 1 {
		build = func() (Dialer, error) { return xrBuildChain(test) }
	}
	n := &node{Proto: proto, Candidates: []candidate{{
		Engine: "xray",
		Debug:  test,
		Build:  build,
	}}}
	c.Payload = test
	if hop, ok := xrHop(obs, chain); ok {
		c.Tester = &XrayConnectivityTester{n: n, hop: &hop, chain: true}
		c.Warn("tested through dialerProxy chain via %s:%d", hop.Host, hop.Port)
	} else {
		c.Tester = &XrayConnectivityTester{n: n, chain: len(test) > 1}
	}
	return c
}

func xrCheckOutbound(test []any) error {
	return xrCheck(map[string]any{"log": xrLogNone(), "outbounds": test})
}

func xrParseDoc(f *vfile, fs *vfs, raw map[string]any, element bool) []*Config {
	doc, deps := xrPrepare(f, fs, raw)
	obs := pxList(doc, "outbounds")
	targets := xrProxyIdx(obs)
	remarks := pxStr(doc, "remarks", "remark", "ps")
	if len(targets) == 0 {
		reason := "no proxy outbounds in config"
		if len(pxList(doc, "inbounds")) > 0 {
			reason = "server-side config without proxy outbounds"
		}
		c := unsupportedConfig(f, "Xray", "", reason)
		c.Name = remarks
		return []*Config{c}
	}
	var picked []int
	if element {
		ti := targets[0]
		if m, ok := obs[0].(map[string]any); ok && !xrNonProxy[strings.ToLower(pxStr(m, "protocol"))] {
			ti = 0
		}
		picked = []int{ti}
	} else {
		picked = targets
	}
	var cs []*Config
	for _, ti := range picked {
		name := ""
		if element || len(targets) == 1 {
			name = remarks
		}
		c := xrConfig(f, fs, doc, ti, name, deps)
		if element && len(targets) > 1 {
			c.Warn("config has %d proxy outbounds; tested the default one", len(targets))
		}
		cs = append(cs, c)
	}
	ferr := xrValidate(doc)
	if ferr != nil && xrGeoRe.MatchString(ferr.Error()) {
		if xrValidate(xrStripGeo(doc)) == nil {
			for _, c := range cs {
				c.Warn("routing/DNS rules need geo data files that are not available; they were not validated")
			}
			ferr = nil
		}
	}
	if ferr == nil {
		return cs
	}
	attributed := false
	errs := make([]error, len(cs))
	for i, c := range cs {
		if c.Status != StateParsed {
			continue
		}
		if test, ok := c.Payload.([]any); ok {
			if err := xrCheckOutbound(test); err != nil {
				errs[i] = err
				attributed = true
			}
		}
	}
	for i, c := range cs {
		if c.Status != StateParsed {
			continue
		}
		switch {
		case errs[i] != nil:
			c.Status = StateInvalid
			c.Error = shortErr(errs[i])
		case !attributed:
			c.Status = StateInvalid
			c.Error = shortErr(ferr)
		default:
			c.Warn("full config fails xray validation because of another outbound")
		}
	}
	return cs
}

type XrayConnectivityTester struct {
	n     *node
	hop   *nodeMeta
	chain bool
}

func (t *XrayConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	if t.chain {
		xrChainMu.Lock()
		defer xrChainMu.Unlock()
	}
	if t.hop == nil {
		(&nodeTester{n: t.n}).Test(ctx, c, p)
		return
	}
	(&pxHopTester{n: t.n, host: t.hop.Host, port: t.hop.Port, udp: t.hop.UDP}).Test(ctx, c, p)
}

type XrayConfigFilter struct{}

func (XrayConfigFilter) Filter(f *vfile, idx []int) ([]byte, error) {
	xf, err := xrLoad(f)
	if err != nil {
		return f.Data, nil
	}
	if xf.kind == "array" {
		var elems []json.RawMessage
		if err := json.Unmarshal(pxStripJSONC(f.Data), &elems); err != nil {
			return f.Data, nil
		}
		var b bytes.Buffer
		b.WriteString("[\n")
		n := 0
		for _, i := range idx {
			if i < 0 || i >= len(elems) {
				continue
			}
			if n > 0 {
				b.WriteString(",\n")
			}
			b.Write(bytes.TrimSpace(elems[i]))
			n++
		}
		b.WriteString("\n]\n")
		return b.Bytes(), nil
	}
	var root *pxObj
	switch xf.kind {
	case "json":
		v, err := pxParseOrdered(f.Data)
		if err != nil {
			return f.Data, nil
		}
		root, _ = v.(*pxObj)
	default:
		jb, err := json.Marshal(xf.docs[0])
		if err != nil {
			return f.Data, nil
		}
		v, err := pxParseOrdered(jb)
		if err != nil {
			return f.Data, nil
		}
		root, _ = v.(*pxObj)
	}
	if root == nil {
		return f.Data, nil
	}
	plain := pxPlain(root).(map[string]any)
	obs := pxList(plain, "outbounds")
	targets := xrProxyIdx(obs)
	keep := map[int]bool{}
	for _, i := range idx {
		if i >= 0 && i < len(targets) {
			keep[targets[i]] = true
		}
	}
	if len(keep) == len(targets) {
		return f.Data, nil
	}
	for i := range obs {
		if keep[i] {
			chain, _ := xrChain(obs, i)
			for _, j := range chain {
				keep[j] = true
			}
		}
	}
	isTarget := map[int]bool{}
	for _, t := range targets {
		isTarget[t] = true
	}
	removed := map[string]bool{}
	var nobs []any
	ordered := root.List("outbounds")
	for i, o := range ordered {
		if isTarget[i] && !keep[i] {
			m, _ := obs[i].(map[string]any)
			if t := pxStr(m, "tag"); t != "" {
				removed[t] = true
			}
			continue
		}
		nobs = append(nobs, o)
	}
	for i := range obs {
		if keep[i] || !isTarget[i] {
			m, _ := obs[i].(map[string]any)
			delete(removed, pxStr(m, "tag"))
		}
	}
	root.Set("outbounds", nobs)
	var left []string
	for _, o := range nobs {
		if m, ok := o.(*pxObj); ok {
			left = append(left, m.Str("tag"))
		}
	}
	if r := root.Obj("routing"); r != nil {
		badBal := map[string]bool{}
		if bals := r.List("balancers"); bals != nil {
			var nb []any
			for _, b := range bals {
				bo, ok := b.(*pxObj)
				if !ok {
					nb = append(nb, b)
					continue
				}
				match := false
				for _, sel := range pxStrs(pxPlain(bo.Get("selector"))) {
					for _, t := range left {
						if t != "" && strings.HasPrefix(t, sel) {
							match = true
						}
					}
				}
				if !match {
					badBal[bo.Str("tag")] = true
					continue
				}
				if removed[bo.Str("fallbackTag")] {
					bo.Del("fallbackTag")
				}
				nb = append(nb, b)
			}
			if nb == nil {
				nb = []any{}
			}
			r.Set("balancers", nb)
		}
		if rules := r.List("rules"); rules != nil {
			var nr []any
			for _, x := range rules {
				ro, ok := x.(*pxObj)
				if ok && (removed[ro.Str("outboundTag")] || badBal[ro.Str("balancerTag")]) {
					continue
				}
				nr = append(nr, x)
			}
			if nr == nil {
				nr = []any{}
			}
			r.Set("rules", nr)
		}
	}
	var out []byte
	switch xf.kind {
	case "json":
		out = pxMarshalOrdered(root)
	case "yaml":
		out = pxMarshalYAML(root)
	case "toml":
		out, err = pxTOMLFromPlain(pxPlain(root).(map[string]any))
		if err != nil {
			return f.Data, nil
		}
	}
	nf := newVFile(f.Path, out)
	nxf, err := xrLoad(nf)
	if err != nil || len(nxf.docs) != 1 || nxf.docs[0] == nil {
		return f.Data, nil
	}
	if len(xrProxyIdx(pxList(nxf.docs[0], "outbounds"))) != xrCountKept(keep, isTarget) {
		return f.Data, nil
	}
	if xrValidate(xrStripGeo(nxf.docs[0])) != nil && xrValidate(xrStripGeo(xf.docs[0])) == nil {
		return f.Data, nil
	}
	return out, nil
}

func xrCountKept(keep, isTarget map[int]bool) int {
	n := 0
	for i := range keep {
		if keep[i] && isTarget[i] {
			n++
		}
	}
	return n
}

func init() {
	registerFormat(&fileFormat{Name: "Xray", Detector: XrayConfigDetector{}, Parser: XrayConfigParser{}, Filter: XrayConfigFilter{}})
}
