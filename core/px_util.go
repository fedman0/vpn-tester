package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	ghyaml "github.com/ghodss/yaml"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	toml "github.com/pelletier/go-toml"
	jsonreader "github.com/xtls/xray-core/infra/conf/json"
)

func pxStripJSONC(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	out, err := io.ReadAll(&jsonreader.Reader{Reader: bytes.NewReader(b)})
	if err != nil {
		return b
	}
	return out
}

func pxDecodeJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(pxStripJSONC(b)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("unexpected data after JSON value")
	}
	return v, nil
}

func pxYAMLToJSON(b []byte) ([]byte, error) {
	return ghyaml.YAMLToJSON(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))
}

func pxTOMLToJSON(b []byte) ([]byte, error) {
	m := map[string]any{}
	if err := toml.Unmarshal(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}), &m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func pxTOMLFromPlain(v map[string]any) ([]byte, error) {
	t, err := toml.TreeFromMap(pxTOMLSafe(v).(map[string]any))
	if err != nil {
		return nil, err
	}
	s, err := t.ToTomlString()
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func pxTOMLSafe(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := make(map[string]any, len(x))
		for k, e := range x {
			if e == nil {
				continue
			}
			o[k] = pxTOMLSafe(e)
		}
		return o
	case []any:
		o := make([]any, 0, len(x))
		for _, e := range x {
			if e == nil {
				continue
			}
			o = append(o, pxTOMLSafe(e))
		}
		allMaps := len(o) > 0
		for _, e := range o {
			if _, ok := e.(map[string]any); !ok {
				allMaps = false
			}
		}
		if allMaps {
			ms := make([]map[string]any, len(o))
			for i, e := range o {
				ms[i] = e.(map[string]any)
			}
			return ms
		}
		return o
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		f, _ := x.Float64()
		return f
	}
	return v
}

func pxScalar(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case uint32:
		return strconv.FormatUint(uint64(t), 10)
	case uint16:
		return strconv.FormatUint(uint64(t), 10)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func pxStr(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if s := pxScalar(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func pxInt(m map[string]any, keys ...string) int {
	s := pxStr(m, keys...)
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int(f)
	}
	return 0
}

func pxBool(m map[string]any, keys ...string) bool {
	if m == nil {
		return false
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return truthy(t)
		default:
			return pxScalar(v) == "1"
		}
	}
	return false
}

func pxHas(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	return ok && v != nil
}

func pxMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	o, _ := m[key].(map[string]any)
	return o
}

func pxList(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	switch l := m[key].(type) {
	case []any:
		return l
	case []map[string]any:
		out := make([]any, len(l))
		for i, e := range l {
			out[i] = e
		}
		return out
	}
	return nil
}

func pxStrs(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			out = append(out, s)
		}
	case []any:
		for _, e := range t {
			if s := pxScalar(e); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, e := range t {
			if s := strings.TrimSpace(e); s != "" {
				out = append(out, s)
			}
		}
	default:
		if s := pxScalar(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func pxCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		o := make(map[string]any, len(t))
		for k, e := range t {
			o[k] = pxCopy(e)
		}
		return o
	case []any:
		o := make([]any, len(t))
		for i, e := range t {
			o[i] = pxCopy(e)
		}
		return o
	}
	return v
}

func pxCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return pxCopy(m).(map[string]any)
}

func pxDuration(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if d, err := time.ParseDuration(s); err == nil {
		return int(d / time.Second)
	}
	return 0
}

func pxDurationMS(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if d, err := time.ParseDuration(s); err == nil {
		return int(d / time.Millisecond)
	}
	return 0
}

func pxPorts(v any) string {
	var parts []string
	for _, p := range pxStrs(v) {
		for _, q := range strings.FieldsFunc(p, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			q = strings.ReplaceAll(q, ":", "-")
			if q != "" {
				parts = append(parts, q)
			}
		}
	}
	return strings.Join(parts, ",")
}

func pxFirstPort(ports string) int {
	f := ports
	if i := strings.IndexAny(f, ",-"); i >= 0 {
		f = f[:i]
	}
	n, _ := strconv.Atoi(strings.TrimSpace(f))
	return n
}

func pxReserved(v any) []int {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		if strings.Contains(s, ",") || strings.Contains(s, "/") {
			var out []int
			for _, p := range strings.FieldsFunc(strings.Trim(s, "[]"), func(r rune) bool { return r == ',' || r == '/' || r == ' ' }) {
				n, err := strconv.Atoi(p)
				if err != nil {
					return nil
				}
				out = append(out, n)
			}
			return out
		}
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			out := make([]int, len(b))
			for i, c := range b {
				out[i] = int(c)
			}
			return out
		}
	case []any:
		var out []int
		for _, e := range t {
			n, err := strconv.Atoi(pxScalar(e))
			if err != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	return nil
}

func pxSplitAddrs(addrs []string) (string, string) {
	var v4, v6 string
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		ip := a
		if i := strings.Index(ip, "/"); i >= 0 {
			ip = ip[:i]
		}
		if strings.Contains(ip, ":") {
			if v6 == "" {
				v6 = a
			}
		} else if ip != "" && v4 == "" {
			v4 = a
		}
	}
	return v4, v6
}

func pxCertPin(pemData []byte) string {
	var der []byte
	if b, _ := pem.Decode(pemData); b != nil {
		der = b.Bytes
	} else if d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pemData))); err == nil {
		der = d
	}
	if len(der) == 0 {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func pxECHConfig(lines []string) string {
	s := strings.Join(lines, "\n")
	if b, _ := pem.Decode([]byte(s)); b != nil {
		return base64.StdEncoding.EncodeToString(b.Bytes)
	}
	return strings.TrimSpace(strings.Join(lines, ""))
}

type pxChain struct {
	*mihomoDialer
	rest []C.Proxy
}

func (d *pxChain) Close() error {
	for _, p := range d.rest {
		p.Close()
	}
	return d.mihomoDialer.Close()
}

func pxBuildChain(maps []map[string]any) (dl Dialer, err error) {
	var all []C.Proxy
	defer func() {
		if r := recover(); r != nil {
			for _, q := range all {
				q.Close()
			}
			dl, err = nil, fmt.Errorf("mihomo: %v", r)
		}
	}()
	var prev C.Proxy
	for _, m := range maps {
		cp := make(map[string]any, len(m)+1)
		for k, v := range m {
			cp[k] = v
		}
		delete(cp, "dialer-proxy")
		if pxStr(cp, "name") == "" {
			cp["name"] = "node"
		}
		var opts []adapter.ProxyOption
		if prev != nil {
			opts = append(opts, adapter.WithDialerForAPI(proxydialer.New(prev, false)))
		}
		p, err := adapter.ParseProxy(cp, opts...)
		if err != nil {
			for _, q := range all {
				q.Close()
			}
			return nil, err
		}
		all = append(all, p)
		prev = p
	}
	if prev == nil {
		return nil, errors.New("empty proxy chain")
	}
	return &pxChain{mihomoDialer: &mihomoDialer{p: prev}, rest: all[:len(all)-1]}, nil
}

func pxCheckChain(maps []map[string]any) error {
	d, err := pxBuildChain(maps)
	if err != nil {
		return err
	}
	d.Close()
	return nil
}

func pxChainNode(maps []map[string]any) *node {
	last := maps[len(maps)-1]
	proto := strings.ToLower(pxStr(last, "type"))
	if len(maps) == 1 {
		return &node{Proto: proto, Candidates: []candidate{mihomoCandidate(last)}}
	}
	return &node{Proto: proto, Candidates: []candidate{{
		Engine: "mihomo",
		Debug:  maps,
		Build:  func() (Dialer, error) { return pxBuildChain(maps) },
	}}}
}

type pxHopTester struct {
	n    *node
	host string
	port int
	udp  bool
}

func (t *pxHopTester) Test(ctx context.Context, c *Config, p *probe) {
	cc := *c
	cc.Host, cc.Port, cc.UDP = t.host, t.port, t.udp
	(&nodeTester{n: t.n}).Test(ctx, &cc, p)
}

var pxMeshTypes = map[string]bool{"tailscale": true, "zerotier": true, "easytier": true}

var pxMihomoTypes = map[string]bool{
	"ss": true, "ssr": true, "socks5": true, "http": true, "vmess": true, "vless": true, "snell": true,
	"trojan": true, "hysteria": true, "hysteria2": true, "wireguard": true, "tuic": true, "shadowquic": true,
	"gost-relay": true, "ssh": true, "mieru": true, "anytls": true, "sudoku": true, "masque": true,
	"trusttunnel": true, "openvpn": true,
}

var pxNonProxyTypes = map[string]bool{"direct": true, "reject": true, "dns": true, "rematch": true, "pass": true, "compatible": true, "reject-drop": true}

func pxSanitize(m map[string]any) []string {
	var w []string
	for _, k := range []string{"interface-name", "routing-mark"} {
		if pxHas(m, k) {
			delete(m, k)
			w = append(w, k+" ignored during test")
		}
	}
	return w
}

func pxWarnAll(c *Config, ws []string) {
	for _, w := range ws {
		c.Warn("%s", w)
	}
}

func pxV2FromMihomo(m map[string]any) (*v2, bool) {
	typ := strings.ToLower(pxStr(m, "type"))
	if typ != "vless" && typ != "vmess" && typ != "trojan" {
		return nil, false
	}
	for _, k := range []string{"smux", "ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts", "tlsmirror-opts", "ss-opts", "dialer-proxy"} {
		if o := pxMap(m, k); len(o) > 0 && (k != "smux" || pxBool(o, "enabled")) && (k != "ss-opts" || pxBool(o, "enabled")) {
			return nil, false
		}
		if k == "dialer-proxy" && pxStr(m, k) != "" {
			return nil, false
		}
	}
	v := &v2{Proto: typ, Name: pxStr(m, "name"), Server: pxStr(m, "server"), Port: pxInt(m, "port")}
	switch typ {
	case "vless":
		v.ID = pxStr(m, "uuid")
		v.Flow = pxStr(m, "flow")
		v.Encryption = pxStr(m, "encryption")
	case "vmess":
		v.ID = pxStr(m, "uuid")
		v.AlterID = pxInt(m, "alterId")
		v.Cipher = firstNonEmpty(pxStr(m, "cipher"), "auto")
	case "trojan":
		v.ID = pxStr(m, "password")
	}
	switch strings.ToLower(firstNonEmpty(pxStr(m, "network"), "tcp")) {
	case "tcp":
		v.Net = "tcp"
	case "ws":
		ws := pxMap(m, "ws-opts")
		v.Net = "ws"
		if pxBool(ws, "v2ray-http-upgrade") {
			v.Net = "httpupgrade"
		}
		v.Path = firstNonEmpty(pxStr(ws, "path"), "/")
		v.Host = pxStr(pxMap(ws, "headers"), "Host", "host")
		if ed := pxInt(ws, "max-early-data"); ed > 0 {
			if !strings.EqualFold(pxStr(ws, "early-data-header-name"), "Sec-WebSocket-Protocol") {
				return nil, false
			}
			sep := "?"
			if strings.Contains(v.Path, "?") {
				sep = "&"
			}
			v.Path += sep + "ed=" + strconv.Itoa(ed)
		}
	case "grpc":
		v.Net = "grpc"
		v.Service = pxStr(pxMap(m, "grpc-opts"), "grpc-service-name")
	case "http":
		ho := pxMap(m, "http-opts")
		v.Net = "tcp"
		v.HeaderType = "http"
		v.Path = strings.Join(pxStrs(ho["path"]), ",")
		v.Host = strings.Join(pxStrs(pxMap(ho, "headers")["Host"]), ",")
	default:
		return nil, false
	}
	if ro := pxMap(m, "reality-opts"); len(ro) > 0 {
		v.Security = "reality"
		v.PBK = pxStr(ro, "public-key")
		v.SID = pxStr(ro, "short-id")
	} else if typ == "trojan" || pxBool(m, "tls") {
		v.Security = "tls"
	}
	if v.Security != "" {
		v.SNI = pxStr(m, "servername", "sni")
		v.FP = pxStr(m, "client-fingerprint")
		v.ALPN = pxStrs(m["alpn"])
		v.Insecure = pxBool(m, "skip-cert-verify")
		v.PCS = pxStr(m, "fingerprint")
	}
	return v, true
}

func pxPreferXray(n *node, last map[string]any) {
	v, ok := pxV2FromMihomo(last)
	if !ok {
		return
	}
	ob, err := v.toXray()
	if err != nil {
		return
	}
	xc := xrayCandidate(ob)
	if v.Insecure && v.PCS == "" {
		n.Candidates = append(n.Candidates, xc)
	} else {
		n.Candidates = append([]candidate{xc}, n.Candidates...)
	}
}

func pxMihomoConfig(f *vfile, format string, chain []map[string]any, name string, cerr error) *Config {
	var meta nodeMeta
	var n *node
	err := cerr
	if len(chain) > 0 {
		meta = mihomoMeta(chain[len(chain)-1])
		n = pxChainNode(chain)
		if err == nil {
			err = pxCheckChain(chain)
		}
		if err == nil && len(chain) == 1 {
			pxPreferXray(n, chain[0])
		}
		switch t := strings.ToLower(pxStr(chain[len(chain)-1], "type")); {
		case t == "wireguard" || t == "masque" || t == "openvpn":
			meta.Transport = "udp"
		case udpProto(t, "") && meta.Transport == "tcp":
			meta.Transport = "quic"
		}
	} else if err == nil {
		err = errors.New("empty proxy")
	}
	if name != "" {
		meta.Name = name
	}
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		if ro := pxMap(last, "reality-opts"); ro != nil {
			meta.PublicKey = pxStr(ro, "public-key")
		}
		if meta.Password == "" {
			meta.Password = pxStr(last, "password", "psk", "token", "private-key")
		}
		switch strings.ToLower(pxStr(last, "type")) {
		case "ss", "ssr":
			meta.Extra = pxStr(last, "cipher") + "|" + pxStr(last, "plugin")
		case "vmess", "vless", "trojan":
			meta.Extra = pxPathHint(last)
		}
	}
	c := newNodeConfig(f, format, n, err, meta)
	if c.Protocol == "" && len(chain) > 0 {
		c.Protocol = strings.ToLower(pxStr(chain[len(chain)-1], "type"))
	}
	if c.Status == StateParsed && len(chain) > 1 {
		hop := mihomoMeta(chain[0])
		c.Tester = &pxHopTester{n: n, host: hop.Host, port: hop.Port, udp: hop.UDP}
		c.Warn("tested through proxy chain via %s", firstNonEmpty(pxStr(chain[0], "name"), hop.Host))
	}
	return c
}

func pxPathHint(m map[string]any) string {
	for _, k := range []string{"ws-opts", "h2-opts", "http-opts", "xhttp-opts"} {
		if o := pxMap(m, k); o != nil {
			p := pxStr(o, "path")
			if p == "" {
				p = strings.Join(pxStrs(o["path"]), ",")
			}
			return p
		}
	}
	if o := pxMap(m, "grpc-opts"); o != nil {
		return pxStr(o, "grpc-service-name")
	}
	return ""
}

var pxSimpleKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

type pxObj struct {
	Keys []string
	Vals map[string]any
}

func newPxObj() *pxObj { return &pxObj{Vals: map[string]any{}} }

func (o *pxObj) Get(k string) any {
	if o == nil {
		return nil
	}
	return o.Vals[k]
}

func (o *pxObj) Set(k string, v any) {
	if _, ok := o.Vals[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Vals[k] = v
}

func (o *pxObj) Del(k string) {
	if _, ok := o.Vals[k]; !ok {
		return
	}
	delete(o.Vals, k)
	for i, kk := range o.Keys {
		if kk == k {
			o.Keys = append(o.Keys[:i:i], o.Keys[i+1:]...)
			break
		}
	}
}

func (o *pxObj) Obj(k string) *pxObj {
	x, _ := o.Get(k).(*pxObj)
	return x
}

func (o *pxObj) List(k string) []any {
	x, _ := o.Get(k).([]any)
	return x
}

func (o *pxObj) Str(k string) string {
	return pxScalar(o.Get(k))
}

func pxParseOrdered(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(pxStripJSONC(b)))
	d.UseNumber()
	v, err := pxReadValue(d)
	if err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("unexpected data after JSON value")
	}
	return v, nil
}

func pxReadValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	dl, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch dl {
	case '{':
		o := newPxObj()
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errors.New("bad object key")
			}
			v, err := pxReadValue(d)
			if err != nil {
				return nil, err
			}
			o.Set(k, v)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return o, nil
	case '[':
		arr := []any{}
		for d.More() {
			v, err := pxReadValue(d)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, errors.New("unexpected JSON delimiter")
}

func pxPlain(v any) any {
	switch x := v.(type) {
	case *pxObj:
		m := make(map[string]any, len(x.Keys))
		for _, k := range x.Keys {
			m[k] = pxPlain(x.Vals[k])
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = pxPlain(e)
		}
		return out
	}
	return v
}

func pxJSONString(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}

func pxIsScalar(v any) bool {
	switch x := v.(type) {
	case *pxObj:
		return len(x.Keys) == 0
	case []any:
		return len(x) == 0
	}
	return true
}

func pxScalarJSON(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return pxJSONString(x)
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case *pxObj:
		return "{}"
	case []any:
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func pxWriteJSON(buf *bytes.Buffer, v any, ind string) {
	switch x := v.(type) {
	case *pxObj:
		if len(x.Keys) == 0 {
			buf.WriteString("{}")
			return
		}
		buf.WriteString("{\n")
		for i, k := range x.Keys {
			buf.WriteString(ind + "  ")
			buf.WriteString(pxJSONString(k))
			buf.WriteString(": ")
			pxWriteJSON(buf, x.Vals[k], ind+"  ")
			if i < len(x.Keys)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(ind + "}")
	case []any:
		if len(x) == 0 {
			buf.WriteString("[]")
			return
		}
		inline := len(x) <= 16
		for _, e := range x {
			if !pxIsScalar(e) {
				inline = false
			}
		}
		if inline {
			buf.WriteByte('[')
			for i, e := range x {
				if i > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(pxScalarJSON(e))
			}
			buf.WriteByte(']')
			return
		}
		buf.WriteString("[\n")
		for i, e := range x {
			buf.WriteString(ind + "  ")
			pxWriteJSON(buf, e, ind+"  ")
			if i < len(x)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		buf.WriteString(ind + "]")
	default:
		buf.WriteString(pxScalarJSON(v))
	}
}

func pxMarshalOrdered(v any) []byte {
	var buf bytes.Buffer
	pxWriteJSON(&buf, v, "")
	buf.WriteByte('\n')
	return buf.Bytes()
}

func pxYAMLKey(k string) string {
	if pxSimpleKey.MatchString(k) {
		return k
	}
	return pxJSONString(k)
}

func pxWriteYAML(buf *bytes.Buffer, v any, ind string) {
	switch x := v.(type) {
	case *pxObj:
		for _, k := range x.Keys {
			e := x.Vals[k]
			buf.WriteString(ind + pxYAMLKey(k) + ":")
			if pxIsScalar(e) {
				buf.WriteString(" " + pxScalarJSON(e) + "\n")
				continue
			}
			buf.WriteByte('\n')
			if _, ok := e.([]any); ok {
				pxWriteYAML(buf, e, ind)
			} else {
				pxWriteYAML(buf, e, ind+"  ")
			}
		}
	case []any:
		for _, e := range x {
			if pxIsScalar(e) {
				buf.WriteString(ind + "- " + pxScalarJSON(e) + "\n")
				continue
			}
			var sub bytes.Buffer
			if _, ok := e.([]any); ok {
				buf.WriteString(ind + "-\n")
				pxWriteYAML(buf, e, ind+"  ")
				continue
			}
			pxWriteYAML(&sub, e, ind+"  ")
			s := sub.String()
			buf.WriteString(ind + "- " + strings.TrimPrefix(s, ind+"  "))
		}
	default:
		buf.WriteString(ind + pxScalarJSON(v) + "\n")
	}
}

func pxMarshalYAML(v any) []byte {
	var buf bytes.Buffer
	pxWriteYAML(&buf, v, "")
	return buf.Bytes()
}

func pxSplitTop(s string, sep rune) []string {
	var out []string
	depth := 0
	var quote rune
	start := 0
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '(' || r == '[' || r == '{':
			depth++
		case r == ')' || r == ']' || r == '}':
			if depth > 0 {
				depth--
			}
		case r == sep && depth == 0:
			out = append(out, strings.TrimSpace(string(rs[start:i])))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(string(rs[start:])))
	return out
}
