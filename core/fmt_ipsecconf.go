package main

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

type swICSection struct {
	kind string
	name string
	kv   []iniKV
}

func (s *swICSection) own(k string) (string, bool) {
	for i := len(s.kv) - 1; i >= 0; i-- {
		if s.kv[i].Key == k {
			return s.kv[i].Value, true
		}
	}
	return "", false
}

func swICStripComment(line string) string {
	inQ := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQ = !inQ
		case '#':
			if !inQ {
				return line[:i]
			}
		}
	}
	return line
}

func swICParse(f *vfile, fs *vfs, text string, depth int, deps *[]*vfile) []*swICSection {
	var out []*swICSection
	var cur *swICSection
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(swICStripComment(raw), " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			cur = nil
			switch fields[0] {
			case "conn", "ca":
				if len(fields) > 1 {
					cur = &swICSection{kind: fields[0], name: fields[1]}
					out = append(out, cur)
				}
			case "config":
				cur = &swICSection{kind: "config", name: strings.Join(fields[1:], " ")}
				out = append(out, cur)
			case "include":
				if len(fields) > 1 && depth < 5 {
					for _, g := range swGlobFiles(fs, f, unquote(fields[1])) {
						*deps = append(*deps, g)
						out = append(out, swICParse(g, fs, g.Text(), depth+1, deps)...)
					}
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		cur.kv = append(cur.kv, iniKV{Key: strings.TrimSpace(k), Value: unquote(strings.TrimSpace(v))})
	}
	return out
}

type swICConn struct {
	sec      *swICSection
	conns    map[string]*swICSection
	defaults []*swICSection
}

func (c *swICConn) lookup(s *swICSection, k string, depth int, seen map[string]bool) (string, bool) {
	if v, ok := s.own(k); ok {
		return v, true
	}
	if depth > 8 {
		return "", false
	}
	if also, ok := s.own("also"); ok {
		for _, n := range strings.Fields(also) {
			if seen[n] {
				continue
			}
			seen[n] = true
			if p := c.conns[n]; p != nil {
				if v, ok := c.lookup(p, k, depth+1, seen); ok {
					return v, true
				}
			}
		}
	}
	return "", false
}

func (c *swICConn) get(k string) string {
	if v, ok := c.lookup(c.sec, k, 0, map[string]bool{c.sec.name: true}); ok {
		return v
	}
	for i := len(c.defaults) - 1; i >= 0; i-- {
		if v, ok := c.defaults[i].own(k); ok {
			return v
		}
	}
	return ""
}

func swICIsAddr(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "%any", "%any4", "%any6", "%defaultroute", "%config", "%config4", "%config6", "%opportunistic", "%group", "%opportunisticgroup":
		return false
	}
	return true
}

type swIPSecret struct {
	ids  []string
	typ  string
	val  string
	file string
	pass string
}

func swIPSecretsParse(f *vfile, fs *vfs, text string, depth int, deps *[]*vfile) []swIPSecret {
	var stmts []string
	for _, raw := range strings.Split(text, "\n") {
		line := swICStripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(stmts) > 0 && !strings.Contains(stmts[len(stmts)-1], ":") {
			stmts[len(stmts)-1] += " " + strings.TrimSpace(line)
			continue
		}
		stmts = append(stmts, strings.TrimSpace(line))
	}
	var out []swIPSecret
	for _, st := range stmts {
		if strings.HasPrefix(st, "include ") {
			if depth < 5 {
				for _, g := range swGlobFiles(fs, f, unquote(strings.TrimSpace(st[8:]))) {
					*deps = append(*deps, g)
					out = append(out, swIPSecretsParse(g, fs, g.Text(), depth+1, deps)...)
				}
			}
			continue
		}
		idx := -1
		inQ := false
		for i := 0; i < len(st); i++ {
			if st[i] == '"' {
				inQ = !inQ
			}
			if st[i] == ':' && !inQ && (i+1 == len(st) || st[i+1] == ' ' || st[i+1] == '\t') {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}
		sel := strings.Fields(st[:idx])
		rest := strings.TrimSpace(st[idx+1:])
		typ, val, _ := strings.Cut(rest, " ")
		typ = strings.ToUpper(strings.TrimSpace(typ))
		val = strings.TrimSpace(val)
		e := swIPSecret{typ: typ}
		for _, s := range sel {
			e.ids = append(e.ids, unquote(s))
		}
		switch typ {
		case "RSA", "ECDSA", "P12", "PKCS8", "PKCS12", "BLISS", "PRIVATE":
			toks := swICTokens(val)
			if len(toks) > 0 {
				e.file = toks[0]
			}
			if len(toks) > 1 && !strings.HasPrefix(toks[1], "%prompt") {
				e.pass = swSecret(toks[1])
			}
		default:
			e.val = swSecret(unquote(val))
		}
		out = append(out, e)
	}
	return out
}

func swICTokens(s string) []string {
	var out []string
	s = strings.TrimSpace(s)
	for s != "" {
		if s[0] == '"' {
			end := strings.Index(s[1:], "\"")
			if end < 0 {
				out = append(out, s[1:])
				break
			}
			out = append(out, s[1:1+end])
			s = strings.TrimSpace(s[end+2:])
			continue
		}
		t, r, _ := strings.Cut(s, " ")
		out = append(out, t)
		s = strings.TrimSpace(r)
	}
	return out
}

func swIPPick(secrets []swIPSecret, typs []string, ids []string) (string, bool) {
	best, bestScore := "", -1
	for _, e := range secrets {
		ok := false
		for _, t := range typs {
			if e.typ == t {
				ok = true
			}
		}
		if !ok {
			continue
		}
		score := 0
		if len(e.ids) == 0 {
			score = 1
		} else {
			for _, want := range e.ids {
				if want == "%any" || want == "%any6" {
					score++
					continue
				}
				for _, have := range ids {
					if swIDEq(want, have) {
						score += 3
					}
				}
			}
			if score == 0 {
				continue
			}
		}
		if score > bestScore {
			best, bestScore = e.val, score
		}
	}
	return best, bestScore >= 0
}

var swICDetectRe = regexp.MustCompile(`(?m)^conn[ \t]+\S+`)
var swICKeyRe = regexp.MustCompile(`(?m)^[ \t]+(right|left|keyexchange|authby|leftauth|rightid|rightsubnet|ike)[ \t]*=`)

type IPsecConfDetector struct{}

func (IPsecConfDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) > 2<<20 {
		return 0
	}
	t := f.Text()
	if swICDetectRe.MatchString(t) && swICKeyRe.MatchString(t) {
		return 86
	}
	return 0
}

type IPsecConfParser struct{}

func (IPsecConfParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	var incDeps []*vfile
	secs := swICParse(f, fs, f.Text(), 0, &incDeps)
	conns := map[string]*swICSection{}
	var defaults []*swICSection
	var cas []*swICSection
	for _, s := range secs {
		switch s.kind {
		case "conn":
			if s.name == "%default" {
				defaults = append(defaults, s)
			} else {
				conns[s.name] = s
			}
		case "ca":
			cas = append(cas, s)
		}
	}
	referenced := map[string]bool{}
	for _, s := range conns {
		if v, ok := s.own("also"); ok {
			for _, n := range strings.Fields(v) {
				referenced[n] = true
			}
		}
	}
	var secretFiles []*vfile
	if fs != nil {
		if g := fs.Resolve(f, "ipsec.secrets"); g != nil {
			secretFiles = append(secretFiles, g)
		}
	}
	var secretDeps []*vfile
	var secrets []swIPSecret
	for _, g := range secretFiles {
		secretDeps = append(secretDeps, g)
		secrets = append(secrets, swIPSecretsParse(g, fs, g.Text(), 0, &secretDeps)...)
	}
	var out []*Config
	for _, s := range secs {
		if s.kind != "conn" || s.name == "%default" {
			continue
		}
		cc := &swICConn{sec: s, conns: conns, defaults: defaults}
		if strings.EqualFold(cc.get("auto"), "ignore") {
			continue
		}
		if !swICIsAddr(cc.get("right")) && !swICIsAddr(cc.get("left")) {
			if referenced[s.name] {
				continue
			}
			c := invalidConfig(f, "ipsec.conf", errors.New("no remote address (responder-side connection)"))
			c.Name = s.name
			out = append(out, c)
			continue
		}
		c := swICConfig(f, fs, cc, cas, secrets)
		for _, g := range incDeps {
			c.AddDep(fs, g, false)
		}
		if len(secrets) > 0 {
			for _, g := range secretDeps {
				c.AddDep(fs, g, false)
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no connections defined")
	}
	return out, nil
}

func swICConfig(f *vfile, fs *vfs, cc *swICConn, cas []*swICSection, secrets []swIPSecret) *Config {
	d := &swDeps{}
	srv, cli := "right", "left"
	if !swICIsAddr(cc.get("right")) && swICIsAddr(cc.get("left")) {
		srv, cli = "left", "right"
	}
	g := func(side, k string) string { return cc.get(side + k) }
	host := strings.TrimSpace(strings.Split(cc.get(srv), ",")[0])
	host = strings.TrimPrefix(host, "%")
	spec := &ikeSpec{Name: cc.sec.name, Kind: "ipsec.conf", Host: host}
	if v, err := strconv.Atoi(g(srv, "ikeport")); err == nil {
		spec.Port = v
	}
	spec.Version = 2
	switch strings.ToLower(cc.get("ikev2")) {
	case "no", "never", "permit":
		spec.Version = 1
	}
	if strings.EqualFold(cc.get("keyexchange"), "ikev1") {
		spec.Version = 1
	}
	spec.Aggressive = strings.EqualFold(cc.get("aggressive"), "yes")
	if v := cc.get("ike"); v != "" {
		spec.IKEProposals = []string{v}
	}
	if v := firstNonEmpty(cc.get("esp"), cc.get("ah")); v != "" {
		spec.ESPProposals = []string{v}
	}
	spec.RemoteID = g(srv, "id")
	spec.LocalID = g(cli, "id")
	for _, k := range []string{"leftupdown", "rightupdown"} {
		if v := cc.get(k); v != "" {
			d.warn("updown script ignored: %s", v)
		}
	}
	pp := strings.ToLower(g(cli, "protoport") + " " + g(srv, "protoport"))
	if strings.Contains(pp, "1701") || strings.Contains(pp, "l2tp") {
		spec.L2TP = true
	}
	a1 := strings.ToLower(g(cli, "auth"))
	a2 := strings.ToLower(g(cli, "auth2"))
	if a1 == "" {
		switch strings.ToLower(cc.get("authby")) {
		case "secret", "psk":
			a1 = "psk"
		case "xauthpsk":
			a1, a2 = "psk", "xauth"
		case "xauthrsasig":
			a1, a2 = "pubkey", "xauth"
		case "never":
			a1 = "none"
		default:
			a1 = "pubkey"
		}
	}
	c1 := swAuthClass(a1)
	c2 := ""
	if a2 != "" {
		c2 = swAuthClass(a2)
	}
	if strings.EqualFold(cc.get("xauth"), "client") && c2 == "" && spec.Version == 1 {
		c2 = "xauth"
	}
	switch {
	case c1 == "psk" && c2 == "xauth":
		spec.Auth = "xauth-psk"
	case c1 == "pubkey" && c2 == "xauth":
		spec.Auth = "xauth-pubkey"
	case c1 == "pubkey" && strings.HasPrefix(c2, "eap"):
		spec.Auth = "pubkey+" + c2
	case c1 == "xauth":
		spec.Auth = "hybrid"
	default:
		spec.Auth = c1
	}
	user := firstNonEmpty(cc.get("eap_identity"), cc.get("xauth_identity"), cc.get("aaa_identity"))
	if user == "%identity" {
		user = ""
	}
	if user == "" && (strings.Contains(spec.Auth, "eap") || strings.Contains(spec.Auth, "xauth") || spec.Auth == "hybrid") {
		user = spec.LocalID
	}
	spec.Username = user
	ids := []string{spec.LocalID, spec.RemoteID, host, cc.get(cli)}
	if strings.Contains(spec.Auth, "psk") || spec.L2TP && spec.Auth == "psk" {
		if v, ok := swIPPick(secrets, []string{"PSK"}, ids); ok {
			spec.PSK = v
		}
	}
	if strings.Contains(spec.Auth, "eap") || strings.Contains(spec.Auth, "xauth") || spec.Auth == "hybrid" {
		typs := []string{"EAP", "XAUTH", "NTLM"}
		if strings.Contains(spec.Auth, "xauth") || spec.Auth == "hybrid" {
			typs = []string{"XAUTH", "EAP"}
		}
		if v, ok := swIPPick(secrets, typs, []string{user, spec.LocalID}); ok {
			spec.Password = v
		}
	}
	needCert := strings.Contains(spec.Auth, "pubkey") || spec.Auth == "eap-tls"
	var certFiles []*vfile
	if lc := g(cli, "cert"); lc != "" {
		if strings.HasPrefix(lc, "%smartcard") {
			d.warn("smartcard certificate not supported")
		} else if gf := swResolveIn(fs, f, lc, "ipsec.d/certs", "certs"); gf != nil {
			certFiles = append(certFiles, gf)
		} else {
			d.warn("certificate %s not found", lc)
		}
	}
	if needCert || len(certFiles) > 0 {
		var keys, p12s []swKeyRef
		for _, e := range secrets {
			if e.file == "" {
				continue
			}
			kf := swResolveIn(fs, f, e.file, "ipsec.d/private", "private")
			if kf == nil {
				continue
			}
			if e.typ == "P12" || e.typ == "PKCS12" {
				p12s = append(p12s, swKeyRef{kf, e.pass})
			} else {
				keys = append(keys, swKeyRef{kf, e.pass})
			}
		}
		if len(certFiles) == 0 && needCert {
			certFiles = swDirFiles(fs, f, "ipsec.d/certs", "certs")
		}
		swClientCreds(spec, d, certFiles, keys, p12s, needCert)
	}
	var caFiles []*vfile
	if rc := g(srv, "cert"); rc != "" {
		if gf := swResolveIn(fs, f, rc, "ipsec.d/certs", "certs"); gf != nil {
			caFiles = append(caFiles, gf)
		}
	}
	for _, ca := range cas {
		if v, ok := ca.own("cacert"); ok {
			if gf := swResolveIn(fs, f, v, "ipsec.d/cacerts", "cacerts"); gf != nil {
				caFiles = append(caFiles, gf)
			}
		}
	}
	caFiles = append(caFiles, swDirFiles(fs, f, "ipsec.d/cacerts", "cacerts")...)
	for _, gf := range caFiles {
		if pm := swCertPEM(gf.Data); pm != nil {
			spec.CACerts = append(spec.CACerts, pm)
			d.add(gf, true)
		}
	}
	c := ikeConfig(f, fs, spec)
	c.Format = "ipsec.conf"
	if c.Name == "" {
		c.Name = cc.sec.name
	}
	d.apply(c, fs)
	return c
}

func init() {
	registerFormat(&fileFormat{Name: "ipsec.conf", Detector: IPsecConfDetector{}, Parser: IPsecConfParser{}})
}
