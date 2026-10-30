package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type swNode struct {
	name    string
	parents []string
	kv      []iniKV
	subs    []*swNode
}

func (n *swNode) get(k string) string {
	if n == nil {
		return ""
	}
	for i := len(n.kv) - 1; i >= 0; i-- {
		if strings.EqualFold(n.kv[i].Key, k) {
			return n.kv[i].Value
		}
	}
	return ""
}

func (n *swNode) sub(name string) *swNode {
	if n == nil {
		return nil
	}
	for _, s := range n.subs {
		if strings.EqualFold(s.name, name) {
			return s
		}
	}
	return nil
}

func (n *swNode) addSub(c *swNode) {
	if ex := n.sub(c.name); ex != nil {
		ex.merge(c)
		return
	}
	n.subs = append(n.subs, c)
}

func (n *swNode) merge(o *swNode) {
	n.kv = append(n.kv, o.kv...)
	for _, s := range o.subs {
		n.addSub(s)
	}
	if len(o.parents) > 0 {
		n.parents = o.parents
	}
}

type swParser struct {
	s     string
	i     int
	depth int
	inc   func(pattern string, depth int) []string
}

func (p *swParser) eof() bool { return p.i >= len(p.s) }

func (p *swParser) skipSpace(nl bool) {
	for !p.eof() {
		c := p.s[p.i]
		if c == ' ' || c == '\t' || c == '\r' || (nl && c == '\n') {
			p.i++
			continue
		}
		if c == '#' {
			for !p.eof() && p.s[p.i] != '\n' {
				p.i++
			}
			continue
		}
		return
	}
}

func (p *swParser) word() string {
	st := p.i
	for !p.eof() {
		c := p.s[p.i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '=' || c == '{' || c == '}' || c == '#' || c == '"' || c == ':' {
			break
		}
		p.i++
	}
	return p.s[st:p.i]
}

func (p *swParser) value() string {
	if !p.eof() && p.s[p.i] == '"' {
		p.i++
		var b strings.Builder
		for !p.eof() {
			c := p.s[p.i]
			p.i++
			if c == '\\' && !p.eof() {
				n := p.s[p.i]
				p.i++
				switch n {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case 'r':
					b.WriteByte('\r')
				default:
					b.WriteByte(n)
				}
				continue
			}
			if c == '"' {
				break
			}
			b.WriteByte(c)
		}
		return b.String()
	}
	st := p.i
	for !p.eof() {
		c := p.s[p.i]
		if c == '\n' || c == '#' || c == '{' || c == '}' {
			break
		}
		p.i++
	}
	return strings.TrimSpace(p.s[st:p.i])
}

func (p *swParser) restOfLine() string {
	st := p.i
	for !p.eof() && p.s[p.i] != '\n' && p.s[p.i] != '#' {
		p.i++
	}
	return strings.TrimSpace(p.s[st:p.i])
}

func (p *swParser) body(n *swNode, top bool, guard int) {
	for guard < 1<<20 {
		guard++
		p.skipSpace(true)
		if p.eof() {
			return
		}
		c := p.s[p.i]
		if c == '}' {
			p.i++
			if top {
				continue
			}
			return
		}
		w := p.word()
		if w == "" {
			p.i++
			continue
		}
		p.skipSpace(false)
		if w == "include" && !p.eof() && p.s[p.i] != '=' && p.s[p.i] != '{' {
			pat := unquote(p.restOfLine())
			if p.inc != nil && p.depth < 6 {
				for _, t := range p.inc(pat, p.depth) {
					sp := &swParser{s: t, depth: p.depth + 1, inc: p.inc}
					tmp := &swNode{}
					sp.body(tmp, true, 0)
					n.merge(tmp)
				}
			}
			continue
		}
		if p.eof() {
			return
		}
		switch p.s[p.i] {
		case ':':
			p.i++
			pl := p.value()
			child := &swNode{name: w}
			for _, x := range strings.Split(pl, ",") {
				if x = strings.TrimSpace(x); x != "" {
					child.parents = append(child.parents, x)
				}
			}
			if !p.eof() && p.s[p.i] == '{' {
				p.i++
				p.body(child, false, guard)
			}
			n.addSub(child)
		case '{':
			p.i++
			child := &swNode{name: w}
			p.body(child, false, guard)
			n.addSub(child)
		case '=':
			p.i++
			p.skipSpace(false)
			n.kv = append(n.kv, iniKV{Key: w, Value: p.value()})
		default:
			p.restOfLine()
		}
	}
}

func swResolveParents(n *swNode, siblings []*swNode, depth int) {
	if depth > 8 {
		return
	}
	for _, pn := range n.parents {
		for _, s := range siblings {
			if s != n && strings.EqualFold(s.name, pn) {
				swResolveParents(s, siblings, depth+1)
				base := &swNode{kv: append([]iniKV{}, s.kv...), subs: append([]*swNode{}, s.subs...)}
				base.merge(&swNode{kv: n.kv, subs: n.subs})
				n.kv, n.subs = base.kv, base.subs
			}
		}
	}
	n.parents = nil
	for _, c := range n.subs {
		swResolveParents(c, n.subs, depth+1)
	}
}

func swGlobFiles(fs *vfs, from *vfile, pattern string) []*vfile {
	if fs == nil {
		return nil
	}
	pattern = strings.ReplaceAll(strings.TrimSpace(pattern), "\\", "/")
	if !strings.ContainsAny(pattern, "*?[") {
		if g := fs.Resolve(from, pattern); g != nil {
			return []*vfile{g}
		}
		return nil
	}
	dir := from.Dir()
	var rels []string
	if strings.HasPrefix(pattern, "/") {
		for _, pfx := range []string{"/etc/swanctl/", "/etc/strongswan/swanctl/", "/usr/local/etc/swanctl/", "/etc/strongswan/", "/etc/ipsec.d/", "/etc/", "/usr/local/etc/"} {
			if strings.HasPrefix(pattern, pfx) {
				rels = append(rels, strings.TrimPrefix(pattern, pfx))
			}
		}
		rels = append(rels, path.Base(pattern))
	} else {
		rels = append(rels, pattern)
	}
	var out []*vfile
	seen := map[string]bool{}
	for _, rel := range rels {
		full := path.Clean(path.Join(dir, rel))
		for _, g := range fs.files {
			if seen[g.Path] || g == from {
				continue
			}
			if ok, _ := path.Match(strings.ToLower(full), strings.ToLower(g.Path)); ok {
				seen[g.Path] = true
				out = append(out, g)
			}
		}
		if len(out) > 0 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func swDirFiles(fs *vfs, from *vfile, dirs ...string) []*vfile {
	if fs == nil {
		return nil
	}
	base := from.Dir()
	var out []*vfile
	seen := map[string]bool{}
	for _, d := range dirs {
		pfx := strings.ToLower(path.Join(base, d)) + "/"
		if base == "" {
			pfx = strings.ToLower(d) + "/"
		}
		for _, g := range fs.files {
			lp := strings.ToLower(g.Path)
			if strings.HasPrefix(lp, pfx) && !strings.Contains(lp[len(pfx):], "/") && !seen[g.Path] {
				seen[g.Path] = true
				out = append(out, g)
			}
		}
	}
	return out
}

func swResolveIn(fs *vfs, from *vfile, ref string, subdirs ...string) *vfile {
	ref = strings.TrimSpace(unquote(ref))
	if ref == "" || fs == nil {
		return nil
	}
	if !strings.HasPrefix(ref, "/") && !strings.Contains(ref, "/") {
		for _, d := range subdirs {
			for _, g := range swDirFiles(fs, from, d) {
				if strings.EqualFold(g.Name, ref) {
					return g
				}
			}
		}
	}
	return fs.Resolve(from, ref)
}

func swSecret(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 2 && (strings.HasPrefix(v, "0s") || strings.HasPrefix(v, "0S")) {
		if b, err := b64decode(v[2:]); err == nil {
			return string(b)
		}
	}
	if len(v) > 2 && (strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X")) {
		if b, err := hex.DecodeString(v[2:]); err == nil {
			return string(b)
		}
	}
	return v
}

type swKeyRef struct {
	f    *vfile
	pass string
}

type swDeps struct {
	files []*vfile
	cert  map[string]bool
	warns []string
}

func (d *swDeps) add(f *vfile, cert bool) {
	if f == nil {
		return
	}
	if d.cert == nil {
		d.cert = map[string]bool{}
	}
	for _, x := range d.files {
		if x.Path == f.Path {
			return
		}
	}
	d.files = append(d.files, f)
	d.cert[f.Path] = cert
}

func (d *swDeps) warn(format string, args ...any) {
	m := fmt.Sprintf(format, args...)
	for _, w := range d.warns {
		if w == m {
			return
		}
	}
	d.warns = append(d.warns, m)
}

func (d *swDeps) apply(c *Config, fs *vfs) {
	for _, f := range d.files {
		c.AddDep(fs, f, d.cert[f.Path])
	}
	c.Warnings = append(c.Warnings, d.warns...)
}

func swDecryptKey(data []byte, pass string) ([]byte, error) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		if _, err := ike2ParseKey(data); err == nil {
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), nil
		}
		return nil, errors.New("not a private key")
	}
	var out []byte
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if !strings.Contains(b.Type, "PRIVATE KEY") {
			continue
		}
		if b.Headers["Proc-Type"] != "" {
			if pass == "" {
				return nil, errors.New("private key is encrypted and no passphrase is given")
			}
			der, err := x509.DecryptPEMBlock(b, []byte(pass))
			if err != nil {
				return nil, errors.New("private key passphrase is wrong")
			}
			b = &pem.Block{Type: b.Type, Bytes: der}
		} else if strings.Contains(b.Type, "ENCRYPTED") {
			return nil, errors.New("encrypted PKCS#8 private keys are not supported")
		}
		out = append(out, pem.EncodeToMemory(b)...)
	}
	if out == nil {
		return nil, errors.New("no private key")
	}
	if _, err := ike2ParseKey(out); err != nil {
		return nil, err
	}
	return out, nil
}

func swCertPEM(data []byte) []byte {
	cs := ike2ParseCerts(data)
	if len(cs) == 0 {
		return nil
	}
	var out []byte
	for _, c := range cs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func swClientCreds(spec *ikeSpec, d *swDeps, certs []*vfile, keys []swKeyRef, p12s []swKeyRef, needKey bool) {
	type kp struct {
		ref swKeyRef
		pem []byte
	}
	var parsed []kp
	var keyErr error
	for _, k := range keys {
		pm, err := swDecryptKey(k.f.Data, k.pass)
		if err != nil {
			keyErr = err
			continue
		}
		parsed = append(parsed, kp{k, pm})
	}
	for _, cf := range certs {
		cp := swCertPEM(cf.Data)
		cs := ike2ParseCerts(cf.Data)
		if cp == nil || len(cs) == 0 {
			continue
		}
		for _, k := range parsed {
			key, err := ike2ParseKey(k.pem)
			if err == nil && ike2SamePub(cs[0].PublicKey, key.Public()) {
				spec.ClientCert, spec.ClientKey = cp, k.pem
				d.add(cf, true)
				d.add(k.ref.f, true)
				return
			}
		}
	}
	for _, p := range p12s {
		cp, kp, cas, err := decodePKCS12(p.f.Data, p.pass)
		if err != nil {
			if needKey {
				d.warn("%s: %s", p.f.Name, swP12Err(err))
			}
			continue
		}
		if len(certs) > 0 {
			want := ike2ParseCerts(certs[0].Data)
			got := ike2ParseCerts(cp)
			if len(want) > 0 && len(got) > 0 && !bytes.Equal(want[0].Raw, got[0].Raw) {
				continue
			}
		}
		spec.ClientCert = cp
		for _, ca := range cas {
			spec.ClientCert = append(spec.ClientCert, ca...)
		}
		spec.ClientKey = kp
		d.add(p.f, true)
		return
	}
	if len(certs) > 0 {
		if cp := swCertPEM(certs[0].Data); cp != nil {
			spec.ClientCert = cp
			d.add(certs[0], true)
			if needKey {
				if keyErr != nil {
					d.warn("client key: %s", shortErr(keyErr))
				} else {
					d.warn("no private key found for client certificate %s", certs[0].Name)
				}
			}
			return
		}
	}
	if needKey && keyErr != nil {
		d.warn("client key: %s", shortErr(keyErr))
	}
}

func swP12Err(err error) string {
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "password") || strings.Contains(s, "mac") {
		return "PKCS#12 is password-protected (password not in file)"
	}
	return "PKCS#12: " + shortErr(err)
}

type swSecretEntry struct {
	kind string
	ids  []string
	val  string
	file string
}

func swSecrets(root *swNode) []swSecretEntry {
	var out []swSecretEntry
	for _, sec := range root.subs {
		if !strings.EqualFold(sec.name, "secrets") {
			continue
		}
		for _, s := range sec.subs {
			kind, _, _ := strings.Cut(strings.ToLower(s.name), "-")
			e := swSecretEntry{kind: kind, val: swSecret(unquote(s.get("secret"))), file: unquote(s.get("file"))}
			for _, kv := range s.kv {
				k := strings.ToLower(kv.Key)
				if k == "id" || strings.HasPrefix(k, "id-") {
					e.ids = append(e.ids, unquote(kv.Value))
				}
			}
			out = append(out, e)
		}
	}
	return out
}

func swIDEq(a, b string) bool {
	a, b = strings.TrimSpace(unquote(a)), strings.TrimSpace(unquote(b))
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(strings.TrimPrefix(a, "@"), strings.TrimPrefix(b, "@")) {
		return true
	}
	ia, ok1 := ike2ParseID(a)
	ib, ok2 := ike2ParseID(b)
	return ok1 && ok2 && ike2IDMatch(ia, ib)
}

func swPickSecret(entries []swSecretEntry, kinds []string, ids []string) (string, bool) {
	best, bestScore := "", -1
	for _, e := range entries {
		ok := false
		for _, k := range kinds {
			if e.kind == k {
				ok = true
			}
		}
		if !ok || e.val == "" {
			continue
		}
		score := 0
		if len(e.ids) > 0 {
			for _, want := range e.ids {
				for _, have := range ids {
					if swIDEq(want, have) || want == "%any" {
						score += 2
					}
				}
			}
			if score == 0 {
				continue
			}
		} else {
			score = 1
		}
		if score > bestScore {
			best, bestScore = e.val, score
		}
	}
	return best, bestScore >= 0
}

func swSplit(v string) []string {
	var out []string
	for _, x := range strings.Split(unquote(v), ",") {
		if x = strings.TrimSpace(unquote(strings.TrimSpace(x))); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func swRounds(conn *swNode, prefix string) []*swNode {
	type r struct {
		n   *swNode
		ord int
	}
	var rs []r
	for i, s := range conn.subs {
		ln := strings.ToLower(s.name)
		if ln != prefix && !strings.HasPrefix(ln, prefix+"-") {
			continue
		}
		ord := i
		if v, err := strconv.Atoi(s.get("round")); err == nil {
			ord = v*1000 + i
		} else if _, suf, ok := strings.Cut(ln, "-"); ok {
			if v, err := strconv.Atoi(suf); err == nil {
				ord = v*1000 + i
			}
		}
		rs = append(rs, r{s, ord})
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ord < rs[j].ord })
	out := make([]*swNode, len(rs))
	for i, x := range rs {
		out[i] = x.n
	}
	return out
}

func swAuthClass(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	switch {
	case a == "" || strings.HasPrefix(a, "pubkey") || strings.HasPrefix(a, "rsa") || strings.HasPrefix(a, "ecdsa") || strings.HasPrefix(a, "ed25519") || strings.HasPrefix(a, "ed448") || strings.HasPrefix(a, "bliss"):
		return "pubkey"
	case a == "psk":
		return "psk"
	case strings.HasPrefix(a, "eap"):
		return a
	case strings.HasPrefix(a, "xauth"):
		return "xauth"
	}
	return a
}

var swDetectRe = regexp.MustCompile(`(?m)^\s*connections\s*\{`)
var swConnKeyRe = regexp.MustCompile(`(?m)^\s*(remote_addrs|local_addrs|proposals|children|remote\s*\{|local\s*\{)`)

type SwanctlDetector struct{}

func (SwanctlDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) > 2<<20 {
		return 0
	}
	t := f.Text()
	if swDetectRe.MatchString(t) && swConnKeyRe.MatchString(t) {
		return 88
	}
	return 0
}

type SwanctlParser struct{}

func (SwanctlParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	var incDeps []*vfile
	p := &swParser{s: f.Text()}
	p.inc = func(pat string, depth int) []string {
		var out []string
		for _, g := range swGlobFiles(fs, f, pat) {
			incDeps = append(incDeps, g)
			out = append(out, g.Text())
		}
		return out
	}
	root := &swNode{}
	p.body(root, true, 0)
	swResolveParents(root, nil, 0)
	conns := root.sub("connections")
	if conns == nil || len(conns.subs) == 0 {
		return nil, errors.New("no connections defined")
	}
	secrets := swSecrets(root)
	var out []*Config
	for _, conn := range conns.subs {
		c := swConnConfig(f, fs, root, conn, secrets)
		for _, g := range incDeps {
			c.AddDep(fs, g, false)
		}
		out = append(out, c)
	}
	return out, nil
}

func swConnConfig(f *vfile, fs *vfs, root, conn *swNode, secrets []swSecretEntry) *Config {
	d := &swDeps{}
	spec := &ikeSpec{Name: conn.name, Kind: "swanctl"}
	var host string
	for _, a := range swSplit(conn.get("remote_addrs")) {
		if a == "%any" || a == "%any6" || strings.ContainsAny(a, "/") || strings.Count(a, "-") == 1 && strings.Count(a, ".") >= 6 {
			continue
		}
		host = strings.TrimPrefix(a, "%")
		break
	}
	if host == "" {
		c := invalidConfig(f, "swanctl", errors.New("no remote address (responder-side connection)"))
		c.Name = conn.name
		return c
	}
	spec.Host = host
	if v, err := strconv.Atoi(conn.get("remote_port")); err == nil {
		spec.Port = v
	}
	spec.Version = 2
	if conn.get("version") == "1" {
		spec.Version = 1
	}
	if strings.EqualFold(conn.get("aggressive"), "yes") {
		spec.Aggressive = true
	}
	if pr := conn.get("proposals"); pr != "" {
		spec.IKEProposals = []string{pr}
	}
	for _, s := range conn.subs {
		if strings.EqualFold(s.name, "children") {
			for _, ch := range s.subs {
				if v := ch.get("esp_proposals"); v != "" && len(spec.ESPProposals) == 0 {
					spec.ESPProposals = []string{v}
				}
				if v := ch.get("updown"); v != "" {
					d.warn("updown script ignored: %s", v)
				}
			}
		}
	}
	locals := swRounds(conn, "local")
	remotes := swRounds(conn, "remote")
	var l1, l2, r1 *swNode
	if len(locals) > 0 {
		l1 = locals[0]
	}
	if len(locals) > 1 {
		l2 = locals[1]
	}
	if len(remotes) > 0 {
		r1 = remotes[0]
	}
	a1 := swAuthClass(l1.get("auth"))
	a2 := ""
	if l2 != nil {
		a2 = swAuthClass(l2.get("auth"))
	}
	spec.LocalID = unquote(l1.get("id"))
	spec.RemoteID = unquote(r1.get("id"))
	eapNode := l1
	if strings.HasPrefix(a2, "eap") || a2 == "xauth" {
		eapNode = l2
	}
	user := firstNonEmpty(unquote(eapNode.get("eap_id")), unquote(eapNode.get("xauth_id")), unquote(eapNode.get("aaa_id")))
	if user == "" && (strings.HasPrefix(a1, "eap") || a1 == "xauth" || strings.HasPrefix(a2, "eap") || a2 == "xauth") {
		user = unquote(eapNode.get("id"))
		if eapNode == l1 {
			user = spec.LocalID
		}
	}
	spec.Username = user
	switch {
	case a1 == "psk" && a2 == "xauth":
		spec.Auth = "xauth-psk"
	case a1 == "pubkey" && a2 == "xauth":
		spec.Auth = "xauth-pubkey"
	case a1 == "pubkey" && strings.HasPrefix(a2, "eap"):
		spec.Auth = "pubkey+" + a2
	case a1 == "xauth":
		spec.Auth = "hybrid"
	default:
		spec.Auth = a1
	}
	ids := []string{spec.LocalID, spec.RemoteID, host}
	if strings.Contains(spec.Auth, "psk") {
		if v, ok := swPickSecret(secrets, []string{"ike"}, ids); ok {
			spec.PSK = v
		}
	}
	if strings.Contains(spec.Auth, "eap") || strings.Contains(spec.Auth, "xauth") || spec.Auth == "hybrid" {
		kinds := []string{"eap", "xauth"}
		if strings.Contains(spec.Auth, "xauth") || spec.Auth == "hybrid" {
			kinds = []string{"xauth", "eap"}
		}
		if v, ok := swPickSecret(secrets, kinds, []string{user, spec.LocalID}); ok {
			spec.Password = v
		}
	}
	var certFiles []*vfile
	for _, ref := range swSplit(l1.get("certs")) {
		if g := swResolveIn(fs, f, ref, "x509", "certs"); g != nil {
			certFiles = append(certFiles, g)
		} else {
			d.warn("certificate %s not found", ref)
		}
	}
	for _, s := range l1.subs {
		if strings.HasPrefix(strings.ToLower(s.name), "cert") {
			if g := swResolveIn(fs, f, s.get("file"), "x509"); g != nil {
				certFiles = append(certFiles, g)
			}
		}
	}
	needCert := strings.Contains(spec.Auth, "pubkey") || spec.Auth == "eap-tls"
	if needCert || len(certFiles) > 0 {
		if len(certFiles) == 0 {
			certFiles = swDirFiles(fs, f, "x509")
		}
		var keys, p12s []swKeyRef
		for _, e := range secrets {
			switch e.kind {
			case "private", "rsa", "ecdsa", "pkcs8", "ed25519":
				if g := swResolveIn(fs, f, e.file, "private", "rsa", "ecdsa", "pkcs8"); g != nil {
					keys = append(keys, swKeyRef{g, e.val})
				}
			case "pkcs12":
				if g := swResolveIn(fs, f, e.file, "pkcs12"); g != nil {
					p12s = append(p12s, swKeyRef{g, e.val})
				}
			}
		}
		for _, g := range swDirFiles(fs, f, "private", "rsa", "ecdsa", "pkcs8") {
			keys = append(keys, swKeyRef{f: g})
		}
		for _, g := range swDirFiles(fs, f, "pkcs12") {
			p12s = append(p12s, swKeyRef{f: g})
		}
		swClientCreds(spec, d, certFiles, keys, p12s, needCert)
	}
	var caFiles []*vfile
	for _, ref := range swSplit(r1.get("cacerts")) {
		if g := swResolveIn(fs, f, ref, "x509ca", "cacerts"); g != nil {
			caFiles = append(caFiles, g)
		}
	}
	for _, ref := range swSplit(r1.get("certs")) {
		if g := swResolveIn(fs, f, ref, "x509", "certs"); g != nil {
			caFiles = append(caFiles, g)
		}
	}
	if auths := root.sub("authorities"); auths != nil {
		for _, a := range auths.subs {
			if g := swResolveIn(fs, f, a.get("cacert"), "x509ca"); g != nil {
				caFiles = append(caFiles, g)
			}
		}
	}
	if len(caFiles) == 0 {
		caFiles = swDirFiles(fs, f, "x509ca")
	}
	for _, g := range caFiles {
		if pm := swCertPEM(g.Data); pm != nil {
			spec.CACerts = append(spec.CACerts, pm)
			d.add(g, true)
		}
	}
	c := ikeConfig(f, fs, spec)
	c.Format = "swanctl"
	if c.Name == "" {
		c.Name = conn.name
	}
	d.apply(c, fs)
	return c
}

func init() {
	registerFormat(&fileFormat{Name: "swanctl", Detector: SwanctlDetector{}, Parser: SwanctlParser{}})
}
