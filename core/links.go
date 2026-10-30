package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/enfein/mieru/v3/pkg/appctl"
	"github.com/metacubex/mihomo/common/convert"
)

var errTunnel = errors.New("tunnel-type config: not supported yet")

func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	raw := strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(raw)
}

func hostPort(u *url.URL, def int) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("missing server")
	}
	if u.Port() == "" {
		if def > 0 {
			return host, def, nil
		}
		return "", 0, errors.New("missing port")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, errors.New("bad port")
	}
	return host, p, nil
}

func qget(q url.Values, keys ...string) string {
	for _, k := range keys {
		for qk, vals := range q {
			if strings.EqualFold(qk, k) && len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
				return strings.TrimSpace(vals[0])
			}
		}
	}
	return ""
}

func one(c candidate) []candidate { return []candidate{c} }

func parseLink(link string) (*node, error) {
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return nil, errors.New("not a link")
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	switch scheme {
	case "vless", "trojan":
		u, err := url.Parse(link)
		if err != nil {
			return &node{Proto: scheme}, err
		}
		v, err := v2FromURL(scheme, u)
		if err != nil {
			return &node{Proto: scheme}, err
		}
		cs, err := v.candidates()
		return &node{Proto: scheme, Candidates: cs}, err
	case "trojan-go":
		return parseTrojanGo(link)
	case "vmess":
		return parseVmess(link, rest)
	case "ss":
		return parseSS(link)
	case "ssr":
		return viaConverter("ssr", link)
	case "socks", "socks5", "socks5h", "http", "https":
		return parseSocksHTTP(scheme, link)
	case "socks4", "socks4a":
		return parseSocks4(scheme, link)
	case "tg":
		return parseTG(link)
	case "hysteria":
		return parseHysteria(link)
	case "hysteria2", "hy2", "hysteria2+realm", "hy2+realm", "realm", "hysteria2+realm+http", "hy2+realm+http", "realm+http":
		return parseHysteria2(scheme, link)
	case "tuic", "tuic5", "tuic4":
		return parseTUIC(link)
	case "anytls":
		return viaConverter("anytls", link)
	case "mierus":
		return viaConverter("mieru", link)
	case "mieru":
		return parseMieru(link)
	case "ssh":
		return parseSSH(link)
	case "snell":
		return parseSnell(link)
	case "masque":
		return parseMasque(link)
	case "tt", "trusttunnel":
		return parseTrustTunnel(rest)
	case "naive", "naive+https", "naive+quic", "naive+http2", "naive+h2", "naive+http3", "naive+h3":
		return parseNaive(scheme, link)
	case "juicity":
		return parseJuicity(link)
	case "brook":
		return parseBrook(link)
	case "shadowtls", "shadow-tls", "stls":
		return parseShadowTLS(link)
	case "v2rayn":
		return parseV2rayNInner(rest)
	case "wireguard", "wg", "awg", "amneziawg", "openvpn", "ovpn", "dnstt", "dnst", "slipnet", "slipnet-enc", "slipnet-bundle-enc", "darktunnel", "slipstream", "iodine", "openconnect", "ikev2", "ipsec", "l2tp", "sstp", "softether", "tailscale", "zerotier":
		return &node{Proto: scheme}, errTunnel
	}
	return &node{Proto: scheme}, fmt.Errorf("unknown scheme %q", scheme)
}

func viaConverter(proto, link string) (*node, error) {
	ps, err := convert.ConvertsV2Ray([]byte(link))
	if err != nil || len(ps) == 0 {
		return &node{Proto: proto}, errors.New("invalid " + proto + " link")
	}
	return &node{Proto: proto, Candidates: one(mihomoCandidate(ps[0]))}, nil
}

func parseVmess(link, rest string) (*node, error) {
	body := rest
	if i := strings.IndexAny(body, "?#"); i >= 0 && !strings.Contains(body[:i], "@") {
		body = body[:i]
	}
	if !strings.Contains(rest, "@") {
		if data, err := b64decode(body); err == nil {
			v, err := v2FromVmessJSON(data)
			if err != nil {
				return &node{Proto: "vmess"}, err
			}
			cs, err := v.candidates()
			return &node{Proto: "vmess", Candidates: cs}, err
		}
	}
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "vmess"}, err
	}
	v, err := v2FromURL("vmess", u)
	if err != nil {
		return &node{Proto: "vmess"}, err
	}
	cs, err := v.candidates()
	return &node{Proto: "vmess", Candidates: cs}, err
}

func parseTrojanGo(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "trojan-go"}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return &node{Proto: "trojan-go"}, err
	}
	q := u.Query()
	v := &v2{Proto: "trojan", Name: u.Fragment, Server: host, Port: port, ID: userInfo(u), Security: "tls"}
	v.SNI = qget(q, "sni", "peer")
	v.Net = normNet(qget(q, "type"))
	v.Host = qget(q, "host")
	v.Path = qget(q, "path")
	v.Insecure = truthy(qget(q, "allowInsecure", "insecure"))
	if enc := qget(q, "encryption"); enc != "" {
		parts := strings.SplitN(enc, ";", 3)
		if len(parts) == 3 && strings.EqualFold(parts[0], "ss") {
			v.SSMethod = parts[1]
			v.SSPassword = parts[2]
		}
	}
	if v.SSMethod != "" {
		m, err := v.toMihomo()
		if err != nil {
			return &node{Proto: "trojan-go"}, err
		}
		return &node{Proto: "trojan-go", Candidates: one(mihomoCandidate(m))}, nil
	}
	cs, err := v.candidates()
	return &node{Proto: "trojan-go", Candidates: cs}, err
}

var xraySSMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
	"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true, "none": true, "plain": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
}

func parseSS(link string) (*node, error) {
	body := link[len("ss://"):]
	body, _, _ = strings.Cut(body, "#")
	body, rawQuery, _ := strings.Cut(body, "?")
	body = strings.TrimSuffix(body, "/")
	var method, password, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		ui := body[:at]
		hostport = body[at+1:]
		if dec, err := url.PathUnescape(ui); err == nil {
			ui = dec
		}
		if m, p, ok := strings.Cut(ui, ":"); ok {
			method, password = m, p
		} else {
			dec, err := b64decode(ui)
			if err != nil {
				return &node{Proto: "ss"}, errors.New("bad ss userinfo")
			}
			m, p, ok := strings.Cut(string(dec), ":")
			if !ok {
				return &node{Proto: "ss"}, errors.New("bad ss userinfo")
			}
			method, password = m, p
		}
	} else {
		dec, err := b64decode(body)
		if err != nil {
			return &node{Proto: "ss"}, errors.New("bad ss link")
		}
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return &node{Proto: "ss"}, errors.New("bad ss link")
		}
		m, p, ok := strings.Cut(s[:at], ":")
		if !ok {
			return &node{Proto: "ss"}, errors.New("bad ss link")
		}
		method, password, hostport = m, p, s[at+1:]
	}
	method = strings.ToLower(strings.TrimSpace(method))
	hu, err := url.Parse("ss://" + strings.TrimSuffix(hostport, "/"))
	if err != nil {
		return &node{Proto: "ss"}, err
	}
	host, port, err := hostPort(hu, 0)
	if err != nil {
		return &node{Proto: "ss"}, err
	}
	q, _ := url.ParseQuery(rawQuery)
	m := map[string]any{"name": "ss", "type": "ss", "server": host, "port": port, "cipher": method, "password": password, "udp": true}
	proto := "ss"
	if strings.HasPrefix(method, "2022-") {
		proto = "ss2022"
	}
	plugin := qget(q, "plugin")
	if plugin == "" {
		var cs []candidate
		if xraySSMethods[method] {
			cs = append(cs, xrayCandidate(map[string]any{
				"protocol": "shadowsocks",
				"settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": port, "method": method, "password": password}}},
			}))
		}
		cs = append(cs, mihomoCandidate(m))
		return &node{Proto: proto, Candidates: cs}, nil
	}
	name, opts := parsePluginString(plugin)
	switch name {
	case "obfs-local", "simple-obfs", "obfs":
		m["plugin"] = "obfs"
		m["plugin-opts"] = map[string]any{"mode": firstNonEmpty(opts["obfs"], opts["mode"], "http"), "host": firstNonEmpty(opts["obfs-host"], opts["host"], "bing.com")}
		proto += "+obfs"
	case "v2ray-plugin", "gost-plugin":
		po := map[string]any{
			"mode": firstNonEmpty(opts["mode"], "websocket"),
			"host": firstNonEmpty(opts["host"], opts["obfs-host"]),
			"path": firstNonEmpty(opts["path"], "/"),
		}
		if _, ok := opts["tls"]; ok || opts["security"] == "tls" {
			po["tls"] = true
		}
		if _, ok := opts["mux"]; ok && opts["mux"] != "0" && opts["mux"] != "false" {
			po["mux"] = true
		}
		if truthy(opts["skip-cert-verify"]) || truthy(opts["insecure"]) {
			po["skip-cert-verify"] = true
		}
		m["plugin"] = name
		m["plugin-opts"] = po
		proto += "+" + name
	case "shadow-tls", "shadowtls":
		ver, _ := strconv.Atoi(firstNonEmpty(opts["version"], "3"))
		m["plugin"] = "shadow-tls"
		m["client-fingerprint"] = "chrome"
		m["plugin-opts"] = map[string]any{"host": firstNonEmpty(opts["host"], opts["sni"]), "password": opts["password"], "version": ver}
		proto += "+shadowtls"
	case "kcptun":
		po := map[string]any{}
		for k, v := range opts {
			if v == "" {
				po[k] = true
			} else {
				po[k] = v
			}
		}
		m["plugin"] = "kcptun"
		m["plugin-opts"] = po
		proto += "+kcptun"
	case "restls":
		m["plugin"] = "restls"
		m["client-fingerprint"] = "chrome"
		m["plugin-opts"] = map[string]any{"host": opts["host"], "password": opts["password"], "version-hint": firstNonEmpty(opts["version-hint"], "tls13"), "restls-script": opts["restls-script"]}
		proto += "+restls"
	case "ck-client", "cloak":
		return ckSSNode(proto, opts, host, port, m)
	default:
		return &node{Proto: proto}, fmt.Errorf("ss plugin %q not supported", name)
	}
	return &node{Proto: proto, Candidates: one(mihomoCandidate(m))}, nil
}

func parsePluginString(s string) (string, map[string]string) {
	parts := strings.Split(s, ";")
	name := strings.ToLower(strings.TrimSpace(parts[0]))
	opts := map[string]string{}
	for _, p := range parts[1:] {
		k, v, _ := strings.Cut(p, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			opts[k] = strings.TrimSpace(v)
		}
	}
	return name, opts
}

func credentials(u *url.URL) (string, string) {
	ui := userInfo(u)
	if ui == "" {
		return "", ""
	}
	if !strings.Contains(ui, ":") {
		if dec, err := b64decode(ui); err == nil && strings.Contains(string(dec), ":") {
			ui = string(dec)
		}
	}
	user, pass, _ := strings.Cut(ui, ":")
	return user, pass
}

func parseSocksHTTP(scheme, link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: scheme}, err
	}
	if scheme == "https" || scheme == "http" {
		h := strings.ToLower(u.Hostname())
		if h == "t.me" || h == "telegram.me" || h == "www.t.me" {
			p := strings.Trim(u.Path, "/")
			switch p {
			case "proxy":
				return mtproxyFromQuery(u.Query())
			case "socks":
				return socksFromQuery(u.Query())
			}
		}
	}
	host, port, err := hostPort(u, 0)
	if err != nil {
		return &node{Proto: scheme}, err
	}
	user, pass := credentials(u)
	m := map[string]any{"name": "proxy", "server": host, "port": port, "udp": true}
	if user != "" {
		m["username"] = user
		m["password"] = pass
	}
	proto := scheme
	switch scheme {
	case "socks", "socks5", "socks5h":
		m["type"] = "socks5"
		proto = "socks5"
	case "http":
		m["type"] = "http"
	case "https":
		m["type"] = "http"
		m["tls"] = true
		m["skip-cert-verify"] = true
		if sni := qget(u.Query(), "sni", "peer"); sni != "" {
			m["sni"] = sni
		}
	}
	return &node{Proto: proto, Candidates: one(mihomoCandidate(m))}, nil
}

func socksFromQuery(q url.Values) (*node, error) {
	host := qget(q, "server")
	port, err := strconv.Atoi(qget(q, "port"))
	if host == "" || err != nil {
		return &node{Proto: "socks5"}, errors.New("bad telegram socks link")
	}
	m := map[string]any{"name": "socks", "type": "socks5", "server": host, "port": port, "udp": true}
	if user := qget(q, "user"); user != "" {
		m["username"] = user
		m["password"] = qget(q, "pass")
	}
	return &node{Proto: "socks5", Candidates: one(mihomoCandidate(m))}, nil
}

func parseTG(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "mtproto"}, err
	}
	switch strings.ToLower(u.Host) {
	case "proxy":
		return mtproxyFromQuery(u.Query())
	case "socks":
		return socksFromQuery(u.Query())
	}
	return &node{Proto: "tg"}, errors.New("unsupported tg link")
}

func parseHysteria(link string) (*node, error) {
	hop, ports := splitPorts(link)
	u, err := url.Parse(hop)
	if err != nil {
		return &node{Proto: "hysteria"}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return &node{Proto: "hysteria"}, err
	}
	q := u.Query()
	m := map[string]any{"name": "hysteria", "type": "hysteria", "server": host, "port": port, "udp": true}
	if p := firstNonEmpty(ports, qget(q, "mport")); p != "" {
		m["ports"] = p
	}
	if p := qget(q, "protocol"); p != "" {
		m["protocol"] = p
	}
	if a := firstNonEmpty(qget(q, "auth"), qget(q, "auth_str", "auth-str")); a != "" {
		m["auth-str"] = a
	}
	obfs := qget(q, "obfs")
	obfsParam := qget(q, "obfsParam", "obfs-password", "obfs_password")
	if obfsParam != "" {
		m["obfs"] = obfsParam
	} else if obfs != "" && !strings.EqualFold(obfs, "xplus") {
		m["obfs"] = obfs
	}
	if sni := qget(q, "peer", "sni"); sni != "" {
		m["sni"] = sni
	}
	if truthy(qget(q, "insecure", "allowInsecure")) {
		m["skip-cert-verify"] = true
	}
	if alpn := qget(q, "alpn"); alpn != "" {
		m["alpn"] = splitList(alpn)
	}
	m["up"] = firstNonEmpty(qget(q, "upmbps", "up"), "20")
	m["down"] = firstNonEmpty(qget(q, "downmbps", "down"), "100")
	return &node{Proto: "hysteria", Candidates: one(mihomoCandidate(m))}, nil
}

func splitPorts(line string) (string, string) {
	i := strings.Index(line, "://")
	if i < 0 {
		return line, ""
	}
	head, rest := line[:i+3], line[i+3:]
	auth, tail := rest, ""
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		auth, tail = rest[:j], rest[j:]
	}
	userinfo := ""
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		userinfo, auth = auth[:at+1], auth[at+1:]
	}
	if strings.Contains(auth, "]") {
		return line, ""
	}
	colon := strings.LastIndex(auth, ":")
	if colon < 0 {
		return line, ""
	}
	host, ports := auth[:colon], auth[colon+1:]
	if !strings.ContainsAny(ports, ",-") {
		return line, ""
	}
	first := ports
	if k := strings.IndexAny(ports, ",-"); k >= 0 {
		first = ports[:k]
	}
	if first == "" {
		return line, ""
	}
	return head + userinfo + host + ":" + first + tail, ports
}

func parseHysteria2(scheme, link string) (*node, error) {
	_, rest, _ := strings.Cut(link, "://")
	realm := strings.Contains(scheme, "realm")
	httpRealm := strings.HasSuffix(scheme, "+http")
	target := "hysteria2://"
	if realm {
		target = "hysteria2+realm://"
	}
	norm := target + rest
	ps, err := convert.ConvertsV2Ray([]byte(norm))
	if err != nil || len(ps) == 0 {
		return &node{Proto: "hysteria2"}, errors.New("invalid hysteria2 link")
	}
	m := ps[0]
	u, _ := url.Parse(norm)
	if u != nil {
		q := u.Query()
		if p := qget(q, "mport"); p != "" {
			if _, ok := m["ports"]; !ok {
				m["ports"] = p
			}
		}
		if truthy(qget(q, "insecure", "allowInsecure")) {
			m["skip-cert-verify"] = true
		}
		if httpRealm {
			if ro, ok := m["realm-opts"].(map[string]any); ok {
				ro["server-url"] = "http://" + u.Host
			}
		}
	}
	for _, k := range []string{"obfs", "obfs-password", "sni", "fingerprint", "up", "down"} {
		if s, ok := m[k].(string); ok && s == "" {
			delete(m, k)
		}
	}
	proto := "hysteria2"
	if realm {
		proto = "hysteria2-realm"
	}
	return &node{Proto: proto, Candidates: one(mihomoCandidate(m))}, nil
}

func parseTUIC(link string) (*node, error) {
	_, rest, _ := strings.Cut(link, "://")
	norm := "tuic://" + rest
	ps, err := convert.ConvertsV2Ray([]byte(norm))
	if err != nil || len(ps) == 0 {
		return &node{Proto: "tuic"}, errors.New("invalid tuic link")
	}
	m := ps[0]
	if u, err := url.Parse(norm); err == nil {
		q := u.Query()
		if truthy(qget(q, "allow_insecure", "insecure", "allowInsecure", "skip-cert-verify")) {
			m["skip-cert-verify"] = true
		}
	}
	if _, ok := m["alpn"]; !ok {
		m["alpn"] = []string{"h3"}
	}
	return &node{Proto: "tuic", Candidates: one(mihomoCandidate(m))}, nil
}

func parseMieru(link string) (*node, error) {
	cfg, err := appctl.URLToClientConfig(link)
	if err != nil {
		return &node{Proto: "mieru"}, err
	}
	profiles := cfg.GetProfiles()
	if len(profiles) == 0 {
		return &node{Proto: "mieru"}, errors.New("mieru link has no profile")
	}
	p := profiles[0]
	for _, pp := range profiles {
		if pp.GetProfileName() == cfg.GetActiveProfile() {
			p = pp
		}
	}
	urls, err := appctl.ClientProfileToMultiURLs(p)
	if err != nil || len(urls) == 0 {
		return &node{Proto: "mieru"}, errors.New("mieru profile has no server")
	}
	return viaConverter("mieru", urls[0])
}

func parseSSH(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "ssh"}, err
	}
	host, port, err := hostPort(u, 22)
	if err != nil {
		return &node{Proto: "ssh"}, err
	}
	q := u.Query()
	user := u.User.Username()
	pass, _ := u.User.Password()
	m := map[string]any{"name": "ssh", "type": "ssh", "server": host, "port": port, "username": firstNonEmpty(user, qget(q, "user", "username"), "root")}
	if p := firstNonEmpty(pass, qget(q, "password", "pass")); p != "" {
		m["password"] = p
	}
	if pk := qget(q, "pk", "private-key", "privateKey", "private_key", "key"); pk != "" {
		if !strings.Contains(pk, "PRIVATE KEY") {
			if dec, err := b64decode(pk); err == nil && strings.Contains(string(dec), "PRIVATE KEY") {
				pk = string(dec)
			}
		}
		m["private-key"] = pk
	}
	if pp := qget(q, "passphrase", "private-key-passphrase"); pp != "" {
		m["private-key-passphrase"] = pp
	}
	if hk := qget(q, "hk", "host-key", "hostKey", "host_key"); hk != "" {
		m["host-key"] = []string{hk}
	}
	return &node{Proto: "ssh", Candidates: one(mihomoCandidate(m))}, nil
}

func parseSnell(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "snell"}, err
	}
	host, port, err := hostPort(u, 0)
	if err != nil {
		return &node{Proto: "snell"}, err
	}
	q := u.Query()
	psk := firstNonEmpty(qget(q, "psk"), userInfo(u))
	if psk == "" {
		return &node{Proto: "snell"}, errors.New("missing psk")
	}
	ver, _ := strconv.Atoi(firstNonEmpty(qget(q, "version", "v"), "1"))
	if ver < 1 {
		ver = 1
	}
	if ver > 3 {
		ver = 3
	}
	m := map[string]any{"name": "snell", "type": "snell", "server": host, "port": port, "psk": psk, "version": ver, "udp": true}
	if obfs := strings.ToLower(qget(q, "obfs", "obfs-mode")); obfs != "" && obfs != "none" && obfs != "off" {
		m["obfs-opts"] = map[string]any{"mode": obfs, "host": firstNonEmpty(qget(q, "obfs-host", "host"), "bing.com")}
	}
	return &node{Proto: "snell", Candidates: one(mihomoCandidate(m))}, nil
}

func parseMasque(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "masque"}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return &node{Proto: "masque"}, err
	}
	q := u.Query()
	priv := firstNonEmpty(qget(q, "privateKey", "private-key", "private_key", "pk"), userInfo(u))
	pub := qget(q, "publicKey", "public-key", "public_key", "peerPublicKey", "pbk")
	if priv == "" || pub == "" {
		return &node{Proto: "masque"}, errors.New("masque link needs privateKey and publicKey")
	}
	m := map[string]any{"name": "masque", "type": "masque", "server": host, "port": port, "private-key": priv, "public-key": pub, "udp": true}
	m["ip"] = firstNonEmpty(qget(q, "ip", "ipv4", "address", "local-address"), "172.16.0.2")
	if v6 := qget(q, "ipv6"); v6 != "" {
		m["ipv6"] = v6
	}
	if sni := qget(q, "sni", "peer"); sni != "" {
		m["sni"] = sni
	}
	if uri := qget(q, "uri", "path"); uri != "" {
		m["uri"] = uri
	}
	mtu, _ := strconv.Atoi(qget(q, "mtu"))
	if mtu <= 0 {
		mtu = 1280
	}
	m["mtu"] = mtu
	if truthy(qget(q, "insecure", "skip-cert-verify")) {
		m["skip-cert-verify"] = true
	}
	return &node{Proto: "masque", Candidates: one(mihomoCandidate(m))}, nil
}

func ttVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("short varint")
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errors.New("short varint")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

func parseTrustTunnel(rest string) (*node, error) {
	payload := strings.TrimPrefix(rest, "?")
	payload, _, _ = strings.Cut(payload, "#")
	if dec, err := url.QueryUnescape(payload); err == nil {
		payload = dec
	}
	data, err := b64decode(payload)
	if err != nil {
		return &node{Proto: "trusttunnel"}, errors.New("bad tt payload")
	}
	var hostname, sni, user, pass string
	var addrs []string
	var skip, h3 bool
	var certs []byte
	var subscription string
	for len(data) > 0 {
		tag, n, err := ttVarint(data)
		if err != nil {
			return &node{Proto: "trusttunnel"}, err
		}
		data = data[n:]
		l, n, err := ttVarint(data)
		if err != nil {
			return &node{Proto: "trusttunnel"}, err
		}
		data = data[n:]
		if uint64(len(data)) < l {
			return &node{Proto: "trusttunnel"}, errors.New("truncated tt payload")
		}
		val := data[:l]
		data = data[l:]
		switch tag {
		case 0x01:
			hostname = string(val)
		case 0x02:
			addrs = append(addrs, string(val))
		case 0x03:
			sni = string(val)
		case 0x05:
			user = string(val)
		case 0x06:
			pass = string(val)
		case 0x07:
			skip = len(val) > 0 && val[0] == 1
		case 0x08:
			certs = append([]byte(nil), val...)
		case 0x09:
			v, _, _ := ttVarint(val)
			h3 = v == 2
		case 0x0E:
			subscription = string(val)
		}
	}
	if len(addrs) == 0 && hostname == "" {
		if subscription != "" {
			return &node{Proto: "trusttunnel"}, errors.New("subscription-only tt link")
		}
		return &node{Proto: "trusttunnel"}, errors.New("tt link has no address")
	}
	server, port := hostname, 443
	if len(addrs) > 0 {
		h, p, err := net.SplitHostPort(addrs[0])
		if err == nil {
			server = h
			port, _ = strconv.Atoi(p)
		} else {
			server = addrs[0]
		}
	}
	m := map[string]any{"name": "tt", "type": "trusttunnel", "server": server, "port": port, "username": user, "password": pass, "sni": firstNonEmpty(sni, hostname, server), "udp": true}
	if h3 {
		m["quic"] = true
	}
	if skip {
		m["skip-cert-verify"] = true
	} else if len(certs) > 0 {
		if cs, err := x509.ParseCertificates(certs); err == nil && len(cs) > 0 {
			sum := sha256.Sum256(cs[0].Raw)
			m["fingerprint"] = hex.EncodeToString(sum[:])
		}
	}
	return &node{Proto: "trusttunnel", Candidates: one(mihomoCandidate(m))}, nil
}

func parseNaive(scheme, link string) (*node, error) {
	_, rest, _ := strings.Cut(link, "://")
	u, err := url.Parse("https://" + rest)
	if err != nil {
		return &node{Proto: "naive"}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return &node{Proto: "naive"}, err
	}
	q := u.Query()
	user, pass := credentials(u)
	quic := strings.HasSuffix(scheme, "quic") || strings.HasSuffix(scheme, "h3") || strings.HasSuffix(scheme, "http3") || truthy(qget(q, "quic"))
	m := map[string]any{"name": "naive", "type": "trusttunnel", "server": host, "port": port, "username": user, "password": pass, "sni": firstNonEmpty(qget(q, "sni", "peer"), host), "udp": true}
	if quic {
		m["quic"] = true
	}
	if truthy(qget(q, "insecure", "allowInsecure", "skip-cert-verify")) {
		m["skip-cert-verify"] = true
	}
	proto := "naive"
	if quic {
		proto = "naive-quic"
	}
	return &node{Proto: proto, Candidates: one(mihomoCandidate(m))}, nil
}

func parseV2rayNInner(rest string) (*node, error) {
	typ, payload, ok := strings.Cut(rest, "/")
	if !ok {
		payload = rest
	}
	payload, _, _ = strings.Cut(payload, "#")
	data, err := b64decode(payload)
	if err != nil {
		return &node{Proto: "v2rayn"}, errors.New("bad v2rayn payload")
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return &node{Proto: "v2rayn"}, errors.New("bad v2rayn json")
	}
	ct, _ := strconv.Atoi(jsonString(m, "ConfigType"))
	if ct == 0 {
		ct = map[string]int{"vmess": 1, "shadowsocks": 3, "socks": 4, "vless": 5, "trojan": 6, "hysteria2": 7, "tuic": 8, "wireguard": 9, "http": 10, "anytls": 11, "naive": 12, "masque": 14}[strings.ToLower(typ)]
	}
	te := jsonObject(m, "TransportExtraObj")
	if te == nil {
		te = jsonObject(m, "TransportExtra")
	}
	if te == nil {
		te = map[string]any{}
	}
	pe := jsonObject(m, "ProtoExtraObj")
	if pe == nil {
		pe = jsonObject(m, "ProtoExtra")
	}
	if pe == nil {
		pe = map[string]any{}
	}
	addr := jsonString(m, "Address")
	port, _ := strconv.Atoi(jsonString(m, "Port"))
	if addr == "" || port <= 0 {
		return &node{Proto: "v2rayn"}, errors.New("v2rayn item has no address")
	}
	hp := net.JoinHostPort(addr, strconv.Itoa(port))
	pass := firstNonEmpty(jsonString(m, "Password"), jsonString(m, "Id"))
	user := jsonString(m, "Username")
	sni := jsonString(m, "Sni")
	insecure := truthy(jsonString(m, "AllowInsecure"))
	switch ct {
	case 1, 5, 6:
		proto := map[int]string{1: "vmess", 5: "vless", 6: "trojan"}[ct]
		v := &v2{Proto: proto, Name: jsonString(m, "Remarks"), Server: addr, Port: port, ID: pass}
		v.Net = normNet(jsonString(m, "Network"))
		v.Host = firstNonEmpty(jsonString(te, "Host"), jsonString(m, "RequestHost"))
		v.Path = firstNonEmpty(jsonString(te, "Path"), jsonString(m, "Path"))
		v.HeaderType = strings.ToLower(firstNonEmpty(jsonString(te, "RawHeaderType"), jsonString(te, "KcpHeaderType"), jsonString(m, "HeaderType")))
		v.Seed = jsonString(te, "KcpSeed")
		v.Service = firstNonEmpty(jsonString(te, "GrpcServiceName"), v.Path)
		v.Authority = jsonString(te, "GrpcAuthority")
		v.GrpcMode = jsonString(te, "GrpcMode")
		v.XMode = jsonString(te, "XhttpMode")
		v.XExtra = jsonString(te, "XhttpExtra")
		if v.XExtra == "" {
			if o := jsonObject(te, "XhttpExtra"); o != nil {
				b, _ := json.Marshal(o)
				v.XExtra = string(b)
			}
		}
		v.Security = strings.ToLower(jsonString(m, "StreamSecurity"))
		v.SNI = sni
		v.FP = jsonString(m, "Fingerprint")
		v.ALPN = splitList(jsonString(m, "Alpn"))
		v.Insecure = insecure
		v.PBK = jsonString(m, "PublicKey")
		v.SID = jsonString(m, "ShortId")
		v.SPX = jsonString(m, "SpiderX")
		v.PQV = jsonString(m, "Mldsa65Verify")
		v.ECH = jsonString(m, "EchConfigList")
		v.PCS = jsonString(m, "CertSha")
		v.VCN = jsonString(m, "VerifyPeerCertByName")
		v.FM = jsonString(m, "Finalmask")
		v.Flow = firstNonEmpty(jsonString(pe, "Flow"), jsonString(m, "Flow"))
		if proto == "vless" {
			v.Encryption = firstNonEmpty(jsonString(pe, "VlessEncryption"), jsonString(m, "Security"), "none")
		}
		if proto == "vmess" {
			v.Cipher = firstNonEmpty(jsonString(pe, "VmessSecurity"), jsonString(m, "Security"), "auto")
			v.AlterID, _ = strconv.Atoi(firstNonEmpty(jsonString(pe, "AlterId"), jsonString(m, "AlterId")))
		}
		cs, err := v.candidates()
		return &node{Proto: proto, Candidates: cs}, err
	case 3:
		method := firstNonEmpty(jsonString(pe, "SsMethod"), jsonString(m, "Security"))
		return parseLink("ss://" + base64.RawURLEncoding.EncodeToString([]byte(method+":"+pass)) + "@" + hp)
	case 4, 10:
		scheme := "socks5"
		if ct == 10 {
			scheme = "http"
		}
		ui := ""
		if user != "" || pass != "" {
			ui = url.UserPassword(user, pass).String() + "@"
		}
		return parseLink(scheme + "://" + ui + hp)
	case 7:
		q := url.Values{}
		if sni != "" {
			q.Set("sni", sni)
		}
		if insecure {
			q.Set("insecure", "1")
		}
		if sp := jsonString(pe, "SalamanderPass"); sp != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", sp)
		}
		if p := firstNonEmpty(jsonString(pe, "Ports"), jsonString(m, "Ports")); p != "" {
			q.Set("mport", strings.ReplaceAll(p, ":", "-"))
		}
		return parseLink("hysteria2://" + url.PathEscape(pass) + "@" + hp + "/?" + q.Encode())
	case 8:
		q := url.Values{}
		if sni != "" {
			q.Set("sni", sni)
		}
		if a := jsonString(m, "Alpn"); a != "" {
			q.Set("alpn", a)
		}
		if cc := jsonString(pe, "CongestionControl"); cc != "" {
			q.Set("congestion_control", cc)
		}
		if insecure {
			q.Set("allow_insecure", "1")
		}
		id := firstNonEmpty(user, jsonString(m, "Id"))
		pw := firstNonEmpty(jsonString(m, "Password"), jsonString(m, "Security"))
		return parseLink("tuic://" + url.UserPassword(id, pw).String() + "@" + hp + "?" + q.Encode())
	case 11:
		q := url.Values{}
		if sni != "" {
			q.Set("sni", sni)
		}
		if insecure {
			q.Set("insecure", "1")
		}
		return parseLink("anytls://" + url.PathEscape(pass) + "@" + hp + "?" + q.Encode())
	case 12:
		scheme := "naive+https"
		if truthy(jsonString(pe, "NaiveQuic")) {
			scheme = "naive+quic"
		}
		return parseLink(scheme + "://" + url.UserPassword(user, pass).String() + "@" + hp)
	case 9:
		return &node{Proto: "wireguard"}, errTunnel
	}
	return &node{Proto: "v2rayn"}, fmt.Errorf("v2rayn config type %d not supported", ct)
}
