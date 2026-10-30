package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var amzLinkRe = regexp.MustCompile(`vpn://[A-Za-z0-9_\-+/]+=*`)

type amzDoc struct {
	obj     map[string]any
	encoded bool
}

type amzOwner struct {
	doc  int
	cont int
}

func amzDecodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var last error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		last = err
	}
	if strings.ContainsAny(s, "-_") && strings.ContainsAny(s, "+/") {
		return nil, last
	}
	t := strings.TrimRight(s, "=")
	t = strings.NewReplacer("+", "-", "/", "_").Replace(t)
	b, err := base64.RawURLEncoding.DecodeString(t)
	if err != nil {
		return nil, last
	}
	return b, nil
}

func amzInflate(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, nil
}

func amzDecodePayload(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "vpn://")
	b, err := amzDecodeB64(s)
	if err != nil {
		return nil, fmt.Errorf("vpn:// payload is not base64: %v", err)
	}
	if len(b) == 0 {
		return nil, errors.New("empty vpn:// payload")
	}
	t := bytes.TrimSpace(b)
	if len(t) > 0 && t[0] == '{' {
		return t, nil
	}
	if len(b) > 6 && b[4] == 0x78 {
		if out, err := amzInflate(b[4:]); err == nil {
			return out, nil
		}
	}
	if b[0] == 0x78 {
		if out, err := amzInflate(b); err == nil {
			return out, nil
		}
	}
	return nil, errors.New("vpn:// payload is neither qCompress/zlib data nor JSON")
}

func amzDecodeJSON(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func amzIsAPI(m map[string]any) bool {
	for _, k := range []string{"api_config", "auth_data", "api_key", "api_endpoint"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func amzLooksAmnezia(m map[string]any) bool {
	if m == nil {
		return false
	}
	if cs, ok := m["containers"].([]any); ok {
		if len(cs) == 0 {
			_, h := m["hostName"]
			_, d := m["defaultContainer"]
			return h || d
		}
		for _, c := range cs {
			if co, ok := c.(map[string]any); ok {
				if _, ok := co["container"]; ok {
					return true
				}
			}
		}
		return false
	}
	if amzIsAPI(m) {
		_, v := m["config_version"]
		_, p := m["protocol"]
		_, n := m["name"]
		return v || p || n
	}
	_, h := m["hostName"]
	_, d := m["defaultContainer"]
	return h && d
}

func amzExtract(text string) ([]*amzDoc, []error) {
	var docs []*amzDoc
	var errs []error
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "{") {
		if m, err := amzDecodeJSON([]byte(t)); err == nil && amzLooksAmnezia(m) {
			return []*amzDoc{{obj: m}}, nil
		}
	}
	seen := map[string]bool{}
	for _, tok := range amzLinkRe.FindAllString(text, -1) {
		if seen[tok] || len(tok) < 16 {
			continue
		}
		seen[tok] = true
		b, err := amzDecodePayload(tok)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m, err := amzDecodeJSON(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("vpn:// payload is not valid JSON: %v", err))
			continue
		}
		if !amzLooksAmnezia(m) {
			errs = append(errs, errors.New("vpn:// payload is not an Amnezia config"))
			continue
		}
		docs = append(docs, &amzDoc{obj: m, encoded: true})
	}
	return docs, errs
}

type AmneziaVpnDetector struct{}

func (AmneziaVpnDetector) Detect(f *vfile) int {
	if len(f.Data) == 0 || len(f.Data) > 8<<20 || !f.IsText() {
		return 0
	}
	text := f.Text()
	if !strings.Contains(text, "vpn://") {
		t := strings.TrimSpace(text)
		if !strings.HasPrefix(t, "{") || !strings.Contains(t, "\"containers\"") && !strings.Contains(t, "\"defaultContainer\"") && !strings.Contains(t, "\"api_config\"") && !strings.Contains(t, "\"auth_data\"") {
			return 0
		}
	}
	docs, errs := amzExtract(text)
	if len(docs) > 0 {
		return 95
	}
	if len(errs) > 0 && strings.HasPrefix(strings.TrimSpace(text), "vpn://") {
		return 60
	}
	return 0
}

func amzStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch x := v.(type) {
			case string:
				if s := strings.TrimSpace(x); s != "" {
					return s
				}
			case json.Number:
				return x.String()
			case bool:
				return strconv.FormatBool(x)
			case float64:
				return strconv.FormatFloat(x, 'f', -1, 64)
			}
		}
	}
	return ""
}

func amzObj(m map[string]any, key string) map[string]any {
	switch v := m[key].(type) {
	case map[string]any:
		return v
	case string:
		if o, err := amzDecodeJSON([]byte(v)); err == nil {
			return o
		}
	}
	return nil
}

type amzNative struct {
	text string
	lc   map[string]any
}

func amzLastConfig(proto map[string]any) *amzNative {
	if proto == nil {
		return nil
	}
	raw, ok := proto["last_config"]
	if !ok || raw == nil {
		return nil
	}
	n := &amzNative{}
	switch v := raw.(type) {
	case map[string]any:
		n.lc = v
		if b, err := json.Marshal(v); err == nil {
			n.text = string(b)
		}
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		if strings.HasPrefix(s, "{") {
			if m, err := amzDecodeJSON([]byte(s)); err == nil {
				n.lc = m
			}
		}
		n.text = s
	default:
		return nil
	}
	if n.lc != nil {
		if c, ok := n.lc["config"]; ok {
			switch x := c.(type) {
			case string:
				n.text = x
			case map[string]any:
				if b, err := json.Marshal(x); err == nil {
					n.text = string(b)
				}
			}
		}
	}
	return n
}

func amzSubst(text string, doc map[string]any) string {
	d1 := amzStr(doc, "dns1")
	if d1 == "" {
		d1 = "1.1.1.1"
	}
	d2 := amzStr(doc, "dns2")
	if d2 == "" {
		d2 = "1.0.0.1"
	}
	r := strings.NewReplacer("$PRIMARY_DNS", d1, "$SECONDARY_DNS", d2)
	return r.Replace(text)
}

var amzAwgKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "J1", "J2", "J3", "Itime"}

func amzInjectAwg(text string, sources ...map[string]any) string {
	present := map[string]bool{}
	for _, l := range wgSplitLines(text) {
		if l.Section == "interface" && l.Key != "" {
			present[l.Key] = true
		}
	}
	var add []string
	for _, k := range amzAwgKeys {
		if present[strings.ToLower(k)] {
			continue
		}
		for _, src := range sources {
			if src == nil {
				continue
			}
			if v := amzStr(src, k); v != "" {
				add = append(add, k+" = "+v)
				break
			}
		}
	}
	if len(add) == 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.EqualFold(strings.TrimSpace(l), "[Interface]") {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, add...)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n")
		}
	}
	return text
}

func amzSynthWG(lc, proto, doc map[string]any) string {
	priv := amzStr(lc, "client_priv_key")
	pub := amzStr(lc, "server_pub_key")
	if priv == "" || pub == "" {
		return ""
	}
	host := amzStr(lc, "hostName")
	if host == "" {
		host = amzStr(doc, "hostName")
	}
	port := amzStr(lc, "port")
	if port == "" {
		port = amzStr(proto, "port")
	}
	var b strings.Builder
	b.WriteString("[Interface]\nPrivateKey = " + priv + "\n")
	if ip := amzStr(lc, "client_ip"); ip != "" {
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		b.WriteString("Address = " + ip + "\n")
	}
	if mtu := amzStr(lc, "mtu"); mtu != "" {
		b.WriteString("MTU = " + mtu + "\n")
	}
	b.WriteString("\n[Peer]\nPublicKey = " + pub + "\n")
	if psk := amzStr(lc, "psk_key"); psk != "" {
		b.WriteString("PresharedKey = " + psk + "\n")
	}
	allowed := "0.0.0.0/0, ::/0"
	if a, ok := lc["allowed_ips"].([]any); ok && len(a) > 0 {
		var parts []string
		for _, x := range a {
			if s, ok := x.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			allowed = strings.Join(parts, ", ")
		}
	}
	b.WriteString("AllowedIPs = " + allowed + "\n")
	if host != "" && port != "" {
		b.WriteString("Endpoint = " + host + ":" + port + "\n")
	}
	if ka := amzStr(lc, "persistent_keep_alive"); ka != "" {
		b.WriteString("PersistentKeepalive = " + ka + "\n")
	}
	return b.String()
}

var amzSkipContainers = map[string]bool{
	"amnezia-dns": true, "amnezia-sftp": true, "amnezia-torwebsite": true, "amnezia-tor": true,
	"amnezia-nextcloud": true, "amnezia-mtproxy": true,
}

func amzProtoKey(cont map[string]any, prefer ...string) (string, map[string]any) {
	for _, k := range prefer {
		if o := amzObj(cont, k); o != nil {
			return k, o
		}
	}
	return "", nil
}

func amzName(doc map[string]any, container string) string {
	desc := amzStr(doc, "description", "name", "hostName")
	short := strings.TrimPrefix(container, "amnezia-")
	if desc == "" {
		return short
	}
	return desc + " · " + short
}

type amzBuilder struct {
	f       *vfile
	fs      *vfs
	docIdx  int
	doc     map[string]any
	configs []*Config
	owners  []amzOwner
}

func (b *amzBuilder) add(ci int, cs ...*Config) {
	for _, c := range cs {
		if c == nil {
			continue
		}
		b.configs = append(b.configs, c)
		b.owners = append(b.owners, amzOwner{doc: b.docIdx, cont: ci})
	}
}

func (b *amzBuilder) unsupported(ci int, proto, name, reason string) {
	c := unsupportedConfig(b.f, "AmneziaVPN", proto, reason)
	c.Name = name
	b.add(ci, c)
}

func (b *amzBuilder) child(ci int, key, name, text string) *vfile {
	tag := fmt.Sprintf("containers[%d].%s", ci, key)
	if b.docIdx > 0 {
		tag = fmt.Sprintf("vpn[%d].%s", b.docIdx, tag)
	}
	return b.f.Child(tag, name, []byte(text))
}

func (b *amzBuilder) dispatch(ci int, format, key, fileName, text, name, host string, proto map[string]any) {
	ch := b.child(ci, key, fileName, text)
	cs, _ := parseAs(format, ch, b.fs)
	for _, c := range cs {
		c.Format = "AmneziaVPN"
		if c.Name == "" || c.Name == wgFileName(ch) {
			c.Name = name
		}
		if c.Protocol == "" {
			c.Protocol = format
		}
		if c.Status != StateParsed {
			if c.Host == "" && host != "" {
				c.Host = host
			}
			if c.Port == 0 && proto != nil {
				c.Port, _ = strconv.Atoi(amzStr(proto, "port"))
			}
		}
	}
	b.add(ci, cs...)
}

func (b *amzBuilder) container(ci int, cont map[string]any) {
	name := amzStr(cont, "container")
	lname := strings.ToLower(name)
	if amzSkipContainers[lname] {
		return
	}
	label := amzName(b.doc, name)
	host := amzStr(b.doc, "hostName")
	switch {
	case strings.Contains(lname, "awg") || strings.Contains(lname, "amneziawg"):
		key, proto := amzProtoKey(cont, "awg", "awg2", "amneziawg", strings.TrimPrefix(lname, "amnezia-"))
		b.wireguard(ci, key, proto, label, true)
	case lname == "amnezia-wireguard" || strings.Contains(lname, "wireguard"):
		key, proto := amzProtoKey(cont, "wireguard")
		b.wireguard(ci, key, proto, label, false)
	case strings.Contains(lname, "cloak"):
		b.unsupported(ci, "OpenVPN", label, "OpenVPN over Cloak is not supported")
	case lname == "amnezia-shadowsocks":
		_, proto := amzProtoKey(cont, "shadowsocks")
		b.shadowsocks(ci, proto, label, host)
	case lname == "amnezia-ssxray":
		key, proto := amzProtoKey(cont, "ssxray", "xray")
		b.xray(ci, key, proto, label, host)
	case strings.Contains(lname, "xray"):
		key, proto := amzProtoKey(cont, "xray", "ssxray")
		b.xray(ci, key, proto, label, host)
	case strings.Contains(lname, "openvpn"):
		key, proto := amzProtoKey(cont, "openvpn")
		n := amzLastConfig(proto)
		if n == nil || strings.TrimSpace(n.text) == "" {
			b.noClient(ci, "OpenVPN", label)
			return
		}
		b.dispatch(ci, "OpenVPN", key, name+".ovpn", amzSubst(n.text, b.doc), label, host, proto)
	case strings.Contains(lname, "ipsec") || strings.Contains(lname, "ikev2"):
		_, proto := amzProtoKey(cont, "ikev2", "ipsec")
		b.ikev2(ci, proto, label, host)
	case strings.Contains(lname, "socks5"):
		_, proto := amzProtoKey(cont, "socks5proxy", "socks5")
		b.socks5(ci, proto, label, host)
	default:
		b.unknown(ci, cont, name, label, host)
	}
}

func (b *amzBuilder) noClient(ci int, proto, label string) {
	b.unsupported(ci, proto, label, "container has no client config (server-management share); export a connection config from the Amnezia app")
}

func (b *amzBuilder) wireguard(ci int, key string, proto map[string]any, label string, awg bool) {
	format, protoName := "WireGuard", "WireGuard"
	if awg {
		format, protoName = "AmneziaWG", "AmneziaWG"
	}
	n := amzLastConfig(proto)
	if n == nil {
		b.noClient(ci, protoName, label)
		return
	}
	text := n.text
	if !strings.Contains(strings.ToLower(text), "[interface]") && n.lc != nil {
		text = amzSynthWG(n.lc, proto, b.doc)
	}
	if strings.TrimSpace(text) == "" {
		b.noClient(ci, protoName, label)
		return
	}
	text = amzSubst(text, b.doc)
	if awg {
		text = amzInjectAwg(text, n.lc, proto)
	}
	if key == "" {
		key = strings.ToLower(protoName)
	}
	b.dispatch(ci, format, key, strings.ToLower(protoName)+".conf", text, label, amzStr(b.doc, "hostName"), proto)
}

func (b *amzBuilder) xray(ci int, key string, proto map[string]any, label, host string) {
	n := amzLastConfig(proto)
	if n == nil || strings.TrimSpace(n.text) == "" {
		b.noClient(ci, "Xray", label)
		return
	}
	if key == "" {
		key = "xray"
	}
	b.dispatch(ci, "Xray", key, key+".json", n.text, label, host, proto)
}

func (b *amzBuilder) shadowsocks(ci int, proto map[string]any, label, host string) {
	n := amzLastConfig(proto)
	var ss map[string]any
	if n != nil {
		if n.lc != nil {
			ss = n.lc
		}
		if t := strings.TrimSpace(n.text); strings.HasPrefix(t, "{") {
			if m, err := amzDecodeJSON([]byte(t)); err == nil {
				ss = m
			}
		}
	}
	if ss == nil {
		b.noClient(ci, "ss", label)
		return
	}
	server := amzStr(ss, "server", "hostName")
	if server == "" || server == "127.0.0.1" {
		server = host
	}
	port, _ := strconv.Atoi(amzStr(ss, "server_port", "port"))
	if port == 0 {
		port, _ = strconv.Atoi(amzStr(proto, "port"))
	}
	m := map[string]any{
		"type":     "ss",
		"name":     label,
		"server":   server,
		"port":     port,
		"cipher":   firstNonEmpty(amzStr(ss, "method", "cipher"), amzStr(proto, "cipher")),
		"password": amzStr(ss, "password"),
		"udp":      false,
	}
	ch := b.child(ci, "shadowsocks", "shadowsocks.json", n.text)
	var err error
	switch {
	case server == "" || port <= 0:
		err = errors.New("shadowsocks config has no server address")
	case m["password"] == "" || m["cipher"] == "":
		err = errors.New("shadowsocks config has no cipher/password")
	}
	c := newNodeConfig(ch, "AmneziaVPN", mihomoNode(m), err, mihomoMeta(m))
	c.Name = label
	c.RawConfig = []byte(n.text)
	c.Warn("Amnezia runs OpenVPN over this Shadowsocks server; only the Shadowsocks layer is tested")
	b.add(ci, c)
}

func (b *amzBuilder) socks5(ci int, proto map[string]any, label, host string) {
	src := proto
	if n := amzLastConfig(proto); n != nil && n.lc != nil {
		src = n.lc
	}
	if src == nil {
		b.noClient(ci, "socks5", label)
		return
	}
	port, _ := strconv.Atoi(amzStr(src, "port"))
	if port == 0 && proto != nil {
		port, _ = strconv.Atoi(amzStr(proto, "port"))
	}
	server := firstNonEmpty(amzStr(src, "hostName", "server"), host)
	if server == "" || port == 0 {
		b.noClient(ci, "socks5", label)
		return
	}
	m := map[string]any{"type": "socks5", "name": label, "server": server, "port": port, "udp": false}
	if u := amzStr(src, "userName", "username", "user"); u != "" {
		m["username"] = u
		m["password"] = amzStr(src, "password")
	}
	ch := b.child(ci, "socks5proxy", "socks5.json", "")
	c := newNodeConfig(ch, "AmneziaVPN", mihomoNode(m), nil, mihomoMeta(m))
	c.Name = label
	b.add(ci, c)
}

func (b *amzBuilder) ikev2(ci int, proto map[string]any, label, host string) {
	n := amzLastConfig(proto)
	if n == nil || n.lc == nil {
		b.noClient(ci, "IKEv2", label)
		return
	}
	lc := n.lc
	h := firstNonEmpty(amzStr(lc, "hostName"), host)
	user := amzStr(lc, "userName")
	ch := b.child(ci, "ikev2", "ikev2.json", n.text)
	spec := &ikeSpec{Name: label, Kind: "ikev2", Version: 2, Host: h, Port: 500, RemoteID: h, LocalID: user, Auth: "cert"}
	if cert := amzStr(lc, "cert"); cert != "" {
		p12, err := amzDecodeB64(cert)
		if err != nil {
			c := invalidConfig(ch, "AmneziaVPN", fmt.Errorf("IKEv2 client certificate is not base64: %v", err))
			c.Name, c.Protocol = label, "IKEv2"
			b.add(ci, c)
			return
		}
		cp, kp, cas, err := decodePKCS12(p12, amzStr(lc, "password"))
		if err != nil {
			c := invalidConfig(ch, "AmneziaVPN", fmt.Errorf("IKEv2 client certificate (PKCS#12) could not be decoded: %v", err))
			c.Name, c.Protocol = label, "IKEv2"
			b.add(ci, c)
			return
		}
		spec.ClientCert, spec.ClientKey, spec.CACerts = cp, kp, cas
	} else if pw := amzStr(lc, "password"); pw != "" && user != "" {
		spec.Auth, spec.Username, spec.Password = "eap", user, pw
	}
	c := ikeConfig(ch, b.fs, spec)
	if c != nil {
		c.Format = "AmneziaVPN"
		if c.Name == "" {
			c.Name = label
		}
		if c.Host == "" {
			c.Host = h
		}
	}
	b.add(ci, c)
}

func (b *amzBuilder) unknown(ci int, cont map[string]any, name, label, host string) {
	keys := make([]string, 0, len(cont))
	for k := range cont {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		proto := amzObj(cont, k)
		n := amzLastConfig(proto)
		if n == nil || strings.TrimSpace(n.text) == "" {
			continue
		}
		t := strings.TrimSpace(n.text)
		switch {
		case strings.Contains(strings.ToLower(t), "[interface]"):
			b.wireguard(ci, k, proto, label, strings.Contains(strings.ToLower(t), "\njc"))
		case strings.HasPrefix(t, "{") && strings.Contains(t, "outbounds"):
			b.dispatch(ci, "Xray", k, k+".json", t, label, host, proto)
		case strings.Contains(t, "\nremote ") || strings.HasPrefix(t, "client"):
			b.dispatch(ci, "OpenVPN", k, k+".ovpn", amzSubst(t, b.doc), label, host, proto)
		default:
			continue
		}
		return
	}
	if name == "" {
		name = "container"
	}
	b.unsupported(ci, "", label, "unsupported Amnezia container "+name)
}

func (b *amzBuilder) document() {
	doc := b.doc
	if amzIsAPI(doc) {
		if _, ok := doc["containers"]; !ok || len(amzContainers(doc)) == 0 {
			b.unsupported(-1, "AmneziaVPN", amzStr(doc, "description", "name"), "Amnezia subscription (API) key: the VPN config is fetched from the Amnezia service at connect time")
			return
		}
	}
	conts := amzContainers(doc)
	start := len(b.configs)
	for i, c := range conts {
		b.container(i, c)
	}
	if len(b.configs) == start {
		if len(conts) == 0 {
			c := invalidConfig(b.f, "AmneziaVPN", errors.New("Amnezia config has no containers"))
			c.Name = amzStr(doc, "description", "hostName")
			b.add(-1, c)
			return
		}
		b.unsupported(-1, "", amzStr(doc, "description", "hostName"), "Amnezia config has no VPN containers (only services such as DNS/SFTP/Tor)")
		return
	}
	if amzStr(doc, "userName") != "" && (amzStr(doc, "password") != "" || amzStr(doc, "port") != "") {
		for _, c := range b.configs[start:] {
			c.Warn("file also contains server SSH credentials (not used)")
		}
	}
}

func amzContainers(doc map[string]any) []map[string]any {
	var out []map[string]any
	if cs, ok := doc["containers"].([]any); ok {
		for _, c := range cs {
			if co, ok := c.(map[string]any); ok {
				out = append(out, co)
			}
		}
	}
	return out
}

func amzParse(f *vfile, fs *vfs) ([]*Config, []amzOwner, []*amzDoc, error) {
	docs, errs := amzExtract(f.Text())
	if len(docs) == 0 {
		if len(errs) > 0 {
			return nil, nil, nil, errs[0]
		}
		return nil, nil, nil, errors.New("no Amnezia config found")
	}
	b := &amzBuilder{f: f, fs: fs}
	for i, d := range docs {
		b.docIdx, b.doc = i, d.obj
		b.document()
	}
	for _, c := range b.configs {
		if c.Format == "" || c.Format == "Unknown" {
			c.Format = "AmneziaVPN"
		}
	}
	return b.configs, b.owners, docs, nil
}

type AmneziaVpnConfigParser struct{}

func (AmneziaVpnConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	cs, _, _, err := amzParse(f, fs)
	return cs, err
}

func amzEncode(obj map[string]any, compressed bool) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(obj); err != nil {
		return "", err
	}
	js := bytes.TrimRight(buf.Bytes(), "\n")
	if !compressed {
		return string(js) + "\n", nil
	}
	var z bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(js)))
	z.Write(hdr[:])
	w, err := zlib.NewWriterLevel(&z, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	w.Write(js)
	w.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(z.Bytes()), nil
}

type AmneziaVpnFilter struct{}

func (AmneziaVpnFilter) Filter(f *vfile, indices []int) ([]byte, error) {
	_, owners, docs, err := amzParse(f, nil)
	if err != nil {
		return nil, err
	}
	keepDoc := map[int]bool{}
	keepCont := map[int]map[int]bool{}
	for _, i := range indices {
		if i < 0 || i >= len(owners) {
			continue
		}
		o := owners[i]
		if o.cont < 0 {
			keepDoc[o.doc] = true
			continue
		}
		if keepCont[o.doc] == nil {
			keepCont[o.doc] = map[int]bool{}
		}
		keepCont[o.doc][o.cont] = true
	}
	var out []string
	for di, d := range docs {
		if !keepDoc[di] && len(keepCont[di]) == 0 {
			continue
		}
		obj := d.obj
		if !keepDoc[di] {
			cp := make(map[string]any, len(obj))
			for k, v := range obj {
				cp[k] = v
			}
			var kept []any
			var names []string
			for ci, c := range amzContainers(obj) {
				if keepCont[di][ci] {
					kept = append(kept, c)
					names = append(names, amzStr(c, "container"))
				}
			}
			cp["containers"] = kept
			def := amzStr(obj, "defaultContainer")
			found := false
			for _, n := range names {
				if n == def {
					found = true
				}
			}
			if !found && len(names) > 0 {
				cp["defaultContainer"] = names[0]
			}
			obj = cp
		}
		s, err := amzEncode(obj, d.encoded)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("no configs selected")
	}
	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res), nil
}

func init() {
	registerFormat(&fileFormat{Name: "AmneziaVPN", Detector: AmneziaVpnDetector{}, Parser: AmneziaVpnConfigParser{}, Filter: AmneziaVpnFilter{}})
}
