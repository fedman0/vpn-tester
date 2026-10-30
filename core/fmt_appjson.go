package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type ajObj map[string]any

func ajParse(f *vfile) ([]ajObj, bool, error) {
	t := bytes.TrimSpace(bytes.TrimPrefix(f.Data, []byte{0xEF, 0xBB, 0xBF}))
	if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return nil, false, errors.New("not json")
	}
	var v any
	if err := json.Unmarshal(t, &v); err != nil {
		return nil, false, err
	}
	switch x := v.(type) {
	case map[string]any:
		for _, k := range []string{"configs", "servers", "profiles", "items"} {
			if arr, ok := x[k].([]any); ok && len(arr) > 0 {
				var out []ajObj
				for _, e := range arr {
					if m, ok := e.(map[string]any); ok {
						out = append(out, ajObj(m))
					}
				}
				if len(out) > 0 {
					return out, true, nil
				}
			}
		}
		return []ajObj{ajObj(x)}, false, nil
	case []any:
		var out []ajObj
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, ajObj(m))
			}
		}
		return out, true, nil
	}
	return nil, false, errors.New("unexpected json")
}

func (o ajObj) sub(keys ...string) ajObj {
	for _, k := range keys {
		for kk, v := range o {
			if strings.EqualFold(kk, k) {
				if m, ok := v.(map[string]any); ok {
					return ajObj(m)
				}
			}
		}
	}
	return nil
}

func (o ajObj) str(keys ...string) string {
	if o == nil {
		return ""
	}
	for _, k := range keys {
		for kk, v := range o {
			if !strings.EqualFold(kk, k) || v == nil {
				continue
			}
			switch x := v.(type) {
			case string:
				if s := strings.TrimSpace(x); s != "" {
					return s
				}
			case float64:
				return strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				if x {
					return "true"
				}
				return "false"
			case []any:
				var parts []string
				for _, e := range x {
					parts = append(parts, fmt.Sprint(e))
				}
				if len(parts) > 0 {
					return strings.Join(parts, ",")
				}
			}
		}
	}
	return ""
}

func (o ajObj) num(keys ...string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(o.str(keys...)))
	return n
}

func (o ajObj) flag(keys ...string) bool {
	switch strings.ToLower(o.str(keys...)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func (o ajObj) has(keys ...string) bool {
	for _, k := range keys {
		for kk := range o {
			if strings.EqualFold(kk, k) {
				return true
			}
		}
	}
	return false
}

func ajMerged(o ajObj, nested ...string) ajObj {
	m := ajObj{}
	for k, v := range o {
		m[k] = v
	}
	for _, n := range nested {
		if s := o.sub(n); s != nil {
			for k, v := range s {
				if _, exists := m[k]; !exists {
					m[k] = v
				}
			}
		}
	}
	return m
}

func ajIsClientConfig(o ajObj) bool {
	return o.has("outbounds", "inbounds", "proxies", "proxy-groups", "routing", "containers")
}

func ajSplitHostPort(s string, def int) (string, int) {
	s = strings.TrimSpace(s)
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		if n == 0 {
			n = def
		}
		return strings.Trim(h, "[]"), n
	}
	return strings.Trim(s, "[]"), def
}

func ajV2Link(proto string, o ajObj, name string) (string, error) {
	server := o.str("server", "address", "add", "host_address", "server_address")
	port := o.num("port", "server_port", "serverport")
	if server != "" && port == 0 {
		server, port = ajSplitHostPort(server, 0)
	}
	if server == "" || port == 0 {
		return "", errors.New("missing server or port")
	}
	hp := net.JoinHostPort(server, strconv.Itoa(port))
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	netw := strings.ToLower(o.str("network", "transport", "net", "type_network"))
	if netw == "" || netw == "standard" {
		netw = "tcp"
	}
	sec := strings.ToLower(o.str("security", "tls_type"))
	if sec == "" && (o.flag("tls", "tls_enabled", "enabled_tls") || o.sub("tls").flag("enabled")) {
		sec = "tls"
	}
	if o.str("reality_public_key", "public_key_reality", "pbk") != "" {
		sec = "reality"
	}
	set("type", netw)
	set("security", sec)
	set("sni", o.str("sni", "server_name", "servername", "peer"))
	set("fp", o.str("fingerprint", "fp", "utls"))
	set("alpn", o.str("alpn"))
	set("path", o.str("path", "ws_path"))
	set("host", o.str("host", "ws_host", "host_header"))
	set("serviceName", o.str("service_name", "servicename", "grpc_service"))
	set("flow", o.str("flow"))
	set("pbk", o.str("reality_public_key", "public_key_reality", "pbk"))
	set("sid", o.str("reality_short_id", "short_id", "sid"))
	set("spx", o.str("reality_spider_x", "spider_x", "spx"))
	if o.flag("allow_insecure", "allowinsecure", "insecure", "skip_cert_verify") {
		q.Set("allowInsecure", "1")
	}
	frag := url.PathEscape(name)
	switch proto {
	case "vless":
		uuid := o.str("uuid", "id", "user_id")
		if uuid == "" {
			return "", errors.New("missing uuid")
		}
		set("encryption", firstNonEmpty(o.str("encryption"), "none"))
		return "vless://" + uuid + "@" + hp + "?" + q.Encode() + "#" + frag, nil
	case "trojan":
		pw := o.str("password", "pass")
		if pw == "" {
			return "", errors.New("missing password")
		}
		return "trojan://" + url.PathEscape(pw) + "@" + hp + "?" + q.Encode() + "#" + frag, nil
	case "vmess":
		uuid := o.str("uuid", "id", "user_id")
		if uuid == "" {
			return "", errors.New("missing uuid")
		}
		j := map[string]any{
			"v": "2", "ps": name, "add": server, "port": strconv.Itoa(port), "id": uuid,
			"aid": firstNonEmpty(o.str("alter_id", "alterid", "aid"), "0"), "scy": firstNonEmpty(o.str("cipher", "scy"), "auto"),
			"net": netw, "type": firstNonEmpty(o.str("header_type", "headertype"), "none"), "host": o.str("host", "ws_host", "host_header"),
			"path": firstNonEmpty(o.str("path", "ws_path"), o.str("service_name", "servicename")), "tls": sec, "sni": o.str("sni", "server_name", "servername"),
			"fp": o.str("fingerprint", "fp"), "alpn": o.str("alpn"),
		}
		b, _ := json.Marshal(j)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
	case "ss":
		method := firstNonEmpty(o.str("method", "cipher", "encryption"), "chacha20-ietf-poly1305")
		pw := o.str("password", "pass")
		if pw == "" {
			return "", errors.New("missing password")
		}
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(method+":"+pw)) + "@" + hp + "#" + frag, nil
	case "hysteria2":
		pw := o.str("password", "auth", "auth_str")
		h := url.Values{}
		if v := o.str("sni", "server_name", "servername"); v != "" {
			h.Set("sni", v)
		}
		if v := o.str("obfs"); v != "" && !strings.EqualFold(v, "none") {
			h.Set("obfs", v)
			h.Set("obfs-password", o.str("obfs_password", "obfs-password", "obfspassword"))
		}
		if o.flag("allow_insecure", "insecure", "skip_cert_verify") {
			h.Set("insecure", "1")
		}
		if v := o.str("port_hopping", "ports", "mport", "hop_ports"); v != "" {
			h.Set("mport", v)
		}
		return "hysteria2://" + url.PathEscape(pw) + "@" + hp + "?" + h.Encode() + "#" + frag, nil
	case "socks", "http":
		cred := ""
		if u := o.str("username", "user"); u != "" {
			cred = url.PathEscape(u) + ":" + url.PathEscape(o.str("password", "pass")) + "@"
		}
		scheme := "socks5"
		if proto == "http" {
			scheme = "http"
		}
		return scheme + "://" + cred + hp + "#" + frag, nil
	}
	return "", fmt.Errorf("unsupported protocol %q", proto)
}

func ajNormProto(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "vless":
		return "vless"
	case "vmess":
		return "vmess"
	case "trojan":
		return "trojan"
	case "ss", "shadowsocks", "shadowsocks2022", "ss2022":
		return "ss"
	case "hy2", "hysteria2", "hysteria":
		return "hysteria2"
	case "socks", "socks5":
		return "socks"
	case "http", "https":
		return "http"
	case "ssh", "ssh_payload", "ssh-payload", "ssh_ssl", "ssh-ssl", "ssh_tls", "ssh_ws", "ssh_websocket":
		return "ssh"
	case "slowdns", "dnstt", "slow_dns", "dns", "ssh_slowdns", "ssh-slowdns", "slowdns_ssh":
		return "slowdns"
	case "wg", "wireguard":
		return "wireguard"
	case "openvpn", "ovpn":
		return "openvpn"
	case "v2ray", "xray":
		return "v2ray"
	}
	return ""
}

func ajSSHSpec(o ajObj, name string) *sshSpec {
	inj := o.sub("injection", "proxy", "http_injection")
	s := &sshSpec{
		Name:      name,
		Host:      o.str("ssh_host", "ssh_server", "server", "host_ssh", "address", "host"),
		Port:      o.num("ssh_port", "port", "server_port"),
		Username:  o.str("ssh_user", "ssh_username", "username", "user"),
		Password:  o.str("ssh_pass", "ssh_password", "password", "pass"),
		SNI:       o.str("sni", "server_name", "ssl_sni", "tls_sni"),
		ProxyHost: firstNonEmpty(o.str("proxy_host", "proxy_ip", "remote_proxy", "proxy_server"), inj.str("proxy_host", "host")),
		ProxyPort: o.num("proxy_port", "remote_proxy_port"),
		Payload:   firstNonEmpty(o.str("payload", "custom_payload", "http_payload"), inj.str("payload")),
		WSPath:    o.str("ws_path", "path"),
		WSHost:    o.str("ws_host", "host_header"),
		UserAgent: o.str("user_agent", "ua"),
	}
	if s.ProxyPort == 0 && inj != nil {
		s.ProxyPort = inj.num("proxy_port", "port")
	}
	if s.Host != "" && s.Port == 0 {
		s.Host, s.Port = ajSplitHostPort(s.Host, 22)
	}
	if s.Port == 0 {
		s.Port = 22
	}
	if s.ProxyHost != "" && s.ProxyPort == 0 {
		s.ProxyHost, s.ProxyPort = ajSplitHostPort(s.ProxyHost, 8080)
	}
	if inj != nil && !inj.flag("enabled") && inj.has("enabled") {
		s.ProxyHost, s.ProxyPort, s.Payload = "", 0, ""
	}
	mode := strings.ToLower(o.str("transport", "method", "mode", "tunnel_type", "connection_type"))
	switch {
	case strings.Contains(mode, "ws") || strings.Contains(mode, "websocket"):
		s.Mode = "ws"
		if strings.Contains(mode, "wss") || strings.Contains(mode, "ssl") || strings.Contains(mode, "tls") {
			s.Mode = "wss"
		}
	case strings.Contains(mode, "ssl") || strings.Contains(mode, "tls") || strings.Contains(mode, "stunnel"):
		s.Mode = "tls"
		if s.Payload != "" {
			s.Mode = "tls+payload"
		}
	case s.ProxyHost != "":
		s.Mode = "proxy"
	case s.Payload != "":
		s.Mode = "payload"
	default:
		s.Mode = "direct"
	}
	return s
}

func ajDNSTTSpec(o ajObj, name string) *dnsttSpec {
	d := o.sub("slowdns", "dnstt", "dns_tunnel")
	m := o
	if d != nil {
		m = ajMerged(d)
		for k, v := range o {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
	}
	s := &dnsttSpec{
		Name:       name,
		Domain:     m.str("nameserver", "name_server", "ns", "dns_nameserver", "domain", "tunnel_domain"),
		PublicKey:  m.str("public_key", "pubkey", "dns_public_key", "dnstt_key", "server_pubkey"),
		RecordType: m.str("record_type", "dns_type", "query_type"),
		Transport:  strings.ToLower(m.str("dns_transport", "resolver_type")),
		Variant:    strings.ToLower(m.str("variant", "dns_variant")),
	}
	for _, r := range strings.FieldsFunc(m.str("dns_resolver", "resolver", "resolvers", "dns", "dns_server"), func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if r = strings.TrimSpace(r); r != "" {
			s.Resolvers = append(s.Resolvers, r)
		}
	}
	if u := o.str("ssh_user", "ssh_username", "username", "user"); u != "" {
		s.Upstream = "ssh"
		ssh := ajSSHSpec(o, name)
		ssh.Mode = "dnstt"
		ssh.DNSTT = nil
		s.SSH = ssh
	} else if m.str("socks_user") != "" || strings.EqualFold(m.str("upstream"), "socks5") {
		s.Upstream = "socks5"
		s.SocksUser, s.SocksPass = m.str("socks_user"), m.str("socks_pass", "socks_password")
	}
	return s
}

func ajWireGuard(f *vfile, fs *vfs, o ajObj, name string, idx int) []*Config {
	priv := o.str("private_key", "privatekey", "secret_key")
	pub := o.str("server_public_key", "public_key", "peer_public_key", "publickey")
	ep := o.str("server_endpoint", "endpoint", "peer")
	if ep == "" {
		if h := o.str("server", "address"); h != "" {
			ep = net.JoinHostPort(h, strconv.Itoa(firstPositive(o.num("port", "server_port"), 51820)))
		}
	}
	var b strings.Builder
	b.WriteString("[Interface]\nPrivateKey = " + priv + "\n")
	if v := o.str("client_address", "address_local", "local_address", "interface_address", "ip"); v != "" {
		b.WriteString("Address = " + v + "\n")
	}
	if v := o.str("dns"); v != "" {
		b.WriteString("DNS = " + v + "\n")
	}
	if v := o.str("mtu"); v != "" {
		b.WriteString("MTU = " + v + "\n")
	}
	b.WriteString("\n[Peer]\nPublicKey = " + pub + "\n")
	if v := o.str("preshared_key", "presharedkey", "psk"); v != "" {
		b.WriteString("PresharedKey = " + v + "\n")
	}
	b.WriteString("Endpoint = " + ep + "\n")
	b.WriteString("AllowedIPs = " + firstNonEmpty(o.str("allowed_ips", "allowedips"), "0.0.0.0/0, ::/0") + "\n")
	if v := o.str("persistent_keepalive", "keepalive"); v != "" {
		b.WriteString("PersistentKeepalive = " + v + "\n")
	}
	cs, _ := parseAs("WireGuard", f.Child(fmt.Sprintf("wg%d", idx), fmt.Sprintf("%s.conf", firstNonEmpty(name, "wireguard")), []byte(b.String())), fs)
	return cs
}

func firstPositive(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func ajLinkConfigs(f *vfile, fs *vfs, link string, idx int) []*Config {
	return linkConfigs(f.Child(fmt.Sprintf("cfg%d", idx), fmt.Sprintf("cfg%d.txt", idx), []byte(link)), fs, link)
}

func ajBuild(f *vfile, fs *vfs, o ajObj, proto string, idx int) []*Config {
	name := o.str("name", "remarks", "remark", "ps", "title", "tag", "profile_name")
	flat := ajMerged(o, "auth", "transport", "tls", "settings", "server_config")
	switch proto {
	case "ssh":
		if o.sub("slowdns", "dnstt") != nil || o.str("nameserver", "dns_nameserver") != "" {
			return []*Config{dnsttConfig(f, fs, ajDNSTTSpec(o, name))}
		}
		return []*Config{sshConfig(f, fs, ajSSHSpec(flat, name))}
	case "slowdns":
		return []*Config{dnsttConfig(f, fs, ajDNSTTSpec(o, name))}
	case "wireguard":
		return ajWireGuard(f, fs, flat, name, idx)
	case "openvpn":
		if t := o.str("config", "ovpn", "openvpn_config", "content"); strings.Contains(t, "remote") {
			cs, _ := parseAs("OpenVPN", f.Child(fmt.Sprintf("ovpn%d", idx), firstNonEmpty(name, "config")+".ovpn", []byte(t)), fs)
			return cs
		}
		return []*Config{unsupportedConfig(f, "JSON", "OpenVPN", "OpenVPN entry without an embedded .ovpn config")}
	case "v2ray":
		if inner := o.sub("v2ray_config", "xray_config", "v2ray", "config"); inner != nil {
			if ajIsClientConfig(inner) {
				b, _ := json.Marshal(inner)
				cs, _ := parseAs("Xray", f.Child(fmt.Sprintf("xray%d", idx), "config.json", b), fs)
				return cs
			}
			p := ajNormProto(inner.str("protocol", "type"))
			if p == "" || p == "v2ray" {
				return []*Config{invalidConfig(f, "JSON", errors.New("v2ray config without protocol"))}
			}
			return ajBuild(f, fs, ajMerged(inner, "auth", "transport", "tls"), p, idx)
		}
		if l := o.str("link", "uri", "url", "config_link"); strings.Contains(l, "://") {
			return ajLinkConfigs(f, fs, l, idx)
		}
		return []*Config{invalidConfig(f, "JSON", errors.New("v2ray entry without config"))}
	default:
		link, err := ajV2Link(proto, flat, name)
		if err != nil {
			return []*Config{invalidConfig(f, "JSON", err)}
		}
		cs := ajLinkConfigs(f, fs, link, idx)
		for _, c := range cs {
			if c.Name == "" {
				c.Name = name
			}
		}
		return cs
	}
}

func ajProtoOf(o ajObj) string {
	if p := ajNormProto(o.str("connection_mode", "mode_connection")); p != "" {
		return p
	}
	if p := ajNormProto(o.str("protocol", "type", "tunnel_type", "config_type")); p != "" {
		return p
	}
	switch {
	case o.str("nameserver", "dns_nameserver") != "" && o.str("public_key", "dns_public_key", "pubkey") != "":
		return "slowdns"
	case o.str("private_key") != "" && (o.str("server_public_key", "peer_public_key") != "" || o.str("server_endpoint", "endpoint") != ""):
		return "wireguard"
	case o.has("ssh_host", "ssh_user", "ssh_username"):
		return "ssh"
	case o.sub("v2ray_config", "xray_config") != nil:
		return "v2ray"
	}
	return ""
}

type appJSONFormat struct {
	name  string
	match func(o ajObj) int
}

func (a appJSONFormat) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) > 2<<20 {
		return 0
	}
	objs, _, err := ajParse(f)
	if err != nil || len(objs) == 0 {
		return 0
	}
	best := 0
	for _, o := range objs {
		if ajIsClientConfig(o) {
			return 0
		}
		if s := a.match(o); s > best {
			best = s
		}
	}
	return best
}

func (a appJSONFormat) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	objs, _, err := ajParse(f)
	if err != nil {
		return nil, err
	}
	var out []*Config
	for i, o := range objs {
		p := ajProtoOf(o)
		var cs []*Config
		if p == "" {
			cs = []*Config{invalidConfig(f, a.name, errors.New("cannot tell which protocol this entry uses"))}
		} else {
			cs = ajBuild(f, fs, o, p, i)
		}
		for _, c := range cs {
			c.Format = a.name
			c.File = f.Root().Path
			out = append(out, c)
		}
	}
	return out, nil
}

type appJSONFilter struct{}

func (appJSONFilter) Filter(f *vfile, indices []int) ([]byte, error) {
	objs, isArr, err := ajParse(f)
	if err != nil || !isArr {
		return f.Data, err
	}
	keep := map[int]bool{}
	for _, i := range indices {
		keep[i] = true
	}
	var out []ajObj
	for i, o := range objs {
		if keep[i] {
			out = append(out, o)
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

func matchHTTPCustom(o ajObj) int {
	t := strings.ToLower(o.str("type"))
	if t != "ssh" && t != "slowdns" && !strings.HasPrefix(t, "ssh") {
		return 0
	}
	if o.has("payload", "proxy_host", "nameserver", "public_key", "dns_resolver", "transport", "method") {
		return 75
	}
	if o.has("server", "username") {
		return 55
	}
	return 0
}

func matchHTTPInjector(o ajObj) int {
	if o.has("connection_mode") && o.has("server", "ssh_host", "v2ray_config") {
		return 80
	}
	if o.has("ssh_host") && o.has("ssh_user", "ssh_pass", "payload", "proxy_ip") {
		return 70
	}
	return 0
}

func matchSlowDNS(o ajObj) int {
	if o.str("nameserver", "dns_nameserver") != "" && o.str("public_key", "dns_public_key", "pubkey") != "" {
		return 70
	}
	return 0
}

func matchGenericJSON(o ajObj) int {
	p := ajNormProto(o.str("protocol"))
	if p == "" || p == "v2ray" {
		if o.str("private_key") != "" && (o.str("server_public_key") != "" || o.str("server_endpoint") != "") {
			return 60
		}
		return 0
	}
	if o.str("server", "address") != "" || o.sub("auth") != nil || o.str("nameserver") != "" {
		return 60
	}
	return 0
}

type npvsDetector struct{}

func (npvsDetector) Detect(f *vfile) int {
	t := bytes.TrimSpace(f.Data)
	if bytes.HasPrefix(t, []byte("npvs1:")) || bytes.HasPrefix(t, []byte("npvt1:")) {
		return 95
	}
	if f.Ext == "npvs" {
		return 60
	}
	return 0
}

type npvsParser struct{}

func (npvsParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	return []*Config{unsupportedConfig(f, "NapsternetV", "NapsternetV", "sealed NapsternetV config (encrypted, can only be opened by NapsternetV)")}, nil
}

type hevYAMLDetector struct{}

func (hevYAMLDetector) Detect(f *vfile) int {
	if !f.IsText() {
		return 0
	}
	t := f.Text()
	if strings.Contains(t, "socks5:") && strings.Contains(t, "tunnel:") && (strings.Contains(t, "ipv4:") || strings.Contains(t, "mtu:")) && !strings.Contains(t, "proxies:") {
		return 70
	}
	return 0
}

type hevYAMLParser struct{}

func (hevYAMLParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	return []*Config{unsupportedConfig(f, "hev-socks5-tunnel", "tun2socks", "local tun2socks settings: there is no server in this file")}, nil
}

type amTunnelDetector struct{}

func (amTunnelDetector) Detect(f *vfile) int {
	if !f.IsText() {
		return 0
	}
	secs := parseINI(f.Text())
	if len(secs) > 0 && secs[0].Has("Hash1") && secs[0].Has("Hash2") && secs[0].Has("Endpoint") && iniFind(secs, "Interface") == nil {
		return 80
	}
	return 0
}

type amTunnelParser struct{}

func (amTunnelParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	return []*Config{unsupportedConfig(f, "AM Tunnel", "WireGuard", "AM Tunnel relay entry: the real server and keys come from the AM Tunnel API, not from this file")}, nil
}

func init() {
	registerFormat(&fileFormat{Name: "HTTP Custom", Detector: appJSONFormat{"HTTP Custom", matchHTTPCustom}, Parser: appJSONFormat{"HTTP Custom", matchHTTPCustom}, Filter: appJSONFilter{}})
	registerFormat(&fileFormat{Name: "HTTP Injector", Detector: appJSONFormat{"HTTP Injector", matchHTTPInjector}, Parser: appJSONFormat{"HTTP Injector", matchHTTPInjector}, Filter: appJSONFilter{}})
	registerFormat(&fileFormat{Name: "SlowDNS", Detector: appJSONFormat{"SlowDNS", matchSlowDNS}, Parser: appJSONFormat{"SlowDNS", matchSlowDNS}, Filter: appJSONFilter{}})
	registerFormat(&fileFormat{Name: "JSON", Detector: appJSONFormat{"JSON", matchGenericJSON}, Parser: appJSONFormat{"JSON", matchGenericJSON}, Filter: appJSONFilter{}})
	registerFormat(&fileFormat{Name: "NapsternetV", Detector: npvsDetector{}, Parser: npvsParser{}})
	registerFormat(&fileFormat{Name: "hev-socks5-tunnel", Detector: hevYAMLDetector{}, Parser: hevYAMLParser{}})
	registerFormat(&fileFormat{Name: "AM Tunnel", Detector: amTunnelDetector{}, Parser: amTunnelParser{}})
	encryptedFormats["npvs"] = "NapsternetV"
}
