package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var sbSkipTypes = map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}

var sbKnownTypes = map[string]bool{
	"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "socks": true, "http": true,
	"hysteria": true, "hysteria2": true, "tuic": true, "anytls": true, "naive": true, "ssh": true,
	"shadowtls": true, "wireguard": true, "shadowsocksr": true, "mieru": true, "snell": true, "juicity": true,
	"tor": true, "tailscale": true,
}

type sbItem struct {
	list string
	pos  int
	obj  map[string]any
}

func sbTags(doc map[string]any) map[string]map[string]any {
	tags := map[string]map[string]any{}
	for _, l := range []string{"outbounds", "endpoints"} {
		for _, o := range pxList(doc, l) {
			if m, ok := o.(map[string]any); ok {
				if t := pxStr(m, "tag"); t != "" {
					if _, dup := tags[t]; !dup {
						tags[t] = m
					}
				}
			}
		}
	}
	return tags
}

func sbStlsUsed(doc map[string]any, tags map[string]map[string]any) map[string]bool {
	used := map[string]bool{}
	for _, l := range []string{"outbounds", "endpoints"} {
		for _, o := range pxList(doc, l) {
			m, ok := o.(map[string]any)
			if !ok {
				continue
			}
			d := pxStr(m, "detour")
			if t, ok := tags[d]; ok && strings.EqualFold(pxStr(t, "type"), "shadowtls") {
				used[d] = true
			}
		}
	}
	return used
}

func sbItems(doc map[string]any) []sbItem {
	tags := sbTags(doc)
	stls := sbStlsUsed(doc, tags)
	var out []sbItem
	for _, l := range []string{"outbounds", "endpoints"} {
		for i, o := range pxList(doc, l) {
			m, ok := o.(map[string]any)
			if !ok {
				continue
			}
			typ := strings.ToLower(pxStr(m, "type"))
			if sbSkipTypes[typ] || typ == "" {
				continue
			}
			if typ == "shadowtls" && stls[pxStr(m, "tag")] {
				continue
			}
			out = append(out, sbItem{list: l, pos: i, obj: m})
		}
	}
	return out
}

func sbDoc(f *vfile) (map[string]any, error) {
	v, err := pxDecodeJSON(f.Data)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("sing-box config must be a JSON object")
	}
	return doc, nil
}

type SingBoxConfigDetector struct{}

func (SingBoxConfigDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	t := f.Text()
	if !strings.Contains(t, "outbounds") && !strings.Contains(t, "endpoints") && !strings.Contains(t, "inbounds") {
		return 0
	}
	if s := strings.TrimSpace(string(pxStripJSONC(f.Data))); !strings.HasPrefix(s, "{") {
		return 0
	}
	doc, err := sbDoc(f)
	if err != nil {
		if strings.Contains(t, "\"outbounds\"") && strings.Contains(t, "\"server_port\"") {
			return 18
		}
		return 0
	}
	proxies, typed, xray := 0, 0, 0
	for _, l := range []string{"outbounds", "endpoints"} {
		for _, o := range pxList(doc, l) {
			m, ok := o.(map[string]any)
			if !ok {
				continue
			}
			if pxHas(m, "protocol") {
				xray++
				continue
			}
			typ := strings.ToLower(pxStr(m, "type"))
			if typ == "" {
				continue
			}
			typed++
			if sbKnownTypes[typ] && (pxHas(m, "server") || pxHas(m, "peers") || typ == "tor" || typ == "tailscale") {
				proxies++
			}
		}
	}
	for _, o := range pxList(doc, "inbounds") {
		if m, ok := o.(map[string]any); ok && pxHas(m, "type") && !pxHas(m, "protocol") {
			typed++
		}
	}
	switch {
	case proxies > 0 && proxies >= xray:
		return 80
	case typed > 0 && xray == 0:
		return 55
	}
	return 0
}

type SingBoxConfigParser struct{}

func (SingBoxConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	doc, err := sbDoc(f)
	if err != nil {
		return nil, err
	}
	tags := sbTags(doc)
	warns := sbCheck(doc, tags)
	items := sbItems(doc)
	if len(items) == 0 {
		c := unsupportedConfig(f, "sing-box", "", "no proxy outbounds in config")
		pxWarnAll(c, warns)
		return []*Config{c}, nil
	}
	out := make([]*Config, 0, len(items))
	for _, it := range items {
		c := sbConfig(f, fs, it.obj, tags)
		pxWarnAll(c, warns)
		c.RawConfig, _ = json.Marshal(it.obj)
		out = append(out, c)
	}
	return out, nil
}

func sbCheck(doc map[string]any, tags map[string]map[string]any) []string {
	var w []string
	add := func(format string, a ...any) {
		if len(w) < 4 {
			w = append(w, "sing-box check: "+fmt.Sprintf(format, a...))
		}
	}
	for _, k := range []string{"outbounds", "endpoints", "inbounds"} {
		if v, ok := doc[k]; ok && v != nil {
			if _, ok := v.([]any); !ok {
				add("%s must be an array", k)
			}
		}
	}
	seen := map[string]bool{}
	for _, l := range []string{"outbounds", "endpoints"} {
		for _, o := range pxList(doc, l) {
			m, ok := o.(map[string]any)
			if !ok {
				add("%s entry is not an object", l)
				continue
			}
			tag := pxStr(m, "tag")
			if tag != "" {
				if seen[tag] {
					add("duplicate tag %q", tag)
				}
				seen[tag] = true
			}
			typ := strings.ToLower(pxStr(m, "type"))
			if typ == "selector" || typ == "urltest" {
				for _, x := range pxStrs(m["outbounds"]) {
					if _, ok := tags[x]; !ok {
						add("outbound %q referenced by %q not found", x, tag)
					}
				}
			}
		}
	}
	if r := pxMap(doc, "route"); r != nil {
		if fin := pxStr(r, "final"); fin != "" {
			if _, ok := tags[fin]; !ok {
				add("route.final outbound %q not found", fin)
			}
		}
		for _, x := range pxList(r, "rules") {
			if rm, ok := x.(map[string]any); ok {
				if ob := pxStr(rm, "outbound"); ob != "" {
					if _, ok := tags[ob]; !ok {
						add("route rule outbound %q not found", ob)
					}
				}
			}
		}
	}
	return w
}

func sbResolve(tag string, tags map[string]map[string]any, depth int) (map[string]any, error) {
	if depth > 8 {
		return nil, fmt.Errorf("detour %q nests too deep", tag)
	}
	o, ok := tags[tag]
	if !ok {
		return nil, fmt.Errorf("detour outbound %q not found", tag)
	}
	switch strings.ToLower(pxStr(o, "type")) {
	case "selector", "urltest":
		cands := pxStrs(o["outbounds"])
		if d := pxStr(o, "default"); d != "" {
			cands = append([]string{d}, cands...)
		}
		for _, c := range cands {
			if r, err := sbResolve(c, tags, depth+1); err == nil {
				return r, nil
			}
		}
		return nil, fmt.Errorf("detour group %q has no usable outbound", tag)
	case "direct":
		return nil, nil
	case "block", "dns":
		return nil, fmt.Errorf("detour %q is not a proxy", tag)
	}
	return o, nil
}

func sbConfig(f *vfile, fs *vfs, o map[string]any, tags map[string]map[string]any) *Config {
	typ := strings.ToLower(pxStr(o, "type"))
	name := firstNonEmpty(pxStr(o, "tag"), typ)
	mk := func(c *Config) *Config {
		c.Name = name
		c.Host = pxStr(o, "server")
		c.Port = pxInt(o, "server_port")
		return c
	}
	switch typ {
	case "tor":
		return mk(unsupportedConfig(f, "sing-box", typ, "tor outbound needs the Tor network daemon"))
	case "tailscale":
		return mk(unsupportedConfig(f, "sing-box", typ, "tailscale endpoint joins a mesh network; not tested"))
	case "juicity", "shadowtls":
		return mk(sbViaLink(f, o, typ, name))
	}
	if !sbKnownTypes[typ] {
		return mk(unsupportedConfig(f, "sing-box", typ, "sing-box outbound type "+typ+" is not supported"))
	}
	var deps []*vfile
	m, notes, err := sbToMihomo(f, fs, o, tags, &deps)
	chain := []map[string]any{}
	if m != nil {
		chain = append(chain, m)
	}
	cur := o
	stls := false
	if d := pxStr(o, "detour"); d != "" {
		if t, ok := tags[d]; ok && strings.EqualFold(pxStr(t, "type"), "shadowtls") {
			stls = true
		}
	}
	for i := 0; err == nil && m != nil && i < 8; i++ {
		d := pxStr(cur, "detour")
		if d == "" || (stls && i == 0) {
			break
		}
		parent, rerr := sbResolve(d, tags, 0)
		if rerr != nil {
			err = rerr
			break
		}
		if parent == nil {
			break
		}
		pm, pn, perr := sbToMihomo(f, fs, parent, tags, &deps)
		if perr != nil {
			err = fmt.Errorf("detour %q: %w", d, perr)
			break
		}
		notes = append(notes, pn...)
		chain = append([]map[string]any{pm}, chain...)
		cur = parent
		if i == 7 {
			err = errors.New("detour chain too long")
		}
	}
	c := pxMihomoConfig(f, "sing-box", chain, name, err)
	if c.Protocol == "" {
		c.Protocol = typ
	}
	if c.Host == "" {
		c.Host = pxStr(o, "server")
		c.Port = pxInt(o, "server_port")
	}
	pxWarnAll(c, notes)
	for _, d := range deps {
		c.AddDep(fs, d, true)
	}
	return c
}

func sbViaLink(f *vfile, o map[string]any, typ, name string) *Config {
	host := pxStr(o, "server")
	port := pxInt(o, "server_port")
	t := pxMap(o, "tls")
	q := url.Values{}
	sni := pxStr(t, "server_name")
	if sni != "" {
		q.Set("sni", sni)
	}
	var link string
	meta := nodeMeta{Name: name, Host: host, Port: port, Security: "tls", SNI: sni}
	switch typ {
	case "juicity":
		if pxBool(t, "insecure") {
			q.Set("allow_insecure", "1")
		}
		if cc := pxStr(o, "congestion_control"); cc != "" {
			q.Set("congestion_control", cc)
		}
		meta.UUID = pxStr(o, "uuid")
		meta.Password = pxStr(o, "password")
		meta.Transport = "quic"
		meta.UDP = true
		link = "juicity://" + url.UserPassword(meta.UUID, meta.Password).String() + "@" + sbHostPort(host, port) + "?" + q.Encode()
	case "shadowtls":
		q.Set("version", firstNonEmpty(pxStr(o, "version"), "1"))
		meta.Password = pxStr(o, "password")
		meta.Transport = "tcp"
		link = "shadowtls://" + url.PathEscape(meta.Password) + "@" + sbHostPort(host, port) + "?" + q.Encode()
	}
	n, err := parseLink(link)
	c := newNodeConfig(f, "sing-box", n, err, meta)
	if c.Protocol == "" {
		c.Protocol = typ
	}
	return c
}

func sbHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

func sbToMihomo(f *vfile, fs *vfs, o map[string]any, tags map[string]map[string]any, deps *[]*vfile) (map[string]any, []string, error) {
	typ := strings.ToLower(pxStr(o, "type"))
	m := map[string]any{"name": firstNonEmpty(pxStr(o, "tag"), typ), "server": pxStr(o, "server"), "port": pxInt(o, "server_port")}
	var notes []string
	if pxBool(o, "tcp_fast_open") {
		m["tfo"] = true
	}
	for _, k := range []string{"bind_interface", "routing_mark", "inet4_bind_address", "inet6_bind_address", "netns"} {
		if pxHas(o, k) {
			notes = append(notes, k+" ignored during test")
		}
	}
	udp := !strings.EqualFold(pxStr(o, "network"), "tcp")
	switch typ {
	case "shadowsocks":
		m["type"] = "ss"
		m["cipher"] = strings.ToLower(pxStr(o, "method"))
		m["password"] = pxStr(o, "password")
		m["udp"] = udp
		if p := pxStr(o, "plugin"); p != "" {
			if err := sbSSPlugin(m, p, pxStr(o, "plugin_opts")); err != nil {
				return nil, notes, err
			}
		}
		if u, ok := o["udp_over_tcp"]; ok {
			switch t := u.(type) {
			case bool:
				m["udp-over-tcp"] = t
			case map[string]any:
				if pxBool(t, "enabled") {
					m["udp-over-tcp"] = true
					if v := pxInt(t, "version"); v > 0 {
						m["udp-over-tcp-version"] = v
					}
				}
			}
		}
		if d := pxStr(o, "detour"); d != "" {
			if st, ok := tags[d]; ok && strings.EqualFold(pxStr(st, "type"), "shadowtls") {
				if pxHas(m, "plugin") {
					return nil, notes, errors.New("shadowsocks plugin combined with shadowtls detour is not supported")
				}
				stTLS := pxMap(st, "tls")
				ver := pxInt(st, "version")
				if ver == 0 {
					ver = 1
				}
				m["server"] = pxStr(st, "server")
				m["port"] = pxInt(st, "server_port")
				m["plugin"] = "shadow-tls"
				m["plugin-opts"] = map[string]any{"host": firstNonEmpty(pxStr(stTLS, "server_name"), pxStr(st, "server")), "password": pxStr(st, "password"), "version": ver}
				fp := "chrome"
				if u := pxMap(stTLS, "utls"); u != nil && pxBool(u, "enabled") && pxStr(u, "fingerprint") != "" {
					fp = pxStr(u, "fingerprint")
				}
				m["client-fingerprint"] = fp
			}
		}
		sbMux(o, m)
		return m, notes, nil
	case "shadowsocksr":
		m["type"] = "ssr"
		m["cipher"] = pxStr(o, "method")
		m["password"] = pxStr(o, "password")
		m["obfs"] = firstNonEmpty(pxStr(o, "obfs"), "plain")
		m["obfs-param"] = pxStr(o, "obfs_param")
		m["protocol"] = firstNonEmpty(pxStr(o, "protocol"), "origin")
		m["protocol-param"] = pxStr(o, "protocol_param")
		m["udp"] = udp
		return m, notes, nil
	case "vmess":
		m["type"] = "vmess"
		m["uuid"] = pxStr(o, "uuid")
		m["alterId"] = pxInt(o, "alter_id")
		m["cipher"] = firstNonEmpty(pxStr(o, "security"), "auto")
		m["udp"] = udp
		if pxBool(o, "global_padding") {
			m["global-padding"] = true
		}
		if pxBool(o, "authenticated_length") {
			m["authenticated-length"] = true
		}
		sbPacketEncoding(o, m, "")
	case "vless":
		m["type"] = "vless"
		m["uuid"] = pxStr(o, "uuid")
		if fl := pxStr(o, "flow"); fl != "" {
			m["flow"] = fl
		}
		m["udp"] = udp
		sbPacketEncoding(o, m, "xudp")
	case "trojan":
		m["type"] = "trojan"
		m["password"] = pxStr(o, "password")
		m["udp"] = udp
	case "socks":
		v := firstNonEmpty(pxStr(o, "version"), "5")
		if v != "5" {
			return nil, notes, fmt.Errorf("socks version %s not supported", v)
		}
		m["type"] = "socks5"
		if u := pxStr(o, "username"); u != "" {
			m["username"] = u
			m["password"] = pxStr(o, "password")
		}
		m["udp"] = udp
		return m, notes, nil
	case "http":
		m["type"] = "http"
		if u := pxStr(o, "username"); u != "" {
			m["username"] = u
			m["password"] = pxStr(o, "password")
		}
		if h := sbHeaders(o); len(h) > 0 {
			m["headers"] = h
		}
		if pxStr(o, "path") != "" {
			notes = append(notes, "http outbound path ignored")
		}
	case "hysteria":
		m["type"] = "hysteria"
		m["up"] = firstNonEmpty(pxStr(o, "up"), pxStr(o, "up_mbps"), "10")
		m["down"] = firstNonEmpty(pxStr(o, "down"), pxStr(o, "down_mbps"), "50")
		sbHop(o, m, false)
		if v := pxStr(o, "obfs"); v != "" {
			m["obfs"] = v
		}
		if v := pxStr(o, "auth_str"); v != "" {
			m["auth-str"] = v
		}
		if v := pxStr(o, "auth"); v != "" {
			m["auth"] = v
		}
		if v := pxInt(o, "recv_window_conn"); v > 0 {
			m["recv-window-conn"] = v
		}
		if v := pxInt(o, "recv_window"); v > 0 {
			m["recv-window"] = v
		}
		if pxBool(o, "disable_mtu_discovery") {
			m["disable-mtu-discovery"] = true
		}
		m["udp"] = true
	case "hysteria2":
		m["type"] = "hysteria2"
		m["password"] = pxStr(o, "password")
		if ob := pxMap(o, "obfs"); ob != nil && pxStr(ob, "password") != "" {
			m["obfs"] = firstNonEmpty(pxStr(ob, "type"), "salamander")
			m["obfs-password"] = pxStr(ob, "password")
		}
		if v := pxStr(o, "up_mbps"); v != "" {
			m["up"] = v
		}
		if v := pxStr(o, "down_mbps"); v != "" {
			m["down"] = v
		}
		sbHop(o, m, true)
		m["udp"] = true
	case "tuic":
		m["type"] = "tuic"
		m["uuid"] = pxStr(o, "uuid")
		m["password"] = pxStr(o, "password")
		if v := pxStr(o, "congestion_control"); v != "" {
			m["congestion-controller"] = v
		}
		if v := pxStr(o, "udp_relay_mode"); v != "" {
			m["udp-relay-mode"] = v
		}
		if pxBool(o, "zero_rtt_handshake") {
			m["reduce-rtt"] = true
		}
		if v := pxDurationMS(pxStr(o, "heartbeat")); v > 0 {
			m["heartbeat-interval"] = v
		}
		if pxBool(o, "udp_over_stream") {
			m["udp-over-stream"] = true
		}
		m["udp"] = true
	case "anytls":
		m["type"] = "anytls"
		m["password"] = pxStr(o, "password")
		if v := pxDuration(pxStr(o, "idle_session_check_interval")); v > 0 {
			m["idle-session-check-interval"] = v
		}
		if v := pxDuration(pxStr(o, "idle_session_timeout")); v > 0 {
			m["idle-session-timeout"] = v
		}
		if v := pxInt(o, "min_idle_session"); v > 0 {
			m["min-idle-session"] = v
		}
		m["udp"] = true
	case "naive":
		t := pxMap(o, "tls")
		m["type"] = "trusttunnel"
		m["username"] = pxStr(o, "username")
		m["password"] = pxStr(o, "password")
		m["sni"] = firstNonEmpty(pxStr(t, "server_name"), pxStr(o, "server"))
		if pxBool(o, "quic") {
			m["quic"] = true
		}
		if pxBool(t, "insecure") {
			m["skip-cert-verify"] = true
		}
		if m["port"] == 0 {
			m["port"] = 443
		}
		m["udp"] = true
		return m, notes, nil
	case "ssh":
		m["type"] = "ssh"
		if m["port"] == 0 {
			m["port"] = 22
		}
		m["username"] = firstNonEmpty(pxStr(o, "user"), "root")
		if v := pxStr(o, "password"); v != "" {
			m["password"] = v
		}
		key := strings.Join(pxStrs(o["private_key"]), "\n")
		if key == "" {
			if p := pxStr(o, "private_key_path"); p != "" {
				if kf := fs.Resolve(f, p); kf != nil {
					key = string(kf.Data)
					*deps = append(*deps, kf)
				} else {
					return nil, notes, fmt.Errorf("private_key_path %q not found in folder", p)
				}
			}
		}
		if key != "" {
			m["private-key"] = key
		}
		if v := pxStr(o, "private_key_passphrase"); v != "" {
			m["private-key-passphrase"] = v
		}
		if hk := pxStrs(o["host_key"]); len(hk) > 0 {
			m["host-key"] = hk
		}
		if ha := pxStrs(o["host_key_algorithms"]); len(ha) > 0 {
			m["host-key-algorithms"] = ha
		}
		return m, notes, nil
	case "wireguard":
		return sbWireGuard(o, m, notes)
	case "mieru":
		m["type"] = "mieru"
		if pr := pxPorts(o["server_ports"]); pr != "" {
			m["port-range"] = pr
			if m["port"] == 0 {
				delete(m, "port")
			}
		}
		m["transport"] = strings.ToUpper(firstNonEmpty(pxStr(o, "transport"), "TCP"))
		m["username"] = pxStr(o, "username")
		m["password"] = pxStr(o, "password")
		if v := pxStr(o, "multiplexing"); v != "" {
			m["multiplexing"] = v
		}
		m["udp"] = true
		return m, notes, nil
	case "snell":
		m["type"] = "snell"
		m["psk"] = pxStr(o, "psk")
		m["version"] = firstNonEmpty(pxStr(o, "version"), "1")
		mode := pxStr(o, "obfs_mode")
		host := pxStr(o, "obfs_host")
		if ob := pxMap(o, "obfs"); ob != nil {
			mode = firstNonEmpty(pxStr(ob, "mode", "type"), mode)
			host = firstNonEmpty(pxStr(ob, "host"), host)
		} else if s := pxStr(o, "obfs"); s != "" {
			mode = s
		}
		if mode != "" && mode != "none" {
			m["obfs-opts"] = map[string]any{"mode": mode, "host": firstNonEmpty(host, "bing.com")}
		}
		m["udp"] = true
		return m, notes, nil
	default:
		return nil, notes, fmt.Errorf("sing-box outbound type %q not supported", typ)
	}
	tn, err := sbTLS(f, fs, o, m, typ, deps)
	notes = append(notes, tn...)
	if err != nil {
		return nil, notes, err
	}
	if typ == "vmess" || typ == "vless" || typ == "trojan" {
		if err := sbTransport(o, m, typ); err != nil {
			return nil, notes, err
		}
		sbMux(o, m)
	}
	return m, notes, nil
}

func sbPacketEncoding(o, m map[string]any, def string) {
	pe := def
	if v, ok := o["packet_encoding"]; ok {
		pe = pxScalar(v)
	}
	switch pe {
	case "xudp":
		m["xudp"] = true
	case "packetaddr":
		m["packet-addr"] = true
	}
}

func sbHop(o, m map[string]any, v2 bool) {
	if ports := pxPorts(o["server_ports"]); ports != "" {
		m["ports"] = ports
		if pxInt(m, "port") == 0 {
			m["port"] = pxFirstPort(ports)
		}
	}
	if hi := pxDuration(pxStr(o, "hop_interval")); hi > 0 {
		if v2 {
			m["hop-interval"] = strconv.Itoa(hi)
		} else {
			m["hop-interval"] = hi
		}
	}
}

func sbSSPlugin(m map[string]any, plugin, opts string) error {
	name, o := parsePluginString(plugin + ";" + opts)
	switch name {
	case "obfs-local", "simple-obfs", "obfs":
		m["plugin"] = "obfs"
		m["plugin-opts"] = map[string]any{"mode": firstNonEmpty(o["obfs"], o["mode"], "http"), "host": firstNonEmpty(o["obfs-host"], o["host"], "bing.com")}
	case "v2ray-plugin":
		po := map[string]any{"mode": firstNonEmpty(o["mode"], "websocket"), "host": firstNonEmpty(o["host"], o["obfs-host"]), "path": firstNonEmpty(o["path"], "/")}
		if _, ok := o["tls"]; ok {
			po["tls"] = true
		}
		if v, ok := o["mux"]; ok && v != "0" && v != "false" {
			po["mux"] = true
		}
		m["plugin"] = "v2ray-plugin"
		m["plugin-opts"] = po
	default:
		return fmt.Errorf("shadowsocks plugin %q not supported", name)
	}
	return nil
}

func sbHeaders(t map[string]any) map[string]any {
	h := map[string]any{}
	for k, v := range pxMap(t, "headers") {
		if s := pxStrs(v); len(s) > 0 {
			h[k] = s[0]
		}
	}
	return h
}

func sbTLS(f *vfile, fs *vfs, o, m map[string]any, typ string, deps *[]*vfile) ([]string, error) {
	var notes []string
	t := pxMap(o, "tls")
	if t == nil || !pxBool(t, "enabled") {
		if typ == "trojan" {
			return notes, errors.New("trojan without TLS is not supported by mihomo")
		}
		return notes, nil
	}
	sniKey := "sni"
	switch typ {
	case "vmess", "vless":
		m["tls"] = true
		sniKey = "servername"
	case "http":
		m["tls"] = true
	}
	if sn := pxStr(t, "server_name"); sn != "" {
		m[sniKey] = sn
	}
	if pxBool(t, "insecure") {
		m["skip-cert-verify"] = true
	}
	if alpn := pxStrs(t["alpn"]); len(alpn) > 0 {
		m["alpn"] = alpn
	} else if typ == "tuic" {
		m["alpn"] = []string{"h3"}
	}
	if u := pxMap(t, "utls"); u != nil && pxBool(u, "enabled") {
		m["client-fingerprint"] = firstNonEmpty(pxStr(u, "fingerprint"), "chrome")
	}
	if r := pxMap(t, "reality"); r != nil && pxBool(r, "enabled") {
		m["reality-opts"] = map[string]any{"public-key": pxStr(r, "public_key"), "short-id": pxStr(r, "short_id")}
		if !pxHas(m, "client-fingerprint") {
			m["client-fingerprint"] = "chrome"
		}
	}
	if e := pxMap(t, "ech"); e != nil && pxBool(e, "enabled") {
		cfg := pxECHConfig(pxStrs(e["config"]))
		if cfg == "" {
			if p := pxStr(e, "config_path"); p != "" {
				if ef := fs.Resolve(f, p); ef != nil {
					cfg = pxECHConfig([]string{string(ef.Data)})
					*deps = append(*deps, ef)
				}
			}
		}
		eo := map[string]any{"enable": true}
		if cfg != "" {
			eo["config"] = cfg
		}
		m["ech-opts"] = eo
	}
	cert := strings.Join(pxStrs(t["certificate"]), "\n")
	if cert == "" {
		if p := pxStr(t, "certificate_path"); p != "" {
			cf := fs.Resolve(f, p)
			if cf == nil {
				return notes, fmt.Errorf("certificate_path %q not found in folder", p)
			}
			cert = string(cf.Data)
			*deps = append(*deps, cf)
		}
	}
	if cert != "" && !pxBool(t, "insecure") {
		if pin := pxCertPin([]byte(cert)); pin != "" {
			m["fingerprint"] = pin
			notes = append(notes, "custom TLS certificate mapped to a certificate pin")
		}
	}
	if pxBool(t, "disable_sni") && typ == "tuic" {
		m["disable-sni"] = true
	}
	return notes, nil
}

func sbTransport(o, m map[string]any, typ string) error {
	t := pxMap(o, "transport")
	if t == nil {
		m["network"] = "tcp"
		return nil
	}
	tlsOn := typ == "trojan" || m["tls"] == true
	tt := strings.ToLower(pxStr(t, "type"))
	switch tt {
	case "ws":
		ws := map[string]any{"path": firstNonEmpty(pxStr(t, "path"), "/")}
		if h := sbHeaders(t); len(h) > 0 {
			ws["headers"] = h
		}
		if n := pxInt(t, "max_early_data"); n > 0 {
			ws["max-early-data"] = n
			if hn := pxStr(t, "early_data_header_name"); hn != "" {
				ws["early-data-header-name"] = hn
			}
		}
		m["network"] = "ws"
		m["ws-opts"] = ws
	case "httpupgrade":
		ws := map[string]any{"path": firstNonEmpty(pxStr(t, "path"), "/"), "v2ray-http-upgrade": true}
		h := sbHeaders(t)
		if host := pxStr(t, "host"); host != "" {
			h["Host"] = host
		}
		if len(h) > 0 {
			ws["headers"] = h
		}
		m["network"] = "ws"
		m["ws-opts"] = ws
	case "grpc":
		m["network"] = "grpc"
		m["grpc-opts"] = map[string]any{"grpc-service-name": pxStr(t, "service_name")}
	case "http":
		if typ == "trojan" {
			return errors.New("trojan with HTTP transport is not supported by mihomo")
		}
		hosts := pxStrs(t["host"])
		path := firstNonEmpty(pxStr(t, "path"), "/")
		if tlsOn {
			h2 := map[string]any{"path": path}
			if len(hosts) > 0 {
				h2["host"] = hosts
			}
			m["network"] = "h2"
			m["h2-opts"] = h2
		} else {
			ho := map[string]any{"path": []string{path}}
			if mt := pxStr(t, "method"); mt != "" {
				ho["method"] = mt
			}
			if len(hosts) > 0 {
				ho["headers"] = map[string]any{"Host": hosts}
			}
			m["network"] = "http"
			m["http-opts"] = ho
		}
	case "quic":
		return errors.New("V2Ray QUIC transport is not supported by mihomo")
	default:
		return fmt.Errorf("transport %q not supported", tt)
	}
	return nil
}

func sbMux(o, m map[string]any) {
	mx := pxMap(o, "multiplex")
	if mx == nil || !pxBool(mx, "enabled") {
		return
	}
	s := map[string]any{"enabled": true, "protocol": firstNonEmpty(pxStr(mx, "protocol"), "h2mux")}
	if n := pxInt(mx, "max_connections"); n > 0 {
		s["max-connections"] = n
	}
	if n := pxInt(mx, "min_streams"); n > 0 {
		s["min-streams"] = n
	}
	if n := pxInt(mx, "max_streams"); n > 0 {
		s["max-streams"] = n
	}
	if pxBool(mx, "padding") {
		s["padding"] = true
	}
	if b := pxMap(mx, "brutal"); b != nil && pxBool(b, "enabled") {
		s["brutal-opts"] = map[string]any{"enabled": true, "up": pxStr(b, "up_mbps"), "down": pxStr(b, "down_mbps")}
	}
	m["smux"] = s
}

func sbWGPeer(p map[string]any) map[string]any {
	out := map[string]any{
		"server":     pxStr(p, "address", "server"),
		"port":       pxInt(p, "port", "server_port"),
		"public-key": pxStr(p, "public_key"),
	}
	if v := pxStr(p, "pre_shared_key"); v != "" {
		out["pre-shared-key"] = v
	}
	if r := pxReserved(p["reserved"]); len(r) > 0 {
		out["reserved"] = r
	}
	if a := pxStrs(p["allowed_ips"]); len(a) > 0 {
		out["allowed-ips"] = a
	}
	return out
}

func sbWireGuard(o, m map[string]any, notes []string) (map[string]any, []string, error) {
	m["type"] = "wireguard"
	m["private-key"] = pxStr(o, "private_key")
	m["udp"] = true
	if v := pxInt(o, "mtu"); v > 0 {
		m["mtu"] = v
	}
	addrs := pxStrs(o["local_address"])
	if len(addrs) == 0 {
		addrs = pxStrs(o["address"])
	}
	v4, v6 := pxSplitAddrs(addrs)
	if v4 != "" {
		m["ip"] = strings.SplitN(v4, "/", 2)[0]
	}
	if v6 != "" {
		m["ipv6"] = strings.SplitN(v6, "/", 2)[0]
	}
	if v4 == "" && v6 == "" {
		return nil, notes, errors.New("wireguard has no local address")
	}
	if pxBool(o, "system") || pxBool(o, "system_interface") {
		notes = append(notes, "system interface mode replaced by userspace stack during test")
	}
	peers := pxList(o, "peers")
	switch {
	case len(peers) == 1:
		p, _ := peers[0].(map[string]any)
		for k, v := range sbWGPeer(p) {
			m[k] = v
		}
		if ka := pxInt(p, "persistent_keepalive_interval"); ka > 0 {
			m["persistent-keepalive"] = ka
		}
	case len(peers) > 1:
		var ps []any
		for _, x := range peers {
			p, _ := x.(map[string]any)
			ps = append(ps, sbWGPeer(p))
		}
		m["peers"] = ps
		first := ps[0].(map[string]any)
		m["server"] = first["server"]
		m["port"] = first["port"]
	default:
		m["public-key"] = pxStr(o, "peer_public_key")
		if v := pxStr(o, "pre_shared_key"); v != "" {
			m["pre-shared-key"] = v
		}
		if r := pxReserved(o["reserved"]); len(r) > 0 {
			m["reserved"] = r
		}
	}
	if pxStr(m, "server") == "" || pxInt(m, "port") == 0 {
		return nil, notes, errors.New("wireguard peer has no endpoint")
	}
	return m, notes, nil
}

type SingBoxConfigFilter struct{}

func (SingBoxConfigFilter) Filter(f *vfile, idx []int) ([]byte, error) {
	ov, err := pxParseOrdered(f.Data)
	if err != nil {
		return f.Data, nil
	}
	root, ok := ov.(*pxObj)
	if !ok {
		return f.Data, nil
	}
	doc := pxPlain(root).(map[string]any)
	items := sbItems(doc)
	if len(items) == 0 {
		return f.Data, nil
	}
	keep := make([]bool, len(items))
	for _, i := range idx {
		if i >= 0 && i < len(items) {
			keep[i] = true
		}
	}
	tags := sbTags(doc)
	itemByTag := map[string]int{}
	for i, it := range items {
		if t := pxStr(it.obj, "tag"); t != "" {
			if _, dup := itemByTag[t]; !dup {
				itemByTag[t] = i
			}
		}
	}
	var mark func(tag string, depth int) bool
	mark = func(tag string, depth int) bool {
		if depth > 8 {
			return false
		}
		ch := false
		if j, ok := itemByTag[tag]; ok {
			if !keep[j] {
				keep[j] = true
				ch = true
			}
			return ch
		}
		if o, ok := tags[tag]; ok {
			for _, x := range pxStrs(o["outbounds"]) {
				if mark(x, depth+1) {
					ch = true
				}
			}
		}
		return ch
	}
	for changed := true; changed; {
		changed = false
		for i, it := range items {
			if keep[i] && mark(pxStr(it.obj, "detour"), 0) {
				changed = true
			}
		}
	}
	removed := map[string]bool{}
	drop := map[string]map[int]bool{"outbounds": {}, "endpoints": {}}
	kept := 0
	for i, it := range items {
		if keep[i] {
			kept++
			continue
		}
		drop[it.list][it.pos] = true
		if t := pxStr(it.obj, "tag"); t != "" {
			removed[t] = true
		}
	}
	if kept == len(items) {
		return f.Data, nil
	}
	for i, it := range items {
		if keep[i] {
			delete(removed, pxStr(it.obj, "tag"))
		}
	}
	for _, l := range []string{"outbounds", "endpoints"} {
		arr := root.List(l)
		if arr == nil {
			continue
		}
		var na []any
		for i, e := range arr {
			if !drop[l][i] {
				na = append(na, e)
			}
		}
		if na == nil {
			na = []any{}
		}
		root.Set(l, na)
	}
	for again := true; again; {
		again = false
		obs := root.List("outbounds")
		var na []any
		for _, e := range obs {
			o, ok := e.(*pxObj)
			if !ok {
				na = append(na, e)
				continue
			}
			typ := strings.ToLower(o.Str("type"))
			if typ != "selector" && typ != "urltest" {
				na = append(na, e)
				continue
			}
			mem := o.List("outbounds")
			var nm []any
			for _, x := range mem {
				if !removed[pxScalar(x)] {
					nm = append(nm, x)
				}
			}
			if len(nm) == 0 && len(mem) > 0 {
				removed[o.Str("tag")] = true
				again = true
				continue
			}
			if len(nm) != len(mem) {
				o.Set("outbounds", nm)
			}
			if d := o.Str("default"); d != "" && removed[d] {
				if len(nm) > 0 {
					o.Set("default", nm[0])
				} else {
					o.Del("default")
				}
			}
			na = append(na, e)
		}
		if na == nil {
			na = []any{}
		}
		root.Set("outbounds", na)
	}
	used := map[string]bool{}
	for _, l := range []string{"outbounds", "endpoints"} {
		for _, e := range root.List(l) {
			if o, ok := e.(*pxObj); ok {
				if d := o.Str("detour"); d != "" {
					used[d] = true
				}
			}
		}
	}
	stls := sbStlsUsed(doc, tags)
	var na []any
	for _, e := range root.List("outbounds") {
		if o, ok := e.(*pxObj); ok && stls[o.Str("tag")] && !used[o.Str("tag")] {
			removed[o.Str("tag")] = true
			continue
		}
		na = append(na, e)
	}
	if na == nil {
		na = []any{}
	}
	root.Set("outbounds", na)
	for _, l := range []string{"outbounds", "endpoints"} {
		for _, e := range root.List(l) {
			if o, ok := e.(*pxObj); ok && removed[o.Str("detour")] {
				o.Del("detour")
			}
		}
	}
	if r := root.Obj("route"); r != nil {
		if removed[r.Str("final")] {
			r.Del("final")
		}
		if rules := r.List("rules"); rules != nil {
			var nr []any
			for _, e := range rules {
				if o, ok := e.(*pxObj); ok && removed[o.Str("outbound")] {
					continue
				}
				nr = append(nr, e)
			}
			if nr == nil {
				nr = []any{}
			}
			r.Set("rules", nr)
		}
	}
	if d := root.Obj("dns"); d != nil {
		for _, e := range d.List("servers") {
			if o, ok := e.(*pxObj); ok && removed[o.Str("detour")] {
				o.Del("detour")
			}
		}
	}
	out := pxMarshalOrdered(root)
	nv, err := pxDecodeJSON(out)
	if err != nil {
		return f.Data, nil
	}
	nd, ok := nv.(map[string]any)
	if !ok || len(sbItems(nd)) != kept {
		return f.Data, nil
	}
	return out, nil
}

func init() {
	registerFormat(&fileFormat{Name: "sing-box", Detector: SingBoxConfigDetector{}, Parser: SingBoxConfigParser{}, Filter: SingBoxConfigFilter{}})
}
