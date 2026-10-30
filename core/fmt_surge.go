package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type sgLn struct {
	idx  int
	sec  string
	raw  string
	text string
}

var sgKeyRe = regexp.MustCompile(`^[A-Za-z0-9_\-]+\s*=`)

func sgContent(text string) ([]string, []sgLn) {
	lines := strings.Split(text, "\n")
	var out []sgLn
	sec, raw := "", ""
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "//") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			raw = strings.TrimSpace(t[1 : len(t)-1])
			sec = strings.ToLower(raw)
			continue
		}
		out = append(out, sgLn{idx: i, sec: sec, raw: raw, text: t})
	}
	return lines, out
}

func sgKV(fields []string) ([]string, map[string]string) {
	var pos []string
	kv := map[string]string{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, "\"") && !strings.HasPrefix(f, "'") && sgKeyRe.MatchString(f) {
			k, v, _ := strings.Cut(f, "=")
			kv[strings.ToLower(strings.TrimSpace(k))] = unquote(strings.TrimSpace(v))
			continue
		}
		pos = append(pos, unquote(f))
	}
	return pos, kv
}

func sgHostPort(m map[string]any, pos []string, at int) error {
	if len(pos) < at+2 {
		return errors.New("missing server or port")
	}
	host := strings.Trim(pos[at], "[]")
	p, err := strconv.Atoi(strings.TrimSpace(pos[at+1]))
	if host == "" || err != nil || p <= 0 || p > 65535 {
		return errors.New("bad server or port")
	}
	m["server"] = host
	m["port"] = p
	return nil
}

func sgSplitEndpoint(s string) (string, int) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return "", 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func sgHeaders(s string) map[string]any {
	h := map[string]any{}
	for _, part := range strings.Split(s, "|") {
		k, v, ok := strings.Cut(part, ":")
		if ok && strings.TrimSpace(k) != "" {
			h[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return h
}

func sgProxyLine(t string) (string, []string, bool) {
	name, rest, ok := strings.Cut(t, "=")
	if !ok {
		return "", nil, false
	}
	name = unquote(strings.TrimSpace(name))
	fields := pxSplitTop(rest, ',')
	if name == "" || len(fields) == 0 || fields[0] == "" {
		return "", nil, false
	}
	return name, fields, true
}

var sgBuiltinTypes = map[string]bool{"direct": true, "reject": true, "reject-tinygif": true, "reject-drop": true, "reject-no-drop": true, "reject-200": true}

var sgSurgeTypes = map[string]bool{"ss": true, "socks5-tls": true, "tuic-v5": true, "snell": true, "external": true, "ssh": true, "trust-tunnel": true}

var sgLoonTypes = map[string]bool{"shadowsocks": true, "shadowsocksr": true, "vless": true}

var sgSharedTypes = map[string]bool{"vmess": true, "trojan": true, "http": true, "https": true, "socks5": true, "hysteria2": true, "tuic": true, "wireguard": true, "anytls": true}

var sgLoonKeys = []string{"over-tls", "tls-name", "transport", "obfs-name", "interface-ip", "salamander-password", "peers", "alterid"}

var sgSurgeKeys = []string{"encrypt-method", "username", "ws", "ws-path", "section-name", "psk", "vmess-aead", "tls", "download-bandwidth"}

func sgDialect(text string) (surge, loon, proxies int) {
	_, lns := sgContent(text)
	for _, l := range lns {
		if l.sec != "proxy" {
			continue
		}
		_, fields, ok := sgProxyLine(l.text)
		if !ok {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(fields[0]))
		switch {
		case sgBuiltinTypes[typ]:
			continue
		case sgSurgeTypes[typ]:
			surge += 2
			proxies++
			continue
		case sgLoonTypes[typ]:
			loon += 2
			proxies++
			continue
		case !sgSharedTypes[typ]:
			continue
		}
		proxies++
		if typ == "vmess" && len(fields) > 3 && !sgKeyRe.MatchString(fields[3]) {
			loon++
		}
		if (typ == "trojan" || typ == "hysteria2" || typ == "anytls") && len(fields) > 3 && strings.HasPrefix(fields[3], "\"") {
			loon++
		}
		_, kv := sgKV(fields[1:])
		for _, k := range sgLoonKeys {
			if _, ok := kv[k]; ok {
				loon++
			}
		}
		for _, k := range sgSurgeKeys {
			if _, ok := kv[k]; ok {
				surge++
			}
		}
	}
	return
}

type sgItem struct {
	line   int
	name   string
	fields []string
	sec    string
}

type sgProxyFunc func(name string, fields []string, ctx *sgCtx) (map[string]any, []string, error)

type sgCtx struct {
	wg     map[string]map[string]string
	byName map[string]*sgItem
}

func sgCollect(text string, proxySec string) ([]sgItem, *sgCtx) {
	_, lns := sgContent(text)
	ctx := &sgCtx{wg: map[string]map[string]string{}, byName: map[string]*sgItem{}}
	var items []sgItem
	for _, l := range lns {
		if strings.HasPrefix(l.sec, "wireguard ") {
			name := strings.ToLower(strings.TrimSpace(l.sec[len("wireguard "):]))
			if ctx.wg[name] == nil {
				ctx.wg[name] = map[string]string{}
			}
			k, v, ok := strings.Cut(l.text, "=")
			if ok {
				ctx.wg[name][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
			continue
		}
		if l.sec != proxySec {
			continue
		}
		name, fields, ok := sgProxyLine(l.text)
		if !ok || sgBuiltinTypes[strings.ToLower(strings.TrimSpace(fields[0]))] {
			continue
		}
		items = append(items, sgItem{line: l.idx, name: name, fields: fields, sec: l.sec})
	}
	for i := range items {
		if _, dup := ctx.byName[items[i].name]; !dup {
			ctx.byName[items[i].name] = &items[i]
		}
	}
	return items, ctx
}

func sgParseWith(f *vfile, format string, items []sgItem, ctx *sgCtx, conv sgProxyFunc, chainKey string) []*Config {
	out := make([]*Config, 0, len(items))
	for _, it := range items {
		m, notes, err := conv(it.name, it.fields, ctx)
		var chain []map[string]any
		if m != nil {
			notes = append(notes, pxSanitize(m)...)
			chain = []map[string]any{m}
			seen := map[string]bool{it.name: true}
			cur := it.fields
			for depth := 0; err == nil && chainKey != "" && depth < 8; depth++ {
				_, kv := sgKV(cur[1:])
				up := kv[chainKey]
				if up == "" || strings.EqualFold(up, "DIRECT") {
					break
				}
				parent, ok := ctx.byName[up]
				if !ok {
					err = fmt.Errorf("%s %q not found", chainKey, up)
					break
				}
				if seen[up] {
					err = fmt.Errorf("%s loop at %q", chainKey, up)
					break
				}
				seen[up] = true
				pm, pn, perr := conv(parent.name, parent.fields, ctx)
				if perr != nil {
					err = fmt.Errorf("%s %q: %w", chainKey, up, perr)
					break
				}
				notes = append(notes, pn...)
				notes = append(notes, pxSanitize(pm)...)
				chain = append([]map[string]any{pm}, chain...)
				cur = parent.fields
			}
		}
		c := pxMihomoConfig(f, format, chain, it.name, err)
		if c.Protocol == "" {
			c.Protocol = strings.ToLower(strings.TrimSpace(it.fields[0]))
		}
		if m == nil {
			c.Name = it.name
		}
		pxWarnAll(c, notes)
		c.RawConfig = []byte(it.name + " = " + strings.Join(it.fields, ", "))
		out = append(out, c)
	}
	return out
}

func sgTLS(m map[string]any, kv map[string]string, sniKey string) {
	if v := firstNonEmpty(kv["sni"], kv["tls-name"]); v != "" && !strings.EqualFold(v, "off") {
		m[sniKey] = v
	}
	if truthy(kv["skip-cert-verify"]) {
		m["skip-cert-verify"] = true
	}
	if v := firstNonEmpty(kv["server-cert-fingerprint-sha256"], kv["tls-cert-sha256"]); v != "" {
		m["fingerprint"] = strings.ToLower(strings.ReplaceAll(v, ":", ""))
	}
	if v := kv["alpn"]; v != "" {
		m["alpn"] = splitList(v)
	}
}

func sgCommon(m map[string]any, kv map[string]string) []string {
	var notes []string
	if truthy(kv["tfo"]) || truthy(kv["fast-open"]) {
		m["tfo"] = true
	}
	if v := kv["interface"]; v != "" {
		notes = append(notes, "interface binding ignored during test")
	}
	return notes
}

func sgShadowTLS(m map[string]any, kv map[string]string, defVer int) error {
	p := kv["shadow-tls-password"]
	if p == "" {
		return nil
	}
	if pxHas(m, "plugin") {
		return errors.New("obfs combined with shadow-tls is not supported")
	}
	ver, _ := strconv.Atoi(kv["shadow-tls-version"])
	if ver == 0 {
		ver = defVer
	}
	m["plugin"] = "shadow-tls"
	m["client-fingerprint"] = "chrome"
	m["plugin-opts"] = map[string]any{"host": kv["shadow-tls-sni"], "password": p, "version": ver}
	return nil
}

func sgWireGuard(m map[string]any, sec map[string]string) error {
	m["type"] = "wireguard"
	m["private-key"] = sec["private-key"]
	m["udp"] = true
	if v := sec["self-ip"]; v != "" {
		m["ip"] = strings.SplitN(v, "/", 2)[0]
	}
	if v := sec["self-ip-v6"]; v != "" {
		m["ipv6"] = strings.SplitN(v, "/", 2)[0]
	}
	if v, _ := strconv.Atoi(sec["mtu"]); v > 0 {
		m["mtu"] = v
	}
	peer := strings.TrimSpace(sec["peer"])
	peer = strings.TrimSuffix(strings.TrimPrefix(peer, "("), ")")
	_, pkv := sgKV(pxSplitTop(peer, ','))
	host, port := sgSplitEndpoint(pkv["endpoint"])
	if host == "" || port == 0 {
		return errors.New("wireguard peer has no endpoint")
	}
	m["server"] = host
	m["port"] = port
	m["public-key"] = pkv["public-key"]
	if v := pkv["preshared-key"]; v != "" {
		m["pre-shared-key"] = v
	}
	if v := pkv["allowed-ips"]; v != "" {
		m["allowed-ips"] = splitList(v)
	}
	if r := pxReserved(pkv["client-id"]); len(r) == 3 {
		m["reserved"] = r
	}
	if v, _ := strconv.Atoi(pkv["keepalive"]); v > 0 {
		m["persistent-keepalive"] = v
	}
	return nil
}

func sgProxy(name string, fields []string, ctx *sgCtx) (map[string]any, []string, error) {
	typ := strings.ToLower(strings.TrimSpace(fields[0]))
	pos, kv := sgKV(fields[1:])
	m := map[string]any{"name": name}
	notes := sgCommon(m, kv)
	var err error
	switch typ {
	case "ss", "shadowsocks":
		err = sgHostPort(m, pos, 0)
		m["type"] = "ss"
		m["cipher"] = strings.ToLower(kv["encrypt-method"])
		m["password"] = kv["password"]
		m["udp"] = truthy(kv["udp-relay"])
		if o := strings.ToLower(kv["obfs"]); o == "http" || o == "tls" {
			m["plugin"] = "obfs"
			m["plugin-opts"] = map[string]any{"mode": o, "host": firstNonEmpty(kv["obfs-host"], "bing.com")}
		}
		if err == nil {
			err = sgShadowTLS(m, kv, 2)
		}
	case "vmess":
		err = sgHostPort(m, pos, 0)
		m["type"] = "vmess"
		m["uuid"] = kv["username"]
		m["alterId"] = 0
		m["cipher"] = firstNonEmpty(kv["encrypt-method"], "auto")
		m["udp"] = truthy(kv["udp-relay"])
		if !truthy(kv["vmess-aead"]) {
			notes = append(notes, "vmess-aead is off (legacy header in Surge); tested with AEAD")
		}
		if truthy(kv["tls"]) {
			m["tls"] = true
			sgTLS(m, kv, "servername")
		}
		sgWS(m, kv)
	case "trojan":
		err = sgHostPort(m, pos, 0)
		m["type"] = "trojan"
		m["password"] = kv["password"]
		m["udp"] = truthy(kv["udp-relay"])
		sgTLS(m, kv, "sni")
		sgWS(m, kv)
	case "http", "https":
		err = sgHostPort(m, pos, 0)
		m["type"] = "http"
		user, pass := kv["username"], kv["password"]
		if user == "" && len(pos) > 2 {
			user = pos[2]
		}
		if pass == "" && len(pos) > 3 {
			pass = pos[3]
		}
		if user != "" {
			m["username"] = user
			m["password"] = pass
		}
		if typ == "https" {
			m["tls"] = true
			sgTLS(m, kv, "sni")
		}
	case "socks5", "socks5-tls":
		err = sgHostPort(m, pos, 0)
		m["type"] = "socks5"
		user, pass := kv["username"], kv["password"]
		if user == "" && len(pos) > 2 {
			user = pos[2]
		}
		if pass == "" && len(pos) > 3 {
			pass = pos[3]
		}
		if user != "" {
			m["username"] = user
			m["password"] = pass
		}
		m["udp"] = truthy(kv["udp-relay"])
		if typ == "socks5-tls" {
			m["tls"] = true
			if truthy(kv["skip-cert-verify"]) {
				m["skip-cert-verify"] = true
			}
		}
	case "snell":
		err = sgHostPort(m, pos, 0)
		m["type"] = "snell"
		m["psk"] = kv["psk"]
		m["version"] = firstNonEmpty(kv["version"], "1")
		m["udp"] = true
		if o := strings.ToLower(kv["obfs"]); o == "http" || o == "tls" {
			m["obfs-opts"] = map[string]any{"mode": o, "host": firstNonEmpty(kv["obfs-host"], "bing.com")}
		}
		if v, _ := strconv.Atoi(m["version"].(string)); v > 3 {
			err = fmt.Errorf("snell v%d not supported", v)
		}
	case "tuic", "tuic-v5":
		err = sgHostPort(m, pos, 0)
		m["type"] = "tuic"
		if typ == "tuic" && kv["token"] != "" {
			m["token"] = kv["token"]
		} else {
			m["uuid"] = kv["uuid"]
			m["password"] = kv["password"]
		}
		sgTLS(m, kv, "sni")
		if !pxHas(m, "alpn") {
			m["alpn"] = []string{"h3"}
		}
		m["udp"] = true
	case "hysteria2":
		err = sgHostPort(m, pos, 0)
		m["type"] = "hysteria2"
		m["password"] = kv["password"]
		if v := kv["download-bandwidth"]; v != "" {
			m["down"] = v
		}
		if v := firstNonEmpty(kv["port-hopping"], kv["ports"]); v != "" {
			m["ports"] = pxPorts(v)
		}
		if v := kv["port-hopping-interval"]; v != "" {
			m["hop-interval"] = strconv.Itoa(pxDuration(v))
		}
		if v := firstNonEmpty(kv["salamander-password"], kv["obfs-password"]); v != "" {
			m["obfs"] = "salamander"
			m["obfs-password"] = v
		}
		sgTLS(m, kv, "sni")
		m["udp"] = true
	case "anytls":
		err = sgHostPort(m, pos, 0)
		m["type"] = "anytls"
		m["password"] = kv["password"]
		sgTLS(m, kv, "sni")
		m["udp"] = true
	case "ssh":
		err = sgHostPort(m, pos, 0)
		m["type"] = "ssh"
		m["username"] = firstNonEmpty(kv["username"], "root")
		if kv["password"] != "" {
			m["password"] = kv["password"]
		}
		if kv["private-key"] != "" && kv["password"] == "" {
			err = errors.New("ssh private-key from Surge keystore not supported")
		}
	case "wireguard":
		sec := ctx.wg[strings.ToLower(kv["section-name"])]
		if sec == nil {
			return nil, notes, fmt.Errorf("[WireGuard %s] section not found", kv["section-name"])
		}
		err = sgWireGuard(m, sec)
	case "external":
		return nil, notes, errors.New("external proxy runs a local program; not supported")
	default:
		return nil, notes, fmt.Errorf("Surge proxy type %q not supported", typ)
	}
	if err != nil {
		return m, notes, err
	}
	return m, notes, nil
}

func sgWS(m map[string]any, kv map[string]string) {
	if !truthy(kv["ws"]) {
		return
	}
	ws := map[string]any{"path": firstNonEmpty(kv["ws-path"], "/")}
	if h := sgHeaders(kv["ws-headers"]); len(h) > 0 {
		ws["headers"] = h
	}
	m["network"] = "ws"
	m["ws-opts"] = ws
}

type SurgeDetector struct{}

func (SurgeDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	t := f.Text()
	if !strings.Contains(strings.ToLower(t), "[proxy]") {
		return 0
	}
	surge, loon, n := sgDialect(t)
	if n == 0 || loon > surge {
		return 0
	}
	return 70
}

type SurgeParser struct{}

func (SurgeParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	items, ctx := sgCollect(f.Text(), "proxy")
	if len(items) == 0 {
		return nil, errors.New("no proxies in [Proxy]")
	}
	return sgParseWith(f, "Surge", items, ctx, sgProxy, "underlying-proxy"), nil
}

type SurgeFilter struct{}

func (SurgeFilter) Filter(f *vfile, idx []int) ([]byte, error) {
	items, _ := sgCollect(f.Text(), "proxy")
	return sgFilter(f, items, idx, "underlying-proxy", sgIniDialect{groupSec: "proxy group", ruleSecs: []string{"rule"}, fallback: "DIRECT"}), nil
}

type sgIniDialect struct {
	groupSec string
	ruleSecs []string
	fallback string
	qx       bool
}

var sgGroupSources = []string{"policy-path", "include-all-proxies", "include-other-group", "policy-regex-filter", "server-tag-regex", "resource-tag-regex", "img-url-only"}

func sgFilter(f *vfile, items []sgItem, idx []int, chainKey string, d sgIniDialect) []byte {
	if len(items) == 0 {
		return f.Data
	}
	keep := make([]bool, len(items))
	for _, i := range idx {
		if i >= 0 && i < len(items) {
			keep[i] = true
		}
	}
	byName := map[string]int{}
	for i, it := range items {
		if _, dup := byName[it.name]; !dup {
			byName[it.name] = i
		}
	}
	for changed := chainKey != ""; changed; {
		changed = false
		for i, it := range items {
			if !keep[i] {
				continue
			}
			_, kv := sgKV(it.fields[1:])
			if j, ok := byName[kv[chainKey]]; ok && !keep[j] {
				keep[j] = true
				changed = true
			}
		}
	}
	removed := map[string]bool{}
	drop := map[int]bool{}
	kept := 0
	for i, it := range items {
		if keep[i] {
			kept++
			continue
		}
		removed[it.name] = true
		drop[it.line] = true
	}
	if kept == len(items) {
		return f.Data
	}
	for i, it := range items {
		if keep[i] {
			delete(removed, it.name)
		}
	}
	lines, lns := sgContent(f.Text())
	for again := true; again; {
		again = false
		for _, l := range lns {
			if l.sec != d.groupSec || drop[l.idx] {
				continue
			}
			nl, gname, empty, changed := sgPruneGroup(lines[l.idx], removed, d.qx)
			if !changed {
				continue
			}
			if empty {
				drop[l.idx] = true
				removed[gname] = true
				again = true
				continue
			}
			lines[l.idx] = nl
		}
	}
	fallback := d.fallback
	for _, l := range lns {
		if l.sec == d.groupSec && !drop[l.idx] {
			if g := sgGroupName(lines[l.idx], d.qx); g != "" {
				fallback = g
				break
			}
		}
	}
	for _, l := range lns {
		in := false
		for _, s := range d.ruleSecs {
			if l.sec == s {
				in = true
			}
		}
		if !in || drop[l.idx] {
			continue
		}
		fields := pxSplitTop(strings.TrimSpace(lines[l.idx]), ',')
		ti := clRuleTarget(fields)
		if ti < 0 || !removed[unquote(fields[ti])] {
			continue
		}
		if ti == 1 {
			fields[1] = fallback
			sep := ","
			if strings.Contains(lines[l.idx], ", ") {
				sep = ", "
			}
			lines[l.idx] = strings.Join(fields, sep)
			continue
		}
		drop[l.idx] = true
	}
	var out []string
	for i, l := range lines {
		if !drop[i] {
			out = append(out, l)
		}
	}
	return []byte(strings.Join(out, "\n"))
}

func sgGroupName(line string, qx bool) string {
	t := strings.TrimSpace(line)
	if qx {
		fields := pxSplitTop(t, ',')
		_, name, _ := strings.Cut(fields[0], "=")
		return strings.TrimSpace(name)
	}
	name, _, _ := strings.Cut(t, "=")
	return unquote(strings.TrimSpace(name))
}

func sgPruneGroup(line string, removed map[string]bool, qx bool) (string, string, bool, bool) {
	t := strings.TrimSpace(line)
	var name, head string
	var fields []string
	if qx {
		all := pxSplitTop(t, ',')
		typ, n, ok := strings.Cut(all[0], "=")
		if !ok {
			return line, "", false, false
		}
		name = strings.TrimSpace(n)
		head = strings.TrimSpace(typ) + "=" + name
		fields = all[1:]
	} else {
		n, rest, ok := strings.Cut(t, "=")
		if !ok {
			return line, "", false, false
		}
		name = unquote(strings.TrimSpace(n))
		all := pxSplitTop(rest, ',')
		if len(all) == 0 {
			return line, "", false, false
		}
		gt := strings.ToLower(strings.TrimSpace(all[0]))
		if gt == "ssid" || gt == "subnet" {
			return line, "", false, false
		}
		head = strings.TrimSpace(n) + " = " + strings.TrimSpace(all[0])
		fields = all[1:]
	}
	var keptF []string
	members, left := 0, 0
	sources := false
	changed := false
	for _, fl := range fields {
		if sgKeyRe.MatchString(fl) && !strings.HasPrefix(fl, "\"") {
			k, v, _ := strings.Cut(fl, "=")
			k = strings.ToLower(strings.TrimSpace(k))
			for _, s := range sgGroupSources {
				if k == s && strings.TrimSpace(v) != "" && !strings.EqualFold(strings.TrimSpace(v), "false") {
					sources = true
				}
			}
			keptF = append(keptF, fl)
			continue
		}
		members++
		if removed[unquote(fl)] {
			changed = true
			continue
		}
		left++
		keptF = append(keptF, fl)
	}
	if !changed {
		return line, name, false, false
	}
	empty := members > 0 && left == 0 && !sources
	out := head
	if len(keptF) > 0 {
		out += ", " + strings.Join(keptF, ", ")
	}
	return out, name, empty, true
}

func init() {
	registerFormat(&fileFormat{Name: "Surge", Detector: SurgeDetector{}, Parser: SurgeParser{}, Filter: SurgeFilter{}})
}
