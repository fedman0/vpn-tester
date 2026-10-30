package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var qxLineRe = regexp.MustCompile(`(?i)^(shadowsocks|vmess|vless|trojan|http|socks5|hysteria2)\s*=\s*\S`)

func qxCollect(text string) []sgItem {
	_, lns := sgContent(text)
	var items []sgItem
	for _, l := range lns {
		if l.sec != "server_local" || !qxLineRe.MatchString(l.text) {
			continue
		}
		fields := pxSplitTop(l.text, ',')
		_, kv := sgKV(fields[1:])
		name := kv["tag"]
		if name == "" {
			_, hp, _ := strings.Cut(fields[0], "=")
			name = strings.TrimSpace(hp)
		}
		items = append(items, sgItem{line: l.idx, name: name, fields: fields, sec: l.sec})
	}
	return items
}

func qxHostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			return "", 0, errors.New("missing port")
		}
		h, p = s[:i], s[i+1:]
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 || h == "" {
		return "", 0, errors.New("bad server or port")
	}
	return h, n, nil
}

func qxObfs(m map[string]any, kv map[string]string, typ string) error {
	obfs := strings.ToLower(kv["obfs"])
	host := kv["obfs-host"]
	path := firstNonEmpty(kv["obfs-uri"], "/")
	tlsOn := false
	switch obfs {
	case "", "none":
		m["network"] = "tcp"
		tlsOn = typ == "trojan" && kv["over-tls"] != "false" || truthy(kv["over-tls"])
	case "over-tls":
		m["network"] = "tcp"
		tlsOn = true
	case "ws", "wss":
		ws := map[string]any{"path": path}
		if host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		m["network"] = "ws"
		m["ws-opts"] = ws
		tlsOn = obfs == "wss" || truthy(kv["over-tls"])
	case "http":
		if typ == "trojan" {
			return errors.New("trojan with http obfs not supported")
		}
		ho := map[string]any{"path": []string{path}}
		if host != "" {
			ho["headers"] = map[string]any{"Host": []string{host}}
		}
		m["network"] = "http"
		m["http-opts"] = ho
	default:
		return fmt.Errorf("QuantumultX obfs %q not supported", obfs)
	}
	if typ == "trojan" && !tlsOn {
		return errors.New("trojan without TLS not supported")
	}
	if tlsOn {
		sniKey := "sni"
		if typ != "trojan" {
			m["tls"] = true
			sniKey = "servername"
		}
		if sni := firstNonEmpty(kv["tls-host"], host); sni != "" {
			m[sniKey] = sni
		}
		if kv["tls-verification"] == "false" {
			m["skip-cert-verify"] = true
		}
		if v := kv["tls-cert-sha256"]; v != "" {
			m["fingerprint"] = strings.ToLower(strings.ReplaceAll(v, ":", ""))
		}
		if v := kv["tls-alpn"]; v != "" {
			m["alpn"] = splitList(v)
		}
	}
	return nil
}

func qxCipher(s string) string {
	switch strings.ToLower(s) {
	case "chacha20-ietf-poly1305":
		return "chacha20-poly1305"
	case "":
		return "auto"
	}
	return strings.ToLower(s)
}

func qxProxy(name string, fields []string, ctx *sgCtx) (map[string]any, []string, error) {
	typ, hp, _ := strings.Cut(fields[0], "=")
	typ = strings.ToLower(strings.TrimSpace(typ))
	_, kv := sgKV(fields[1:])
	m := map[string]any{"name": name}
	var notes []string
	if truthy(kv["fast-open"]) {
		m["tfo"] = true
	}
	host, port, err := qxHostPort(hp)
	if err != nil {
		return m, notes, err
	}
	m["server"] = host
	m["port"] = port
	switch typ {
	case "shadowsocks":
		if p := kv["ssr-protocol"]; p != "" {
			m["type"] = "ssr"
			m["cipher"] = strings.ToLower(kv["method"])
			m["password"] = kv["password"]
			m["protocol"] = p
			m["protocol-param"] = kv["ssr-protocol-param"]
			m["obfs"] = firstNonEmpty(kv["obfs"], "plain")
			m["obfs-param"] = kv["obfs-host"]
			break
		}
		m["type"] = "ss"
		m["cipher"] = strings.ToLower(kv["method"])
		m["password"] = kv["password"]
		m["udp"] = truthy(kv["udp-relay"])
		switch o := strings.ToLower(kv["obfs"]); o {
		case "", "none":
		case "http", "tls":
			m["plugin"] = "obfs"
			m["plugin-opts"] = map[string]any{"mode": o, "host": firstNonEmpty(kv["obfs-host"], "bing.com")}
		case "ws", "wss":
			po := map[string]any{"mode": "websocket", "host": kv["obfs-host"], "path": firstNonEmpty(kv["obfs-uri"], "/")}
			if o == "wss" {
				po["tls"] = true
				if kv["tls-verification"] == "false" {
					po["skip-cert-verify"] = true
				}
			}
			m["plugin"] = "v2ray-plugin"
			m["plugin-opts"] = po
		default:
			return m, notes, fmt.Errorf("shadowsocks obfs %q not supported", o)
		}
	case "vmess":
		m["type"] = "vmess"
		m["uuid"] = kv["password"]
		m["cipher"] = qxCipher(kv["method"])
		m["alterId"] = 0
		m["udp"] = truthy(kv["udp-relay"])
		if kv["aead"] == "false" {
			notes = append(notes, "aead=false (legacy header in QuantumultX); tested with AEAD")
		}
		err = qxObfs(m, kv, typ)
	case "vless":
		m["type"] = "vless"
		m["uuid"] = kv["password"]
		m["udp"] = truthy(kv["udp-relay"])
		if v := kv["vless-flow"]; v != "" {
			m["flow"] = v
		}
		err = qxObfs(m, kv, typ)
		if pk := kv["reality-base64-pubkey"]; pk != "" {
			m["tls"] = true
			m["reality-opts"] = map[string]any{"public-key": pk, "short-id": kv["reality-hex-shortid"]}
			m["client-fingerprint"] = "chrome"
			if !pxHas(m, "servername") {
				if sni := kv["tls-host"]; sni != "" {
					m["servername"] = sni
				}
			}
		}
	case "trojan":
		m["type"] = "trojan"
		m["password"] = kv["password"]
		m["udp"] = truthy(kv["udp-relay"])
		err = qxObfs(m, kv, typ)
	case "http":
		m["type"] = "http"
		if u := kv["username"]; u != "" {
			m["username"] = u
			m["password"] = kv["password"]
		}
		if truthy(kv["over-tls"]) {
			m["tls"] = true
			if sni := kv["tls-host"]; sni != "" {
				m["sni"] = sni
			}
			if kv["tls-verification"] == "false" {
				m["skip-cert-verify"] = true
			}
		}
	case "socks5":
		m["type"] = "socks5"
		if u := kv["username"]; u != "" {
			m["username"] = u
			m["password"] = kv["password"]
		}
		m["udp"] = truthy(kv["udp-relay"])
		if truthy(kv["over-tls"]) {
			m["tls"] = true
			if kv["tls-verification"] == "false" {
				m["skip-cert-verify"] = true
			}
		}
	case "hysteria2":
		m["type"] = "hysteria2"
		m["password"] = kv["password"]
		if sni := kv["tls-host"]; sni != "" {
			m["sni"] = sni
		}
		if kv["tls-verification"] == "false" {
			m["skip-cert-verify"] = true
		}
		m["udp"] = true
	default:
		return nil, notes, fmt.Errorf("QuantumultX type %q not supported", typ)
	}
	return m, notes, err
}

type QuantumultXDetector struct{}

func (QuantumultXDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	if !strings.Contains(strings.ToLower(f.Text()), "[server_local]") {
		return 0
	}
	if len(qxCollect(f.Text())) == 0 {
		return 0
	}
	return 70
}

type QuantumultXParser struct{}

func (QuantumultXParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	items := qxCollect(f.Text())
	if len(items) == 0 {
		return nil, errors.New("no servers in [server_local]")
	}
	return sgParseWith(f, "QuantumultX", items, &sgCtx{}, qxProxy, ""), nil
}

type QuantumultXFilter struct{}

func (QuantumultXFilter) Filter(f *vfile, idx []int) ([]byte, error) {
	return sgFilter(f, qxCollect(f.Text()), idx, "", sgIniDialect{groupSec: "policy", ruleSecs: []string{"filter_local"}, fallback: "direct", qx: true}), nil
}

func init() {
	registerFormat(&fileFormat{Name: "QuantumultX", Detector: QuantumultXDetector{}, Parser: QuantumultXParser{}, Filter: QuantumultXFilter{}})
}
