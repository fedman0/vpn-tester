package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func lnTransport(m map[string]any, kv map[string]string) error {
	switch strings.ToLower(firstNonEmpty(kv["transport"], "tcp")) {
	case "tcp":
		m["network"] = "tcp"
	case "ws", "websocket":
		ws := map[string]any{"path": firstNonEmpty(kv["path"], "/")}
		if h := kv["host"]; h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		m["network"] = "ws"
		m["ws-opts"] = ws
	case "http":
		ho := map[string]any{"path": []string{firstNonEmpty(kv["path"], "/")}}
		if h := kv["host"]; h != "" {
			ho["headers"] = map[string]any{"Host": []string{h}}
		}
		m["network"] = "http"
		m["http-opts"] = ho
	case "grpc":
		m["network"] = "grpc"
		m["grpc-opts"] = map[string]any{"grpc-service-name": firstNonEmpty(kv["service-name"], kv["servicename"], kv["path"])}
	default:
		return fmt.Errorf("Loon transport %q not supported", kv["transport"])
	}
	return nil
}

func lnPeers(s string) []map[string]string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	var out []map[string]string
	for _, p := range pxSplitTop(s, ',') {
		p = strings.TrimSpace(p)
		p = strings.TrimSuffix(strings.TrimPrefix(p, "{"), "}")
		if p == "" {
			continue
		}
		_, kv := sgKV(pxSplitTop(p, ','))
		out = append(out, kv)
	}
	return out
}

func lnProxy(name string, fields []string, ctx *sgCtx) (map[string]any, []string, error) {
	typ := strings.ToLower(strings.TrimSpace(fields[0]))
	pos, kv := sgKV(fields[1:])
	m := map[string]any{"name": name}
	notes := sgCommon(m, kv)
	at := func(i int) string {
		if i < len(pos) {
			return pos[i]
		}
		return ""
	}
	var err error
	if typ != "wireguard" {
		err = sgHostPort(m, pos, 0)
	}
	switch typ {
	case "shadowsocks", "ss":
		m["type"] = "ss"
		m["cipher"] = strings.ToLower(at(2))
		m["password"] = at(3)
		m["udp"] = truthy(kv["udp"])
		if o := strings.ToLower(firstNonEmpty(kv["obfs-name"], kv["obfs"])); o == "http" || o == "tls" {
			m["plugin"] = "obfs"
			m["plugin-opts"] = map[string]any{"mode": o, "host": firstNonEmpty(kv["obfs-host"], "bing.com")}
		}
		if err == nil {
			err = sgShadowTLS(m, kv, 3)
		}
	case "shadowsocksr", "ssr":
		m["type"] = "ssr"
		m["cipher"] = strings.ToLower(at(2))
		m["password"] = at(3)
		m["protocol"] = firstNonEmpty(kv["protocol"], "origin")
		m["protocol-param"] = kv["protocol-param"]
		m["obfs"] = firstNonEmpty(kv["obfs"], "plain")
		m["obfs-param"] = kv["obfs-param"]
		m["udp"] = truthy(kv["udp"])
	case "vmess":
		m["type"] = "vmess"
		m["cipher"] = firstNonEmpty(at(2), "auto")
		m["uuid"] = at(3)
		m["alterId"], _ = strconv.Atoi(firstNonEmpty(kv["alterid"], "0"))
		m["udp"] = true
		if err == nil {
			err = lnTransport(m, kv)
		}
		if truthy(kv["over-tls"]) {
			m["tls"] = true
			sgTLS(m, kv, "servername")
		}
	case "vless":
		m["type"] = "vless"
		m["uuid"] = at(2)
		if v := kv["flow"]; v != "" {
			m["flow"] = v
		}
		m["udp"] = true
		if err == nil {
			err = lnTransport(m, kv)
		}
		if truthy(kv["over-tls"]) || kv["public-key"] != "" {
			m["tls"] = true
			sgTLS(m, kv, "servername")
		}
		if pk := kv["public-key"]; pk != "" {
			m["reality-opts"] = map[string]any{"public-key": pk, "short-id": kv["short-id"]}
			m["client-fingerprint"] = "chrome"
		}
	case "trojan":
		m["type"] = "trojan"
		m["password"] = at(2)
		m["udp"] = truthy(kv["udp"])
		sgTLS(m, kv, "sni")
		if err == nil && kv["transport"] != "" && !strings.EqualFold(kv["transport"], "tcp") {
			err = lnTransport(m, kv)
		}
	case "http", "https":
		m["type"] = "http"
		if u := at(2); u != "" {
			m["username"] = u
			m["password"] = at(3)
		}
		if typ == "https" || truthy(kv["over-tls"]) {
			m["tls"] = true
			sgTLS(m, kv, "sni")
		}
	case "socks5":
		m["type"] = "socks5"
		if u := at(2); u != "" {
			m["username"] = u
			m["password"] = at(3)
		}
		m["udp"] = truthy(kv["udp"])
		if truthy(kv["over-tls"]) {
			m["tls"] = true
			if truthy(kv["skip-cert-verify"]) {
				m["skip-cert-verify"] = true
			}
		}
	case "hysteria2":
		m["type"] = "hysteria2"
		m["password"] = at(2)
		if v := kv["download-bandwidth"]; v != "" {
			m["down"] = v
		}
		if v := kv["salamander-password"]; v != "" {
			m["obfs"] = "salamander"
			m["obfs-password"] = v
		}
		if v := firstNonEmpty(kv["port-hopping"], kv["ports"]); v != "" {
			m["ports"] = pxPorts(v)
		}
		sgTLS(m, kv, "sni")
		m["udp"] = true
	case "tuic":
		m["type"] = "tuic"
		m["uuid"] = firstNonEmpty(kv["uuid"], at(3))
		m["password"] = at(2)
		sgTLS(m, kv, "sni")
		if !pxHas(m, "alpn") {
			m["alpn"] = []string{"h3"}
		}
		m["udp"] = true
	case "anytls":
		m["type"] = "anytls"
		m["password"] = at(2)
		sgTLS(m, kv, "sni")
		m["udp"] = true
	case "wireguard":
		m["type"] = "wireguard"
		m["private-key"] = kv["private-key"]
		m["udp"] = true
		if v := kv["interface-ip"]; v != "" {
			m["ip"] = strings.SplitN(v, "/", 2)[0]
		}
		if v := kv["interface-ipv6"]; v != "" {
			m["ipv6"] = strings.SplitN(v, "/", 2)[0]
		}
		if v, _ := strconv.Atoi(kv["mtu"]); v > 0 {
			m["mtu"] = v
		}
		peers := lnPeers(kv["peers"])
		if len(peers) == 0 {
			return m, notes, errors.New("wireguard has no peers")
		}
		if len(peers) > 1 {
			notes = append(notes, "only the first WireGuard peer is tested")
		}
		p := peers[0]
		host, port := sgSplitEndpoint(p["endpoint"])
		if host == "" || port == 0 {
			return m, notes, errors.New("wireguard peer has no endpoint")
		}
		m["server"] = host
		m["port"] = port
		m["public-key"] = p["public-key"]
		if v := p["preshared-key"]; v != "" {
			m["pre-shared-key"] = v
		}
		if v := p["allowed-ips"]; v != "" {
			m["allowed-ips"] = splitList(v)
		}
		if r := pxReserved(p["reserved"]); len(r) == 3 {
			m["reserved"] = r
		}
	default:
		return nil, notes, fmt.Errorf("Loon proxy type %q not supported", typ)
	}
	return m, notes, err
}

type LoonDetector struct{}

func (LoonDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	t := f.Text()
	if !strings.Contains(strings.ToLower(t), "[proxy]") {
		return 0
	}
	surge, loon, n := sgDialect(t)
	if n == 0 || loon <= surge {
		return 0
	}
	return 70
}

type LoonParser struct{}

func (LoonParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	items, ctx := sgCollect(f.Text(), "proxy")
	if len(items) == 0 {
		return nil, errors.New("no proxies in [Proxy]")
	}
	return sgParseWith(f, "Loon", items, ctx, lnProxy, ""), nil
}

type LoonFilter struct{}

func (LoonFilter) Filter(f *vfile, idx []int) ([]byte, error) {
	items, _ := sgCollect(f.Text(), "proxy")
	return sgFilter(f, items, idx, "", sgIniDialect{groupSec: "proxy group", ruleSecs: []string{"rule"}, fallback: "DIRECT"}), nil
}

func init() {
	registerFormat(&fileFormat{Name: "Loon", Detector: LoonDetector{}, Parser: LoonParser{}, Filter: LoonFilter{}})
}
