package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/convert"
)

type v2 struct {
	Proto      string
	Name       string
	Server     string
	Port       int
	ID         string
	AlterID    int
	Cipher     string
	Flow       string
	Encryption string
	Net        string
	HeaderType string
	Host       string
	Path       string
	Service    string
	Authority  string
	GrpcMode   string
	XMode      string
	XExtra     string
	Seed       string
	Security   string
	SNI        string
	FP         string
	ALPN       []string
	Insecure   bool
	PBK        string
	SID        string
	SPX        string
	PQV        string
	ECH        string
	PCS        string
	VCN        string
	FM         string
	PacketEnc  string
	SSMethod   string
	SSPassword string
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func normNet(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	switch n {
	case "", "raw", "tcp", "original":
		return "tcp"
	case "websocket":
		return "ws"
	case "splithttp":
		return "xhttp"
	case "mkcp":
		return "kcp"
	case "http", "h2":
		return "h2"
	case "gun":
		return "grpc"
	}
	return n
}

func userInfo(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	name := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		return name + ":" + pw
	}
	return name
}

func v2FromURL(proto string, u *url.URL) (*v2, error) {
	q := u.Query()
	v := &v2{Proto: proto, Name: u.Fragment, Server: u.Hostname()}
	if v.Server == "" {
		return nil, errors.New("missing server")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		if proto == "trojan" && u.Port() == "" {
			port = 443
		} else {
			return nil, errors.New("bad port")
		}
	}
	v.Port = port
	v.ID = userInfo(u)
	v.Net = normNet(q.Get("type"))
	v.HeaderType = strings.ToLower(q.Get("headerType"))
	v.Host = q.Get("host")
	v.Path = q.Get("path")
	v.Service = firstNonEmpty(q.Get("serviceName"), q.Get("service_name"))
	v.Authority = q.Get("authority")
	v.GrpcMode = q.Get("mode")
	v.XMode = q.Get("mode")
	v.XExtra = q.Get("extra")
	v.Seed = q.Get("seed")
	v.Security = strings.ToLower(q.Get("security"))
	v.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("serverName"))
	v.FP = q.Get("fp")
	v.ALPN = splitList(q.Get("alpn"))
	v.Insecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) || truthy(q.Get("allow_insecure"))
	v.PBK = firstNonEmpty(q.Get("pbk"), q.Get("publicKey"))
	v.SID = firstNonEmpty(q.Get("sid"), q.Get("shortId"))
	v.SPX = q.Get("spx")
	v.PQV = q.Get("pqv")
	v.ECH = q.Get("ech")
	v.PCS = q.Get("pcs")
	v.VCN = q.Get("vcn")
	v.FM = q.Get("fm")
	v.Flow = q.Get("flow")
	v.Encryption = q.Get("encryption")
	v.PacketEnc = q.Get("packetEncoding")
	if v.Net == "kcp" && v.Seed == "" && v.Path != "" {
		v.Seed = v.Path
	}
	if v.Net == "grpc" && v.Service == "" {
		v.Service = v.Path
	}
	if proto == "vmess" {
		v.Cipher = firstNonEmpty(q.Get("encryption"), q.Get("scy"), "auto")
		v.Encryption = ""
	}
	if proto == "trojan" && v.Security == "" {
		v.Security = "tls"
	}
	if v.Security == "xtls" {
		v.Security = "tls"
	}
	return v, nil
}

func jsonString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		for mk, val := range m {
			if !strings.EqualFold(mk, k) {
				continue
			}
			switch t := val.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return strconv.FormatInt(int64(t), 10)
			case bool:
				return strconv.FormatBool(t)
			case json.Number:
				return t.String()
			}
		}
	}
	return ""
}

func jsonObject(m map[string]any, key string) map[string]any {
	for mk, val := range m {
		if strings.EqualFold(mk, key) {
			if o, ok := val.(map[string]any); ok {
				return o
			}
			if s, ok := val.(string); ok && s != "" {
				var o map[string]any
				if json.Unmarshal([]byte(s), &o) == nil {
					return o
				}
			}
		}
	}
	return nil
}

func v2FromVmessJSON(data []byte) (*v2, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	v := &v2{Proto: "vmess"}
	v.Name = jsonString(m, "ps", "remarks", "remark")
	v.Server = jsonString(m, "add", "address")
	port, err := strconv.Atoi(jsonString(m, "port"))
	if err != nil || v.Server == "" {
		return nil, errors.New("bad vmess json")
	}
	v.Port = port
	v.ID = jsonString(m, "id")
	v.AlterID, _ = strconv.Atoi(jsonString(m, "aid", "alterId"))
	v.Cipher = firstNonEmpty(jsonString(m, "scy", "security"), "auto")
	v.Net = normNet(jsonString(m, "net", "network"))
	typ := strings.ToLower(jsonString(m, "type"))
	v.Host = jsonString(m, "host")
	v.Path = jsonString(m, "path")
	switch v.Net {
	case "tcp":
		v.HeaderType = typ
	case "kcp":
		v.HeaderType = typ
		v.Seed = firstNonEmpty(jsonString(m, "seed"), v.Path)
	case "grpc":
		v.Service = firstNonEmpty(jsonString(m, "serviceName"), v.Path)
		v.Authority = firstNonEmpty(jsonString(m, "authority"), v.Host)
		v.GrpcMode = typ
	case "xhttp":
		v.XMode = firstNonEmpty(jsonString(m, "mode"), typ)
		v.XExtra = jsonString(m, "extra")
	}
	tls := strings.ToLower(jsonString(m, "tls", "streamSecurity"))
	if tls == "tls" || tls == "reality" || tls == "xtls" {
		v.Security = tls
		if tls == "xtls" {
			v.Security = "tls"
		}
	}
	v.SNI = jsonString(m, "sni", "serverName")
	v.ALPN = splitList(jsonString(m, "alpn"))
	v.FP = jsonString(m, "fp", "fingerprint")
	v.Insecure = truthy(jsonString(m, "allowInsecure", "insecure", "skip-cert-verify"))
	v.PBK = jsonString(m, "pbk", "publicKey")
	v.SID = jsonString(m, "sid", "shortId")
	v.SPX = jsonString(m, "spx", "spiderX")
	v.PCS = jsonString(m, "pcs")
	v.ECH = jsonString(m, "ech")
	return v, nil
}

func (v *v2) tlsName() string {
	if v.SNI != "" {
		return v.SNI
	}
	if v.Host != "" {
		if hs := splitList(v.Host); len(hs) > 0 {
			return hs[0]
		}
	}
	return v.Server
}

func (v *v2) fingerprint() string {
	if v.FP == "" || strings.EqualFold(v.FP, "none") {
		return "chrome"
	}
	return strings.ToLower(v.FP)
}

func earlyData(path string) (string, int) {
	pu, err := url.Parse(path)
	if err != nil {
		return path, 0
	}
	q := pu.Query()
	ed, err := strconv.Atoi(q.Get("ed"))
	if err != nil || ed <= 0 {
		return path, 0
	}
	q.Del("ed")
	pu.RawQuery = q.Encode()
	return pu.String(), ed
}

func (v *v2) xrayStream() (map[string]any, error) {
	s := map[string]any{}
	switch v.Net {
	case "tcp":
		s["network"] = "raw"
		if v.HeaderType == "http" {
			path := []string{"/"}
			if v.Path != "" {
				path = splitList(v.Path)
			}
			req := map[string]any{"path": path}
			if hosts := splitList(v.Host); len(hosts) > 0 {
				req["headers"] = map[string]any{"Host": hosts}
			}
			s["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		s["network"] = "ws"
		ws := map[string]any{"path": firstNonEmpty(v.Path, "/")}
		if v.Host != "" {
			ws["host"] = v.Host
		}
		s["wsSettings"] = ws
	case "httpupgrade":
		s["network"] = "httpupgrade"
		hu := map[string]any{"path": firstNonEmpty(v.Path, "/")}
		if v.Host != "" {
			hu["host"] = v.Host
		}
		s["httpupgradeSettings"] = hu
	case "grpc":
		s["network"] = "grpc"
		g := map[string]any{"serviceName": v.Service, "multiMode": strings.EqualFold(v.GrpcMode, "multi")}
		if v.Authority != "" {
			g["authority"] = v.Authority
		}
		s["grpcSettings"] = g
	case "xhttp":
		s["network"] = "xhttp"
		x := map[string]any{"path": firstNonEmpty(v.Path, "/")}
		if v.Host != "" {
			x["host"] = v.Host
		}
		if v.XMode != "" {
			x["mode"] = v.XMode
		}
		if v.XExtra != "" {
			var extra any
			if err := json.Unmarshal([]byte(v.XExtra), &extra); err == nil {
				x["extra"] = extra
			}
		}
		s["xhttpSettings"] = x
	case "kcp":
		s["network"] = "kcp"
		s["kcpSettings"] = map[string]any{}
		var masks []any
		if v.Seed != "" {
			masks = append(masks, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"value": v.Seed}})
		} else {
			masks = append(masks, map[string]any{"type": "mkcp-legacy"})
		}
		header := map[string]string{"srtp": "srtp", "utp": "utp", "wechat-video": "wechat", "wechat": "wechat", "dtls": "dtls", "wireguard": "wireguard", "dns": "dns"}[v.HeaderType]
		if header != "" {
			masks = append(masks, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"header": header}})
		}
		s["finalmask"] = map[string]any{"udp": masks}
	default:
		return nil, fmt.Errorf("transport %q not supported by xray", v.Net)
	}
	switch v.Security {
	case "tls":
		t := map[string]any{"serverName": v.tlsName(), "fingerprint": v.fingerprint()}
		if len(v.ALPN) > 0 {
			t["alpn"] = v.ALPN
		}
		if v.PCS != "" {
			t["pinnedPeerCertSha256"] = v.PCS
		}
		if v.VCN != "" {
			t["verifyPeerCertByName"] = v.VCN
		}
		if v.ECH != "" {
			t["echConfigList"] = v.ECH
		}
		s["security"] = "tls"
		s["tlsSettings"] = t
	case "reality":
		r := map[string]any{"serverName": v.SNI, "fingerprint": v.fingerprint(), "publicKey": v.PBK, "shortId": v.SID}
		if v.SPX != "" {
			r["spiderX"] = v.SPX
		}
		if v.PQV != "" {
			r["mldsa65Verify"] = v.PQV
		}
		s["security"] = "reality"
		s["realitySettings"] = r
	}
	if v.FM != "" {
		var fm any
		if err := json.Unmarshal([]byte(v.FM), &fm); err == nil {
			s["finalmask"] = fm
		}
	}
	return s, nil
}

func (v *v2) toXray() (map[string]any, error) {
	ob := map[string]any{}
	switch v.Proto {
	case "vless":
		user := map[string]any{"id": v.ID, "encryption": firstNonEmpty(v.Encryption, "none")}
		if v.Flow != "" {
			user["flow"] = v.Flow
		}
		ob["protocol"] = "vless"
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{"address": v.Server, "port": v.Port, "users": []any{user}}}}
	case "vmess":
		user := map[string]any{"id": v.ID, "alterId": v.AlterID, "security": firstNonEmpty(v.Cipher, "auto")}
		ob["protocol"] = "vmess"
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{"address": v.Server, "port": v.Port, "users": []any{user}}}}
	case "trojan":
		if v.SSMethod != "" {
			return nil, errors.New("trojan-go shadowsocks layer not supported by xray")
		}
		ob["protocol"] = "trojan"
		ob["settings"] = map[string]any{"servers": []any{map[string]any{"address": v.Server, "port": v.Port, "password": v.ID}}}
	default:
		return nil, errors.New("unsupported")
	}
	s, err := v.xrayStream()
	if err != nil {
		return nil, err
	}
	ob["streamSettings"] = s
	return ob, nil
}

func xhttpOptsViaConverter(path, host, mode, extra string) map[string]any {
	q := url.Values{}
	q.Set("type", "xhttp")
	if path != "" {
		q.Set("path", path)
	}
	if host != "" {
		q.Set("host", host)
	}
	if mode != "" {
		q.Set("mode", mode)
	}
	if extra != "" {
		q.Set("extra", extra)
	}
	link := "vless://00000000-0000-0000-0000-000000000000@example.com:443?" + q.Encode() + "#x"
	ps, err := convert.ConvertsV2Ray([]byte(link))
	if err != nil || len(ps) == 0 {
		return map[string]any{"path": path, "host": host, "mode": mode}
	}
	if o, ok := ps[0]["xhttp-opts"].(map[string]any); ok {
		return o
	}
	return map[string]any{"path": path, "host": host, "mode": mode}
}

func (v *v2) mihomoSupports() bool {
	switch v.Proto {
	case "vless":
		switch v.Net {
		case "tcp", "ws", "httpupgrade", "h2", "grpc", "xhttp":
			return true
		}
	case "vmess":
		switch v.Net {
		case "tcp", "ws", "httpupgrade", "h2", "grpc", "kcp":
			return true
		}
	case "trojan":
		switch v.Net {
		case "tcp", "ws", "httpupgrade", "grpc":
			return v.HeaderType != "http"
		}
	}
	return false
}

func (v *v2) toMihomo() (map[string]any, error) {
	if !v.mihomoSupports() {
		return nil, fmt.Errorf("transport %q not supported by mihomo for %s", v.Net, v.Proto)
	}
	m := map[string]any{"name": firstNonEmpty(v.Name, "node"), "type": v.Proto, "server": v.Server, "port": v.Port, "udp": true}
	switch v.Proto {
	case "vless":
		m["uuid"] = v.ID
		if v.Flow != "" {
			m["flow"] = strings.ToLower(v.Flow)
		}
		if v.Encryption != "" && !strings.EqualFold(v.Encryption, "none") {
			m["encryption"] = v.Encryption
		}
	case "vmess":
		m["uuid"] = v.ID
		m["alterId"] = v.AlterID
		m["cipher"] = firstNonEmpty(v.Cipher, "auto")
	case "trojan":
		m["password"] = v.ID
		if v.SSMethod != "" {
			m["ss-opts"] = map[string]any{"enabled": true, "method": v.SSMethod, "password": v.SSPassword}
		}
	}
	if v.Proto != "trojan" {
		switch v.PacketEnc {
		case "none":
		case "packet", "packetaddr":
			m["packet-addr"] = true
		default:
			m["xudp"] = true
		}
	}
	tls := v.Security == "tls" || v.Security == "reality"
	if tls {
		if v.Proto != "trojan" {
			m["tls"] = true
			m["servername"] = v.tlsName()
		} else {
			m["sni"] = v.tlsName()
		}
		m["client-fingerprint"] = v.fingerprint()
		if len(v.ALPN) > 0 {
			m["alpn"] = v.ALPN
		}
		if v.Insecure {
			m["skip-cert-verify"] = true
		}
		if v.PCS != "" {
			m["fingerprint"] = strings.ReplaceAll(strings.Split(v.PCS, ",")[0], ":", "")
		}
		if v.ECH != "" {
			m["ech-opts"] = map[string]any{"enable": true, "config": v.ECH}
		}
		if v.Security == "reality" {
			m["reality-opts"] = map[string]any{"public-key": v.PBK, "short-id": v.SID}
		}
	} else if v.Proto == "trojan" {
		return nil, errors.New("trojan without tls not supported by mihomo")
	}
	switch v.Net {
	case "tcp":
		if v.HeaderType == "http" {
			m["network"] = "http"
			path := []string{"/"}
			if v.Path != "" {
				path = splitList(v.Path)
			}
			h := map[string]any{"path": path}
			if hosts := splitList(v.Host); len(hosts) > 0 {
				h["headers"] = map[string]any{"Host": hosts}
			}
			m["http-opts"] = h
		} else {
			m["network"] = "tcp"
		}
	case "ws", "httpupgrade":
		m["network"] = "ws"
		path, ed := earlyData(firstNonEmpty(v.Path, "/"))
		headers := map[string]any{}
		if v.Host != "" {
			headers["Host"] = v.Host
		}
		ws := map[string]any{"path": path, "headers": headers}
		if v.Net == "httpupgrade" {
			ws["v2ray-http-upgrade"] = true
			if ed > 0 {
				ws["v2ray-http-upgrade-fast-open"] = true
			}
		} else if ed > 0 {
			ws["max-early-data"] = ed
			ws["early-data-header-name"] = "Sec-WebSocket-Protocol"
		}
		m["ws-opts"] = ws
	case "h2":
		m["network"] = "h2"
		h2 := map[string]any{"path": firstNonEmpty(v.Path, "/")}
		if hosts := splitList(v.Host); len(hosts) > 0 {
			h2["host"] = hosts
		}
		m["h2-opts"] = h2
	case "grpc":
		m["network"] = "grpc"
		m["grpc-opts"] = map[string]any{"grpc-service-name": v.Service}
	case "xhttp":
		m["network"] = "xhttp"
		m["xhttp-opts"] = xhttpOptsViaConverter(v.Path, v.Host, v.XMode, v.XExtra)
	case "kcp":
		m["network"] = "mkcp"
		k := map[string]any{}
		if v.Seed != "" {
			k["seed"] = v.Seed
		}
		if v.HeaderType != "" && v.HeaderType != "none" {
			k["header"] = v.HeaderType
		}
		m["mkcp-opts"] = k
	}
	return m, nil
}

func (v *v2) candidates() ([]candidate, error) {
	var xc, mc *candidate
	var xerr, merr error
	if ob, err := v.toXray(); err == nil {
		c := xrayCandidate(ob)
		xc = &c
	} else {
		xerr = err
	}
	if m, err := v.toMihomo(); err == nil {
		c := mihomoCandidate(m)
		mc = &c
	} else {
		merr = err
	}
	var out []candidate
	preferMihomo := v.Insecure && v.PCS == "" && v.VCN == ""
	if preferMihomo {
		if mc != nil {
			out = append(out, *mc)
		}
		if xc != nil {
			out = append(out, *xc)
		}
	} else {
		if xc != nil {
			out = append(out, *xc)
		}
		if mc != nil {
			out = append(out, *mc)
		}
	}
	if len(out) == 0 {
		if v.Net == "quic" {
			return nil, errors.New("legacy QUIC transport was removed from Xray and is not supported")
		}
		if xerr != nil {
			return nil, xerr
		}
		return nil, merr
	}
	return out, nil
}
