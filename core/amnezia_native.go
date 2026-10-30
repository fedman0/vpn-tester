package main

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func amzSSEntry(m map[string]any) bool {
	if m == nil {
		return false
	}
	if amzStr(m, "server", "address") == "" || amzStr(m, "password") == "" || amzStr(m, "method") == "" {
		return false
	}
	return amzStr(m, "server_port", "port") != ""
}

func amzSSDoc(f *vfile) (map[string]any, []map[string]any) {
	if len(f.Data) == 0 || len(f.Data) > 1<<20 || !f.IsText() {
		return nil, nil
	}
	t := strings.TrimSpace(string(pxStripJSONC(f.Data)))
	if !strings.HasPrefix(t, "{") {
		return nil, nil
	}
	m, err := amzDecodeJSON([]byte(t))
	if err != nil {
		return nil, nil
	}
	if _, ok := m["outbounds"]; ok {
		return nil, nil
	}
	if _, ok := m["proxies"]; ok {
		return nil, nil
	}
	var out []map[string]any
	if amzSSEntry(m) {
		out = append(out, m)
	}
	if list, ok := m["servers"].([]any); ok {
		for _, it := range list {
			if e, ok := it.(map[string]any); ok && amzSSEntry(e) {
				out = append(out, e)
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return m, out
}

type ShadowsocksJSONDetector struct{}

func (ShadowsocksJSONDetector) Detect(f *vfile) int {
	if _, es := amzSSDoc(f); len(es) > 0 {
		return 70
	}
	return 0
}

type ShadowsocksJSONParser struct{}

func (ShadowsocksJSONParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	_, es := amzSSDoc(f)
	if len(es) == 0 {
		return nil, errors.New("not a Shadowsocks client config")
	}
	base := strings.TrimSuffix(f.Name, "."+f.Ext)
	var out []*Config
	for i, e := range es {
		host := strings.Trim(amzStr(e, "server", "address"), "[]")
		port, _ := strconv.Atoi(amzStr(e, "server_port", "port"))
		name := firstNonEmpty(amzStr(e, "remarks", "tag", "name"), base)
		ch := f.Child("servers["+strconv.Itoa(i)+"]", name+".txt", nil)
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() || host == "" {
			c := unsupportedConfig(ch, "Shadowsocks", "ss", "Shadowsocks server-side config (listens on "+firstNonEmpty(host, "?")+"), not a client config")
			c.Name, c.Port = name, port
			out = append(out, c)
			continue
		}
		user := base64.RawURLEncoding.EncodeToString([]byte(amzStr(e, "method") + ":" + amzStr(e, "password")))
		link := "ss://" + user + "@" + net.JoinHostPort(host, strconv.Itoa(port))
		if pl := amzStr(e, "plugin"); pl != "" {
			v := pl
			if po := amzStr(e, "plugin_opts", "plugin-opts"); po != "" {
				v += ";" + po
			}
			link += "/?plugin=" + url.QueryEscape(v)
		}
		link += "#" + url.PathEscape(name)
		ch.Data = []byte(link)
		for _, c := range linkConfigs(ch, fs, link) {
			c.Format = "Shadowsocks"
			c.Name = name
			out = append(out, c)
		}
	}
	return out, nil
}

func init() {
	registerFormat(&fileFormat{Name: "Shadowsocks", Detector: ShadowsocksJSONDetector{}, Parser: ShadowsocksJSONParser{}})
}
