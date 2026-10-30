package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

const amzBackupKey = "Servers/serversList"

type amzGroup struct {
	root    map[string]any
	asText  bool
	servers []any
	docAt   []int
}

func amzDecodeArray(b []byte) ([]any, error) {
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})))
	d.UseNumber()
	var a []any
	if err := d.Decode(&a); err != nil {
		return nil, err
	}
	return a, nil
}

func amzBackupList(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, false
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return []any{}, true
		}
		if !strings.HasPrefix(s, "[") {
			if b, err := amzDecodeB64(s); err == nil {
				s = strings.TrimSpace(string(b))
			}
		}
		if a, err := amzDecodeArray([]byte(s)); err == nil {
			return a, true
		}
	}
	return nil, false
}

func amzExtractGroup(b []byte) []*amzDoc {
	t := bytes.TrimSpace(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))
	if len(t) == 0 {
		return nil
	}
	g := &amzGroup{}
	if t[0] == '[' {
		a, err := amzDecodeArray(t)
		if err != nil {
			return nil
		}
		g.servers = a
	} else {
		m, err := amzDecodeJSON(t)
		if err != nil {
			return nil
		}
		v, ok := m[amzBackupKey]
		if !ok {
			return nil
		}
		list, text := amzBackupList(v)
		if list == nil {
			return []*amzDoc{{obj: map[string]any{"description": "Amnezia backup", "containers": []any{}}, group: g}}
		}
		g.root, g.asText, g.servers = m, text, list
	}
	var docs []*amzDoc
	for i, it := range g.servers {
		m, ok := it.(map[string]any)
		if !ok || !amzLooksAmnezia(m) {
			continue
		}
		g.docAt = append(g.docAt, i)
		docs = append(docs, &amzDoc{obj: m, group: g})
	}
	if len(docs) == 0 && g.root != nil {
		return []*amzDoc{{obj: map[string]any{"description": "Amnezia backup", "containers": []any{}}, group: g}}
	}
	return docs
}

func amzJSONIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (g *amzGroup) encode(kept map[int]map[string]any) ([]byte, error) {
	list := []any{}
	newIdx := map[int]int{}
	for di, si := range g.docAt {
		if obj, ok := kept[di]; ok {
			newIdx[si] = len(list)
			list = append(list, obj)
		}
	}
	if g.root == nil {
		return amzJSONIndent(list)
	}
	root := make(map[string]any, len(g.root))
	for k, v := range g.root {
		root[k] = v
	}
	if g.asText {
		b, err := amzJSONIndent(list)
		if err != nil {
			return nil, err
		}
		root[amzBackupKey] = string(b)
	} else {
		root[amzBackupKey] = list
	}
	if v := amzStr(root, "Servers/defaultServerIndex"); v != "" {
		old, _ := strconv.Atoi(v)
		ni, ok := newIdx[old]
		if !ok {
			ni = 0
		}
		root["Servers/defaultServerIndex"] = ni
	}
	if id := amzStr(root, "Servers/defaultServerId"); id != "" {
		first, found := "", false
		for _, it := range list {
			sid := amzStr(it.(map[string]any), "storageServerId")
			if sid == id {
				found = true
			}
			if first == "" {
				first = sid
			}
		}
		if !found {
			if first != "" {
				root["Servers/defaultServerId"] = first
			} else {
				delete(root, "Servers/defaultServerId")
			}
		}
	}
	return amzJSONIndent(root)
}

func amzTgLink(proto map[string]any, prefix, host string) string {
	link := amzStr(proto, prefix+"_tg_link")
	if link == "" {
		if l := amzStr(proto, prefix+"_tme_link"); l != "" {
			if i := strings.Index(l, "/proxy?"); i >= 0 {
				link = "tg://proxy?" + l[i+len("/proxy?"):]
			}
		}
	}
	pub := amzStr(proto, prefix+"_public_host")
	if link != "" {
		if u, err := url.Parse(link); err == nil {
			q := u.Query()
			srv := q.Get("server")
			if pub != "" || srv == "" || srv == "0.0.0.0" || srv == "::" {
				if s := firstNonEmpty(pub, host); s != "" {
					q.Set("server", s)
					u.RawQuery = q.Encode()
					link = u.String()
				}
			}
		}
		return link
	}
	secret := strings.ToLower(amzStr(proto, prefix+"_secret"))
	server := firstNonEmpty(pub, host)
	if secret == "" || server == "" {
		return ""
	}
	port := firstNonEmpty(amzStr(proto, "port"), "443")
	if strings.EqualFold(amzStr(proto, prefix+"_transport_mode"), "faketls") && len(secret) == 32 {
		secret = "ee" + secret + hex.EncodeToString([]byte(firstNonEmpty(amzStr(proto, prefix+"_tls_domain"), "googletagmanager.com")))
	}
	q := url.Values{}
	q.Set("server", strings.Trim(server, "[]"))
	q.Set("port", port)
	q.Set("secret", secret)
	return "tg://proxy?" + q.Encode()
}

func (b *amzBuilder) telegram(ci int, cont map[string]any, key, label, host string) {
	proto := amzObj(cont, key)
	if proto == nil {
		b.noClient(ci, key, label)
		return
	}
	if v, ok := proto[key+"_is_enabled"].(bool); ok && !v {
		b.unsupported(ci, "mtproxy", label, "Telegram proxy is disabled on the server")
		return
	}
	link := amzTgLink(proto, key, host)
	if link == "" {
		b.noClient(ci, "mtproxy", label)
		return
	}
	ch := b.child(ci, key, key+".txt", link)
	cs := linkConfigs(ch, b.fs, link)
	for _, c := range cs {
		c.Format = "AmneziaVPN"
		c.Name = label
		if c.Host == "" {
			if u, err := url.Parse(link); err == nil {
				c.Host = u.Query().Get("server")
				c.Port, _ = strconv.Atoi(u.Query().Get("port"))
			}
		}
	}
	b.add(ci, cs...)
}
