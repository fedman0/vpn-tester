package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var linkSchemes = []string{
	"vless", "vmess", "trojan", "trojan-go", "ss", "ssr", "socks", "socks4", "socks4a", "socks5", "socks5h",
	"https", "http", "tg", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "mieru", "mierus", "ssh", "snell",
	"masque", "tt", "trusttunnel", "naive", "naive+https", "naive+quic", "juicity", "brook", "shadowtls",
	"v2rayn", "realm", "wireguard", "wg", "awg",
}

var linkRe = regexp.MustCompile(`(?i)\b(?:slipnet-bundle-enc|slipnet-enc|slipnet|vless|vmess|trojan-go|trojan|ssr|ss|socks5h|socks5|socks4a|socks4|socks|tg|hysteria2|hysteria|hy2|tuic|anytls|mierus|mieru|ssh|snell|masque|trusttunnel|tt|naive\+https|naive\+quic|naive|juicity|brook|shadowtls|v2rayn|realm|wireguard|awg|wg|vpn)://[^\s"'<>]+`)

var proxyHTTPRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>/@]+:[^\s"'<>/@]*@[^\s"'<>/]+`)

type LinkListDetector struct{}

func (LinkListDetector) Detect(f *vfile) int {
	if !f.IsText() || len(f.Data) == 0 {
		return 0
	}
	links := extractFileLinks(f.Text())
	if len(links) == 0 {
		return 0
	}
	t := strings.TrimSpace(f.Text())
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return 15
	}
	return 40
}

func extractFileLinks(text string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimRight(strings.TrimSpace(s), ",;")
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	scan := func(t string) {
		for _, line := range strings.Split(t, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			ms := linkRe.FindAllString(line, -1)
			if len(ms) == 1 && strings.HasPrefix(strings.ToLower(line), strings.ToLower(ms[0][:strings.Index(ms[0], "://")])) {
				add(line)
				continue
			}
			for _, m := range ms {
				add(m)
			}
			for _, m := range proxyHTTPRe.FindAllString(line, -1) {
				add(m)
			}
		}
	}
	scan(text)
	if len(out) == 0 {
		t := strings.TrimSpace(text)
		if len(t) >= 16 && !strings.ContainsAny(t, " {}<>") {
			if b, err := b64decode(t); err == nil {
				scan(string(b))
			}
		}
	}
	return out
}

func linkMeta(link string) nodeMeta {
	m := nodeMeta{}
	scheme, rest, _ := strings.Cut(link, "://")
	scheme = strings.ToLower(scheme)
	if scheme == "vmess" {
		body := rest
		if i := strings.IndexAny(body, "#?"); i >= 0 {
			body = body[:i]
		}
		if b, err := b64decode(body); err == nil {
			var j map[string]any
			if json.Unmarshal(b, &j) == nil {
				m.Name = jsonString(j, "ps")
				m.Host = jsonString(j, "add")
				m.Port, _ = strconv.Atoi(jsonString(j, "port"))
				m.Transport = jsonString(j, "net")
				m.Security = jsonString(j, "tls")
				m.SNI = jsonString(j, "sni")
				m.UUID = jsonString(j, "id")
				if m.Transport == "" {
					m.Transport = "tcp"
				}
				m.UDP = udpProto("vmess", m.Transport)
				m.Extra = jsonString(j, "path") + "|" + jsonString(j, "host")
				return m
			}
		}
	}
	if scheme == "ss" && !strings.Contains(rest, "@") {
		body := rest
		if i := strings.IndexAny(body, "#?/"); i >= 0 {
			body = body[:i]
		}
		if b, err := b64decode(body); err == nil {
			rest = string(b)
			if i := strings.Index(link, "#"); i >= 0 {
				rest += link[i:]
			}
			link = "ss://" + rest
		}
	}
	u, err := url.Parse(link)
	if err != nil {
		return m
	}
	if f := u.Fragment; f != "" {
		m.Name = f
	}
	m.Host = u.Hostname()
	m.Port, _ = strconv.Atoi(u.Port())
	q := u.Query()
	m.Transport = firstNonEmpty(qget(q, "type", "network", "net", "transport"), "tcp")
	m.Security = qget(q, "security")
	if m.Security == "" && (scheme == "trojan" || scheme == "hysteria2" || scheme == "hy2" || scheme == "tuic" || scheme == "hysteria" || scheme == "anytls" || scheme == "https") {
		m.Security = "tls"
	}
	m.SNI = qget(q, "sni", "peer", "servername", "serverName")
	m.PublicKey = qget(q, "pbk", "publicKey", "public-key")
	if u.User != nil {
		user := u.User.Username()
		pass, hasPass := u.User.Password()
		switch scheme {
		case "vless", "vmess", "tuic":
			m.UUID = user
			m.Password = pass
		case "ss":
			if hasPass {
				m.Password = pass
				m.Extra = user
			} else if b, err := b64decode(user); err == nil {
				method, pw, _ := strings.Cut(string(b), ":")
				m.Password = pw
				m.Extra = method
			}
		case "trojan", "hysteria2", "hy2", "anytls", "hysteria":
			m.Password = user
			if hasPass {
				m.Password = user + ":" + pass
			}
		default:
			m.User = user
			m.Password = pass
		}
	}
	m.Extra += "|" + qget(q, "path", "serviceName") + "|" + qget(q, "host")
	m.UDP = udpProto(scheme, m.Transport)
	return m
}

type LinkListParser struct{}

func (LinkListParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	links := extractFileLinks(f.Text())
	out := make([]*Config, 0, len(links))
	for i, l := range links {
		for _, c := range linkConfigs(f.Child(fmt.Sprintf("link%d", i), fmt.Sprintf("link%d.txt", i), []byte(l)), fs, l) {
			c.Format = "Links"
			c.File = f.Root().Path
			out = append(out, c)
		}
	}
	return out, nil
}

type LinkListFilter struct{}

func (LinkListFilter) Filter(f *vfile, indices []int) ([]byte, error) {
	links := extractFileLinks(f.Text())
	var owner []int
	for i, l := range links {
		n := 1
		if lookupLinkHandler(l) != nil {
			n = len(linkConfigs(f.Child(fmt.Sprintf("link%d", i), fmt.Sprintf("link%d.txt", i), []byte(l)), nil, l))
		}
		for k := 0; k < n; k++ {
			owner = append(owner, i)
		}
	}
	keep := map[int]bool{}
	for _, i := range indices {
		if i >= 0 && i < len(owner) {
			keep[owner[i]] = true
		}
	}
	var b strings.Builder
	for i, l := range links {
		if keep[i] {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func init() {
	registerFormat(&fileFormat{Name: "Links", Detector: LinkListDetector{}, Parser: LinkListParser{}, Filter: LinkListFilter{}})
}
