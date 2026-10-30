package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type linkHandler func(f *vfile, fs *vfs, link string) []*Config

var (
	linkHandlersMu sync.RWMutex
	linkHandlers   = map[string]linkHandler{}
)

func registerLinkScheme(h linkHandler, schemes ...string) {
	linkHandlersMu.Lock()
	defer linkHandlersMu.Unlock()
	for _, s := range schemes {
		linkHandlers[strings.ToLower(s)] = h
	}
}

func lookupLinkHandler(link string) linkHandler {
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil
	}
	linkHandlersMu.RLock()
	defer linkHandlersMu.RUnlock()
	return linkHandlers[strings.ToLower(strings.TrimSpace(scheme))]
}

func linkConfigs(f *vfile, fs *vfs, link string) []*Config {
	if h := lookupLinkHandler(link); h != nil {
		var cs []*Config
		func() {
			defer func() {
				if p := recover(); p != nil {
					cs = []*Config{invalidConfig(f, "Links", fmt.Errorf("link parser crashed: %v", p))}
				}
			}()
			cs = h(f, fs, link)
		}()
		if len(cs) == 0 {
			cs = []*Config{invalidConfig(f, "Links", errors.New("no usable config in link"))}
		}
		for _, c := range cs {
			if len(c.RawConfig) == 0 {
				c.RawConfig = []byte(link)
			}
		}
		return cs
	}
	n, err := parseLink(link)
	c := newNodeConfig(f, "Links", n, err, linkMeta(link))
	if c.Protocol == "" {
		scheme, _, _ := strings.Cut(link, "://")
		c.Protocol = strings.ToLower(scheme)
	}
	c.RawConfig = []byte(link)
	return []*Config{c}
}

func runLinkViaHandler(cfg *runConfig, j job, h linkHandler) (r result) {
	r.ID = j.ID
	link := strings.TrimSpace(j.Link)
	f := newVFile("link.txt", []byte(link))
	cs := h(f, newVFS(), link)
	var testable []*Config
	for _, c := range cs {
		validateConfig(c)
		if c.Status == StateParsed && c.Tester != nil {
			testable = append(testable, c)
		}
	}
	if len(testable) == 0 {
		if len(cs) > 0 {
			r.Proto = cs[0].Protocol
			r.Error = firstNonEmpty(cs[0].Error, strings.ToLower(cs[0].Status))
		} else {
			r.Error = "no usable config in link"
		}
		return
	}
	opt := &scanOptions{URLs: cfg.URLs, Concurrency: 1}
	opt.Timeouts.Overall = cfg.Timeout
	opt.normalize()
	if opt.Timeouts.Overall < 3000 {
		opt.Timeouts.Overall = 3000
	}
	results := make([]*TestResult, len(testable))
	var wg sync.WaitGroup
	for i, c := range testable {
		c.ID = i + 1
		wg.Add(1)
		go func(i int, c *Config) {
			defer wg.Done()
			results[i] = testConfig(opt, c)
		}(i, c)
	}
	wg.Wait()
	best := -1
	for i, res := range results {
		if res.IsConnectable && (best < 0 || res.Latency < results[best].Latency) {
			best = i
		}
	}
	if best >= 0 {
		res := results[best]
		r.OK = true
		r.Delay = res.Latency
		r.Proto = testable[best].Protocol
		r.Engine = res.Engine
		if res.Result != StateDataPlaneVerified {
			r.Error = firstNonEmpty(res.Note, "handshake ok, data probe not verified")
		}
		return
	}
	res := results[0]
	r.Proto = testable[0].Protocol
	r.Engine = res.Engine
	r.Error = strings.TrimSpace(res.Result + ": " + res.ErrorMessage)
	if res.ErrorCode == "TIMEOUT" {
		r.Error = "timeout"
	}
	return
}

func wireguardLinkHandler(f *vfile, fs *vfs, link string) []*Config {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return []*Config{invalidConfig(f, "Links", err)}
	}
	q := u.Query()
	priv := ""
	if u.User != nil {
		priv = u.User.Username()
		if p, ok := u.User.Password(); ok && p != "" {
			priv += ":" + p
		}
	}
	priv = firstNonEmpty(priv, qget(q, "privatekey", "private_key", "secretkey", "private-key"))
	if dec, err := url.PathUnescape(priv); err == nil {
		priv = dec
	}
	pub := qget(q, "publickey", "public_key", "peer", "public-key", "pk")
	addr := qget(q, "address", "ip", "local_address", "addr")
	if u.Hostname() == "" || u.Port() == "" {
		return []*Config{invalidConfig(f, "Links", errors.New("wireguard link has no endpoint host:port"))}
	}
	var b strings.Builder
	b.WriteString("[Interface]\nPrivateKey = " + priv + "\n")
	if addr != "" {
		b.WriteString("Address = " + strings.ReplaceAll(addr, ";", ",") + "\n")
	}
	if v := qget(q, "dns"); v != "" {
		b.WriteString("DNS = " + v + "\n")
	}
	if v := qget(q, "mtu"); v != "" {
		b.WriteString("MTU = " + v + "\n")
	}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if v := qget(q, k); v != "" {
			b.WriteString(strings.ToUpper(k[:1]) + k[1:] + " = " + v + "\n")
		}
	}
	b.WriteString("\n[Peer]\nPublicKey = " + pub + "\n")
	if v := qget(q, "presharedkey", "preshared_key", "psk", "pre_shared_key"); v != "" {
		b.WriteString("PresharedKey = " + v + "\n")
	}
	b.WriteString("Endpoint = " + u.Host + "\n")
	allowed := firstNonEmpty(qget(q, "allowedips", "allowed_ips"), "0.0.0.0/0, ::/0")
	b.WriteString("AllowedIPs = " + strings.ReplaceAll(allowed, ";", ",") + "\n")
	if v := qget(q, "keepalive", "persistentkeepalive"); v != "" {
		b.WriteString("PersistentKeepalive = " + v + "\n")
	}
	name := u.Fragment
	if name == "" {
		name = "wireguard"
	}
	cs, _ := parseAs("WireGuard", f.Child("wg", name+".conf", []byte(b.String())), fs)
	for _, c := range cs {
		if c.Name == "" {
			c.Name = u.Fragment
		}
		if v := qget(q, "reserved"); v != "" {
			c.Warn("reserved bytes (%s) are not used by the handshake test", v)
		}
	}
	return cs
}

func amneziaLinkHandler(f *vfile, fs *vfs, link string) []*Config {
	cs, _ := parseAs("AmneziaVPN", f.Child("amnezia", "amnezia.vpn", []byte(strings.TrimSpace(link))), fs)
	return cs
}

func init() {
	registerLinkScheme(wireguardLinkHandler, "wireguard", "wg", "awg", "amneziawg")
	registerLinkScheme(amneziaLinkHandler, "vpn")
}
