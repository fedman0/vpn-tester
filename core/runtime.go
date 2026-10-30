package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"

	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	mlog "github.com/metacubex/mihomo/log"
)

var fallbackDNS = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}

func dnsServers(in []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host, port = strings.Trim(s, "[]"), "53"
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return
		}
		addr := net.JoinHostPort(ip.String(), port)
		if seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}
	for _, s := range in {
		add(s)
	}
	for _, s := range fallbackDNS {
		add(s)
	}
	return out
}

func initRuntime(servers []string) {
	mlog.SetLevel(mlog.SILENT)
	list := dnsServers(servers)
	var idx atomic.Uint32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			i := idx.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, list[int(i)%len(list)])
		},
	}
	ns := make([]dns.NameServer, 0, len(list))
	for _, a := range list {
		ns = append(ns, dns.NameServer{Net: "udp", Addr: a})
	}
	rs := dns.NewResolver(dns.Config{Main: ns, Default: ns, ProxyServer: ns, DirectServer: ns})
	resolver.DefaultResolver = rs
	if rs.ProxyResolver != nil {
		resolver.ProxyServerHostResolver = rs.ProxyResolver
	} else {
		resolver.ProxyServerHostResolver = rs
	}
	if rs.DirectResolver != nil {
		resolver.DirectHostResolver = rs.DirectResolver
	} else {
		resolver.DirectHostResolver = rs
	}
	resolver.SystemResolver = rs
	direct.InitDirectDialers(list[0])
}
