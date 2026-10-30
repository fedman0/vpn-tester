package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/juicity"
	"github.com/metacubex/mihomo/transport/shadowtls"
	"github.com/txthinking/brook"
)

func deadlineFrom(ctx context.Context, c net.Conn) {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
}

type socks4Dialer struct {
	server string
	user   string
	a      bool
}

func parseSocks4(scheme, link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: scheme}, err
	}
	host, port, err := hostPort(u, 1080)
	if err != nil {
		return &node{Proto: scheme}, err
	}
	d := &socks4Dialer{server: net.JoinHostPort(host, strconv.Itoa(port)), user: u.User.Username(), a: scheme == "socks4a"}
	return &node{Proto: scheme, Candidates: one(candidate{
		Engine: "native",
		Debug:  map[string]any{"server": d.server, "user": d.user, "socks4a": d.a},
		Build:  func() (Dialer, error) { return d, nil },
	})}, nil
}

func (d *socks4Dialer) Close() error { return nil }

func (d *socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}
	deadlineFrom(ctx, c)
	ip := net.ParseIP(host).To4()
	domain := ""
	if ip == nil {
		if d.a {
			ip = net.IPv4(0, 0, 0, 1).To4()
			domain = host
		} else {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				c.Close()
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
			ip = ips[0].To4()
		}
	}
	req := []byte{4, 1, byte(port >> 8), byte(port)}
	req = append(req, ip...)
	req = append(req, d.user...)
	req = append(req, 0)
	if domain != "" {
		req = append(req, domain...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(c, resp); err != nil {
		c.Close()
		return nil, err
	}
	if resp[1] != 0x5a {
		c.Close()
		return nil, fmt.Errorf("%w: socks4 code %d", errRejected, resp[1])
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

type netproxyConn struct {
	netproxy.Conn
}

func (c netproxyConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c netproxyConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

type juicityDialer struct {
	d netproxy.Dialer
}

func (j *juicityDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := j.d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := c.(net.Conn); ok {
		return nc, nil
	}
	return netproxyConn{c}, nil
}

func (j *juicityDialer) Close() error { return nil }

func parseJuicity(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "juicity"}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return &node{Proto: "juicity"}, err
	}
	q := u.Query()
	id := u.User.Username()
	pass, _ := u.User.Password()
	sni := firstNonEmpty(qget(q, "sni", "peer"), host)
	insecure := truthy(qget(q, "allow_insecure", "allowInsecure", "insecure")) || qget(q, "pinned_certchain_sha256") != ""
	cc := firstNonEmpty(qget(q, "congestion_control", "cc"), "bbr")
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	build := func() (Dialer, error) {
		h := protocol.Header{
			ProxyAddress: addr,
			SNI:          sni,
			Feature1:     cc,
			TlsConfig:    &tls.Config{ServerName: sni, InsecureSkipVerify: insecure, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
			User:         id,
			Password:     pass,
			IsClient:     true,
		}
		d, err := juicity.NewDialer(direct.SymmetricDirect, h)
		if err != nil {
			return nil, err
		}
		return &juicityDialer{d: d}, nil
	}
	return &node{Proto: "juicity", Candidates: one(candidate{
		Engine: "juicity",
		Debug:  map[string]any{"server": addr, "uuid": id, "sni": sni, "insecure": insecure, "cc": cc},
		Build:  build,
	})}, nil
}

type brookDialer struct {
	blk *brook.BrookLink
}

func socks5AddrBytes(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("host too long")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func (d *brookDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dst, err := socks5AddrBytes(addr)
	if err != nil {
		return nil, err
	}
	type res struct {
		ex brook.Exchanger
		rc net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ex, rc, err := d.blk.CreateExchanger("tcp", "127.0.0.1:1", dst, 30, 30)
		ch <- res{ex, rc, err}
	}()
	var r res
	select {
	case <-ctx.Done():
		go func() {
			r := <-ch
			if r.err == nil {
				r.ex.Clean()
				r.rc.Close()
			}
		}()
		return nil, ctx.Err()
	case r = <-ch:
	}
	if r.err != nil {
		return nil, r.err
	}
	local, remote := net.Pipe()
	go func() {
		r.ex.Exchange(remote)
		r.ex.Clean()
		r.rc.Close()
		remote.Close()
	}()
	stop := context.AfterFunc(ctx, func() { local.Close() })
	return &pipeConn{Conn: local, onClose: func() { stop() }}, nil
}

func (d *brookDialer) Close() error { return nil }

func parseBrook(link string) (*node, error) {
	blk, err := brook.NewBrookLink(link)
	if err != nil {
		return &node{Proto: "brook"}, err
	}
	if blk.Kind == "socks5" {
		u, err := url.Parse(blk.V.Get("socks5"))
		if err != nil {
			return &node{Proto: "brook"}, err
		}
		host, port, err := hostPort(u, 1080)
		if err != nil {
			return &node{Proto: "brook"}, err
		}
		m := map[string]any{"name": "socks", "type": "socks5", "server": host, "port": port}
		if user := blk.V.Get("username"); user != "" {
			m["username"] = user
			m["password"] = blk.V.Get("password")
		}
		return &node{Proto: "socks5", Candidates: one(mihomoCandidate(m))}, nil
	}
	switch blk.Kind {
	case "server", "wsserver", "wssserver", "quicserver":
	default:
		return &node{Proto: "brook"}, fmt.Errorf("brook kind %q not supported", blk.Kind)
	}
	return &node{Proto: "brook-" + blk.Kind, Candidates: one(candidate{
		Engine: "brook",
		Debug:  map[string]any{"kind": blk.Kind, "address": blk.Address, "host": blk.Host, "path": blk.Path},
		Build:  func() (Dialer, error) { return &brookDialer{blk: blk}, nil },
	})}, nil
}

func parseShadowTLS(link string) (*node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return &node{Proto: "shadowtls"}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return &node{Proto: "shadowtls"}, err
	}
	q := u.Query()
	password := firstNonEmpty(qget(q, "password", "shadowtls-password", "stls-password"), userInfo(u))
	version, _ := strconv.Atoi(firstNonEmpty(qget(q, "version", "v"), "3"))
	sni := firstNonEmpty(qget(q, "sni", "host", "peer", "server_name"), host)
	if inner := qget(q, "ss", "inner", "detour"); inner != "" {
		if !strings.Contains(inner, "://") {
			inner = "ss://" + inner
		}
		n, err := parseSS(inner)
		if err != nil {
			return &node{Proto: "shadowtls"}, err
		}
		for _, c := range n.Candidates {
			if c.Engine != "mihomo" {
				continue
			}
			m, _ := c.Debug.(map[string]any)
			if m == nil {
				continue
			}
			m["server"] = host
			m["port"] = port
			m["plugin"] = "shadow-tls"
			m["client-fingerprint"] = "chrome"
			m["plugin-opts"] = map[string]any{"host": sni, "password": password, "version": version}
			return &node{Proto: "ss+shadowtls", Candidates: one(mihomoCandidate(m))}, nil
		}
	}
	method := qget(q, "method", "cipher", "ss-method")
	ssPass := qget(q, "ss-password", "ss_password", "sspassword")
	if method != "" && ssPass != "" {
		m := map[string]any{"name": "stls", "type": "ss", "server": host, "port": port, "cipher": strings.ToLower(method), "password": ssPass, "udp": true,
			"plugin": "shadow-tls", "client-fingerprint": "chrome",
			"plugin-opts": map[string]any{"host": sni, "password": password, "version": version}}
		return &node{Proto: "ss+shadowtls", Candidates: one(mihomoCandidate(m))}, nil
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	probe := func(ctx context.Context) (time.Duration, error) {
		start := time.Now()
		var nd net.Dialer
		c, err := nd.DialContext(ctx, "tcp", addr)
		if err != nil {
			return 0, err
		}
		defer c.Close()
		deadlineFrom(ctx, c)
		sc, err := shadowtls.NewShadowTLS(ctx, c, &shadowtls.ShadowTLSOption{
			Password:          password,
			Host:              sni,
			Version:           version,
			ClientFingerprint: "chrome",
			ALPN:              shadowtls.DefaultALPN,
		})
		if err != nil {
			if strings.Contains(err.Error(), "hijacked") {
				return 0, fmt.Errorf("%w: wrong shadowtls password", errRejected)
			}
			return 0, err
		}
		sc.Close()
		return time.Since(start), nil
	}
	return &node{Proto: "shadowtls", Candidates: one(candidate{
		Engine: "shadowtls-handshake",
		Debug:  map[string]any{"server": addr, "sni": sni, "version": version},
		Probe:  probe,
	})}, nil
}
