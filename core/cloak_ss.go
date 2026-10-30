package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

type ckSSDialer struct {
	cfg *ckConfig
	ss  *outbound.ShadowSocks
}

func newCloakSSDialer(cfg *ckConfig, m map[string]any) (Dialer, error) {
	str := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	port, _ := m["port"].(int)
	if port == 0 {
		port = cfg.RemotePort
	}
	ss, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss-cloak",
		Server:   firstNonEmpty(str("server"), cfg.RemoteHost),
		Port:     port,
		Password: str("password"),
		Cipher:   str("cipher"),
	})
	if err != nil {
		return nil, err
	}
	if ss == nil {
		return nil, errors.New("cannot build shadowsocks client")
	}
	return &ckSSDialer{cfg: cfg, ss: ss}, nil
}

func (d *ckSSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(d.cfg.RemoteHost, strconv.Itoa(d.cfg.RemotePort)))
	if err != nil {
		return nil, err
	}
	cc, err := ckHandshake(ctx, raw, d.cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	md := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DstPort: uint16(port)}
	if ip, err := netip.ParseAddr(host); err == nil {
		md.DstIP = ip
	} else {
		md.Host = host
	}
	c, err := d.ss.StreamConnContext(ctx, cc, md)
	if err != nil {
		cc.Close()
		return nil, err
	}
	return c, nil
}

func (d *ckSSDialer) Close() error {
	return d.ss.Close()
}

func ckSSNode(proto string, opts map[string]string, host string, port int, m map[string]any) (*node, error) {
	cm := map[string]any{}
	for k, v := range opts {
		cm[k] = v
	}
	cfg, err := ckParseConfig(cm, host, port)
	if err != nil {
		return &node{Proto: proto + "+cloak"}, err
	}
	return &node{Proto: proto + "+cloak", Candidates: one(candidate{
		Engine: "cloak+mihomo",
		Debug:  m,
		Build:  func() (Dialer, error) { return newCloakSSDialer(cfg, m) },
	})}, nil
}
