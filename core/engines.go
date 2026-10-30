package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/xtls/xray-core/core"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

type mihomoDialer struct {
	p C.Proxy
}

func newMihomo(m map[string]any) (Dialer, error) {
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	if _, ok := cp["name"]; !ok {
		cp["name"] = "node"
	}
	p, err := adapter.ParseProxy(cp)
	if err != nil {
		return nil, err
	}
	return &mihomoDialer{p: p}, nil
}

func mihomoCandidate(m map[string]any) candidate {
	return candidate{
		Engine: "mihomo",
		Debug:  m,
		Build:  func() (Dialer, error) { return newMihomo(m) },
	}
}

func (d *mihomoDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	md := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DstPort: uint16(port)}
	if ip, err := netip.ParseAddr(host); err == nil {
		md.DstIP = ip
	} else {
		md.Host = host
	}
	return d.p.DialContext(ctx, md)
}

func (d *mihomoDialer) Close() error {
	return d.p.Close()
}

type xrayDialer struct {
	inst *core.Instance
}

func newXray(outbound map[string]any) (Dialer, error) {
	ob := make(map[string]any, len(outbound)+1)
	for k, v := range outbound {
		ob[k] = v
	}
	ob["tag"] = "proxy"
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "none", "access": "none", "error": "none"},
		"outbounds": []any{ob},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	c, err := serial.LoadJSONConfig(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	xrNewMu.Lock()
	inst, err := core.New(c)
	xrNewMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, err
	}
	return &xrayDialer{inst: inst}, nil
}

func xrayCandidate(ob map[string]any) candidate {
	return candidate{
		Engine: "xray",
		Debug:  ob,
		Build:  func() (Dialer, error) { return newXray(ob) },
	}
}

func (d *xrayDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dest, err := xnet.ParseDestination("tcp:" + addr)
	if err != nil {
		return nil, err
	}
	return core.Dial(ctx, d.inst, dest)
}

func (d *xrayDialer) Close() error {
	return d.inst.Close()
}
