package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type stageFlags struct {
	Parse          *bool `json:"parse"`
	DNS            *bool `json:"dns"`
	Transport      *bool `json:"transport"`
	Handshake      *bool `json:"handshake"`
	Authentication *bool `json:"authentication"`
	DataPlane      *bool `json:"dataPlane"`
}

type TestResult struct {
	Ev            string     `json:"ev"`
	ID            int        `json:"id"`
	Stages        stageFlags `json:"stages"`
	Result        string     `json:"result"`
	Latency       int64      `json:"latency,omitempty"`
	ErrorCode     string     `json:"errorCode,omitempty"`
	ErrorMessage  string     `json:"errorMessage,omitempty"`
	IsConnectable bool       `json:"isConnectable"`
	Engine        string     `json:"engine,omitempty"`
	Note          string     `json:"note,omitempty"`
	Address       string     `json:"address,omitempty"`
}

type probe struct {
	opt     *scanOptions
	cfg     *Config
	res     *TestResult
	start   time.Time
	ctx     context.Context
	addrs   []netip.Addr
	failed  bool
	latency time.Duration
}

func newProbe(opt *scanOptions, c *Config) *probe {
	return &probe{opt: opt, cfg: c, res: &TestResult{Ev: "result", ID: c.ID, Result: StateUnknown}, start: time.Now()}
}

func (p *probe) flag(stage string) **bool {
	s := &p.res.Stages
	switch stage {
	case StageParse:
		return &s.Parse
	case StageDNS:
		return &s.DNS
	case StageTransport:
		return &s.Transport
	case StageHandshake:
		return &s.Handshake
	case StageAuth:
		return &s.Authentication
	case StageDataPlane:
		return &s.DataPlane
	}
	return new(*bool)
}

func (p *probe) Pass(stages ...string) {
	for _, st := range stages {
		v := true
		*p.flag(st) = &v
	}
}

func (p *probe) Failed() bool { return p.failed }

func (p *probe) Elapsed() time.Duration { return time.Since(p.start) }

func (p *probe) Engine(name string) { p.res.Engine = name }

func (p *probe) Note(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	if p.res.Note == "" {
		p.res.Note = s
	} else {
		p.res.Note += "; " + s
	}
}

var stateCodes = map[string]string{
	StateInvalid:         "INVALID",
	StateDNSFailed:       "DNS_FAILED",
	StateHostUnreachable: "HOST_UNREACHABLE",
	StatePortUnreachable: "PORT_UNREACHABLE",
	StateHandshakeFailed: "HANDSHAKE_FAILED",
	StateAuthFailed:      "AUTH_FAILED",
	StateUnsupported:     "UNSUPPORTED",
}

func (p *probe) Fail(stage, state string, err error) {
	v := false
	*p.flag(stage) = &v
	p.failed = true
	p.res.Result = state
	p.res.ErrorCode = stateCodes[state]
	msg := "failed"
	if err != nil {
		msg = shortErr(err)
	}
	if p.ctx != nil && p.ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		p.res.ErrorCode = "TIMEOUT"
		if err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "deadline exceeded") {
			msg = "timeout during " + stage
		}
	}
	p.res.ErrorMessage = msg
}

func (p *probe) FailErr(stage string, err error) {
	p.Fail(stage, classifyErr(stage, err), err)
}

func (p *probe) Unsupported(reason string) {
	p.failed = true
	p.res.Result = StateUnsupported
	p.res.ErrorCode = "UNSUPPORTED"
	p.res.ErrorMessage = reason
}

func (p *probe) Connectable(latency time.Duration) {
	if p.failed {
		return
	}
	p.res.Result = StateConnectable
	if latency <= 0 {
		latency = p.Elapsed()
	}
	p.latency = latency
}

func (p *probe) DataPlaneOK(latency time.Duration) {
	if p.failed {
		return
	}
	p.Pass(StageDataPlane)
	p.res.Result = StateDataPlaneVerified
	if latency > 0 {
		p.latency = latency
	}
}

func (p *probe) DataPlaneFail(err error) {
	v := false
	p.res.Stages.DataPlane = &v
	if err != nil {
		p.Note("data probe: %s", shortErr(err))
	}
}

func (p *probe) StageCtx(ctx context.Context, stage string) (context.Context, context.CancelFunc) {
	t := p.opt.Timeouts
	ms := 0
	switch stage {
	case StageDNS:
		ms = t.DNS
	case StageTransport:
		ms = t.Connect
	case StageHandshake:
		ms = t.Handshake
	case StageAuth:
		ms = t.Auth
	}
	if ms <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
}

func (p *probe) WantDataProbe() bool {
	return p.opt.DataProbe == nil || *p.opt.DataProbe
}

func (p *probe) URLs() []string { return p.opt.URLs }

func (p *probe) Resolve(ctx context.Context, host string) []netip.Addr {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		p.Fail(StageDNS, StateInvalid, errors.New("missing server address"))
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		p.addrs = []netip.Addr{ip.Unmap()}
		p.res.Address = ip.Unmap().String()
		return p.addrs
	}
	sctx, cancel := p.StageCtx(ctx, StageDNS)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(sctx, "ip", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			err = fmt.Errorf("no such host %s", host)
		}
		p.Fail(StageDNS, StateDNSFailed, err)
		return nil
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			out = append(out, ip.Unmap())
		}
	}
	for _, ip := range ips {
		if !ip.Unmap().Is4() {
			out = append(out, ip)
		}
	}
	p.addrs = out
	p.res.Address = out[0].String()
	p.Pass(StageDNS)
	return out
}

func (p *probe) Addr(port int) string {
	if len(p.addrs) == 0 {
		return ""
	}
	return net.JoinHostPort(p.addrs[0].String(), strconv.Itoa(port))
}

func (p *probe) DialTCP(ctx context.Context, host string, port int) net.Conn {
	if len(p.addrs) == 0 && p.Resolve(ctx, host) == nil {
		return nil
	}
	sctx, cancel := p.StageCtx(ctx, StageTransport)
	defer cancel()
	var last error
	var d net.Dialer
	for i, ip := range p.addrs {
		if i >= 2 {
			break
		}
		c, err := d.DialContext(sctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			p.res.Address = ip.String()
			p.Pass(StageTransport)
			return c
		}
		last = err
		if sctx.Err() != nil {
			break
		}
	}
	p.Fail(StageTransport, classifyErr(StageTransport, last), last)
	return nil
}

func (p *probe) ReachTCP(ctx context.Context, host string, port int) bool {
	c := p.DialTCP(ctx, host, port)
	if c == nil {
		return false
	}
	c.Close()
	return true
}

func (p *probe) DialUDP(ctx context.Context, host string, port int) *net.UDPConn {
	if len(p.addrs) == 0 && p.Resolve(ctx, host) == nil {
		return nil
	}
	ua := net.UDPAddrFromAddrPort(netip.AddrPortFrom(p.addrs[0], uint16(port)))
	c, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		p.Fail(StageTransport, classifyErr(StageTransport, err), err)
		return nil
	}
	return c
}

func (p *probe) finish(ctx context.Context) *TestResult {
	r := p.res
	if r.Result == StateUnknown {
		if ctx.Err() != nil {
			p.Fail(StageHandshake, StateHandshakeFailed, context.DeadlineExceeded)
		} else {
			p.Fail(StageHandshake, StateHandshakeFailed, errors.New("tester returned no result"))
		}
	}
	r.IsConnectable = r.Result == StateConnectable || r.Result == StateDataPlaneVerified
	if r.IsConnectable {
		ms := p.latency.Milliseconds()
		if ms < 1 {
			ms = 1
		}
		r.Latency = ms
		r.ErrorCode = ""
		r.ErrorMessage = ""
	}
	return r
}

func classifyErr(stage string, err error) string {
	if err == nil {
		return StateHandshakeFailed
	}
	s := strings.ToLower(err.Error())
	var de *net.DNSError
	switch {
	case errors.As(err, &de) || strings.Contains(s, "no such host") || strings.Contains(s, "server misbehaving"):
		return StateDNSFailed
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(s, "connection refused") || strings.Contains(s, "port unreachable"):
		return StatePortUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || strings.Contains(s, "no route to host") || strings.Contains(s, "network is unreachable") || strings.Contains(s, "host is unreachable"):
		return StateHostUnreachable
	case strings.Contains(s, "auth_failed") || strings.Contains(s, "authentication fail") || strings.Contains(s, "auth failed") || strings.Contains(s, "invalid password") || strings.Contains(s, "wrong password") || strings.Contains(s, "unauthorized") || strings.Contains(s, "407 proxy authentication"):
		return StateAuthFailed
	}
	if stage == StageTransport {
		return StateHostUnreachable
	}
	if stage == StageAuth {
		return StateAuthFailed
	}
	return StateHandshakeFailed
}

type nodeTester struct {
	n *node
}

func (t *nodeTester) Test(ctx context.Context, c *Config, p *probe) {
	if p.Resolve(ctx, c.Host) == nil {
		return
	}
	if !c.UDP && c.Port > 0 {
		if !p.ReachTCP(ctx, c.Host, c.Port) {
			return
		}
	}
	d, engine, err := testNode(ctx, t.n, p.URLs())
	p.Engine(engine)
	if err != nil {
		if errors.Is(err, errRejected) {
			p.Pass(StageHandshake, StageAuth)
			if c.UDP {
				p.Pass(StageTransport)
			}
			p.Connectable(0)
			p.DataPlaneFail(err)
			return
		}
		p.FailErr(StageHandshake, err)
		return
	}
	if c.UDP {
		p.Pass(StageTransport)
	}
	p.Pass(StageHandshake, StageAuth)
	p.Connectable(d)
	p.DataPlaneOK(d)
}

type nodeMeta struct {
	Name      string
	Host      string
	Port      int
	Transport string
	Security  string
	SNI       string
	User      string
	Password  string
	UUID      string
	PublicKey string
	UDP       bool
	Extra     string
}

func newNodeConfig(f *vfile, format string, n *node, err error, m nodeMeta) *Config {
	proto := ""
	if n != nil {
		proto = n.Proto
	}
	c := newConfig(f, format, proto)
	c.Name, c.Host, c.Port = m.Name, m.Host, m.Port
	c.Transport, c.Security, c.SNI = m.Transport, m.Security, m.SNI
	c.Username, c.Password, c.UUID, c.PublicKey = m.User, m.Password, m.UUID, m.PublicKey
	c.UDP, c.Extra = m.UDP || udpProto(proto, m.Transport), m.Extra
	if err != nil {
		if errors.Is(err, errTunnel) {
			c.Status = StateUnsupported
		} else if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "unknown scheme") {
			c.Status = StateUnsupported
		} else {
			c.Status = StateInvalid
		}
		c.Error = shortErr(err)
		return c
	}
	c.Tester = &nodeTester{n: n}
	return c
}

func udpProto(proto, transport string) bool {
	switch strings.ToLower(proto) {
	case "hysteria", "hysteria2", "hy2", "tuic", "juicity", "wireguard", "masque", "quic", "realm":
		return true
	}
	switch strings.ToLower(transport) {
	case "kcp", "mkcp", "quic", "h3", "http3":
		return true
	}
	return false
}

func mihomoMeta(m map[string]any) nodeMeta {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok && v != nil {
				s := strings.TrimSpace(fmt.Sprint(v))
				if s != "" {
					return s
				}
			}
		}
		return ""
	}
	port, _ := strconv.Atoi(str("port"))
	sec := ""
	if b, _ := m["tls"].(bool); b {
		sec = "tls"
	}
	if ro, ok := m["reality-opts"].(map[string]any); ok && len(ro) > 0 {
		sec = "reality"
	}
	typ := strings.ToLower(str("type"))
	switch typ {
	case "hysteria", "hysteria2", "tuic", "anytls", "trojan", "trusttunnel", "juicity":
		if sec == "" {
			sec = "tls"
		}
	}
	netw := str("network")
	if netw == "" {
		netw = "tcp"
	}
	return nodeMeta{
		Name:      str("name"),
		Host:      str("server"),
		Port:      port,
		Transport: netw,
		Security:  sec,
		SNI:       str("servername", "sni", "server-name"),
		User:      str("username"),
		Password:  str("password", "psk", "auth", "auth-str", "auth_str"),
		UUID:      str("uuid"),
		PublicKey: str("public-key"),
		UDP:       udpProto(typ, netw),
	}
}

func mihomoNode(m map[string]any) *node {
	typ := strings.ToLower(fmt.Sprint(m["type"]))
	return &node{Proto: typ, Candidates: []candidate{mihomoCandidate(m)}}
}
