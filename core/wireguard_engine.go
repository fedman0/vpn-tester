package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	amneziav3 "github.com/metacubex/amneziawg-go/device"
	amnezia "github.com/metacubex/amneziawg-go/device_v1"
	"github.com/metacubex/mipstack"
	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
)

type wgEndpoint netip.AddrPort

func (e wgEndpoint) ClearSrc()           {}
func (e wgEndpoint) SrcToString() string { return "" }
func (e wgEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e wgEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
func (e wgEndpoint) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e wgEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

type wgBind struct {
	mu        sync.RWMutex
	targets   []netip.AddrPort
	conns     map[netip.AddrPort]*net.UDPConn
	reserved  map[netip.AddrPort][3]byte
	rx        atomic.Int64
	refused   atomic.Int64
	lastSend  atomic.Int64
	rtt       atomic.Int64
	errMu     sync.Mutex
	lastErr   error
	openErr   error
	openFails int
}

func (b *wgBind) setErr(err error) {
	b.errMu.Lock()
	b.lastErr = err
	b.errMu.Unlock()
}

func (b *wgBind) err() (error, error) {
	b.errMu.Lock()
	defer b.errMu.Unlock()
	return b.lastErr, b.openErr
}

func (b *wgBind) openState() (error, int) {
	b.errMu.Lock()
	defer b.errMu.Unlock()
	return b.openErr, b.openFails
}

func wgIsRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "connection refused")
}

func (b *wgBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conns != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	conns := map[netip.AddrPort]*net.UDPConn{}
	var fns []conn.ReceiveFunc
	var actual uint16
	var firstErr error
	fails := 0
	for _, t := range b.targets {
		if _, ok := conns[t]; ok {
			continue
		}
		c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(t))
		if err != nil {
			fails++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_ = c.SetReadBuffer(1 << 20)
		conns[t] = c
		if actual == 0 {
			if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
				actual = uint16(la.Port)
			}
		}
		fns = append(fns, b.receiver(c, t))
	}
	b.errMu.Lock()
	b.openErr = firstErr
	b.openFails = fails
	b.errMu.Unlock()
	if len(conns) == 0 {
		if firstErr == nil {
			firstErr = errors.New("no endpoints")
		}
		return nil, 0, firstErr
	}
	b.conns = conns
	return fns, actual, nil
}

func (b *wgBind) receiver(c *net.UDPConn, t netip.AddrPort) conn.ReceiveFunc {
	ep := wgEndpoint(t)
	res, useRes := b.reserved[t]
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := c.Read(packets[0])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return 0, net.ErrClosed
				}
				if wgIsRefused(err) {
					b.refused.Add(1)
					continue
				}
				b.setErr(err)
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				b.mu.RLock()
				closed := b.conns == nil
				b.mu.RUnlock()
				if closed {
					return 0, net.ErrClosed
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			now := time.Now().UnixNano()
			if b.rx.Add(1) == 1 {
				if ls := b.lastSend.Load(); ls > 0 {
					b.rtt.Store(now - ls)
				}
			}
			if useRes && n > 3 && res != [3]byte{} {
				packets[0][1], packets[0][2], packets[0][3] = 0, 0, 0
			}
			sizes[0] = n
			eps[0] = ep
			return 1, nil
		}
	}
}

func (b *wgBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		c.Close()
	}
	b.conns = nil
	return nil
}

func (b *wgBind) SetMark(mark uint32) error { return nil }

func (b *wgBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(wgEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	t := netip.AddrPort(e)
	b.mu.RLock()
	c := b.conns[t]
	b.mu.RUnlock()
	if c == nil {
		return net.ErrClosed
	}
	res, useRes := b.reserved[t]
	for _, buf := range bufs {
		if useRes && len(buf) > 3 && res != [3]byte{} {
			buf[1], buf[2], buf[3] = res[0], res[1], res[2]
		}
		if _, err := c.Write(buf); err != nil {
			if wgIsRefused(err) {
				b.refused.Add(1)
			} else {
				b.setErr(err)
			}
			return err
		}
	}
	b.lastSend.Store(time.Now().UnixNano())
	return nil
}

func (b *wgBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return wgEndpoint(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), nil
}

func (b *wgBind) BatchSize() int { return 1 }

type wgNullBind struct{}

func (wgNullBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (wgNullBind) Close() error                                         { return nil }
func (wgNullBind) SetMark(mark uint32) error                            { return nil }
func (wgNullBind) Send(bufs [][]byte, ep conn.Endpoint) error           { return nil }
func (wgNullBind) BatchSize() int                                       { return 1 }
func (wgNullBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return wgEndpoint(ap), nil
}

type wgNullTun struct {
	events chan tun.Event
	done   chan struct{}
	once   sync.Once
	mtu    int
}

func newWgNullTun(mtu int) *wgNullTun {
	return &wgNullTun{events: make(chan tun.Event, 1), done: make(chan struct{}), mtu: mtu}
}

func (t *wgNullTun) File() *os.File { return nil }
func (t *wgNullTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-t.done
	return 0, os.ErrClosed
}
func (t *wgNullTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (t *wgNullTun) MTU() (int, error)                            { return t.mtu, nil }
func (t *wgNullTun) Name() (string, error)                        { return "null", nil }
func (t *wgNullTun) Events() <-chan tun.Event                     { return t.events }
func (t *wgNullTun) BatchSize() int                               { return 1 }
func (t *wgNullTun) Close() error {
	t.once.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}
func (t *wgNullTun) up() { t.events <- tun.EventUp }

type wgStackTun struct {
	*mipstack.Stack
	events chan tun.Event
	once   sync.Once
}

func (t *wgStackTun) File() *os.File           { return nil }
func (t *wgStackTun) Events() <-chan tun.Event { return t.events }
func (t *wgStackTun) Close() error {
	t.once.Do(func() { close(t.events) })
	return t.Stack.Close()
}
func (t *wgStackTun) up() { t.events <- tun.EventUp }

type wgDevice interface {
	IpcSet(string) error
	IpcGet() (string, error)
	Close()
}

var wgSilentLogger = &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}

func wgNewDevice(w *wgConf, t tun.Device, b conn.Bind, workers int) wgDevice {
	if w.Amnezia {
		if w.V3 {
			return amneziav3.NewDevice(t, b, wgSilentLogger, workers)
		}
		return amnezia.NewDevice(t, b, wgSilentLogger, workers)
	}
	return device.NewDevice(t, b, wgSilentLogger, workers)
}

func (w *wgConf) deviceUAPI() string {
	var sb strings.Builder
	sb.WriteString("private_key=" + hex.EncodeToString(w.priv[:]) + "\n")
	if w.Amnezia {
		for _, p := range w.AWG {
			sb.WriteString(p.Key + "=" + p.Value + "\n")
		}
	}
	return sb.String()
}

func wgCleanIPCErr(err error) error {
	if err == nil {
		return nil
	}
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	for strings.HasPrefix(s, "IPC error ") {
		i := strings.Index(s, ": ")
		if i < 0 {
			break
		}
		s = s[i+2:]
	}
	s = strings.TrimPrefix(s, "uapi: ")
	if i := strings.Index(s, " IPC error "); i > 0 {
		s = s[:i]
	}
	return errors.New(s)
}

func wgCheckAwgParams(w *wgConf) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("AmneziaWG parameters rejected: %v", r)
		}
	}()
	t := newWgNullTun(1420)
	dev := wgNewDevice(w, t, wgNullBind{}, 1)
	defer dev.Close()
	if e := dev.IpcSet(w.deviceUAPI()); e != nil {
		return fmt.Errorf("AmneziaWG parameters rejected: %v", wgCleanIPCErr(e))
	}
	return nil
}

type wgTarget struct {
	peer *wgPeer
	addr netip.AddrPort
	hex  string
}

type wgSession struct {
	conf    *wgConf
	bind    *wgBind
	dev     wgDevice
	stack   *mipstack.Stack
	targets []*wgTarget
	start   time.Time
}

func (s *wgSession) close() {
	if s.dev != nil {
		s.dev.Close()
	}
	if s.bind != nil {
		s.bind.Close()
	}
}

func (w *wgConf) mtu() int {
	if w.MTU > 0 {
		return w.MTU
	}
	return 1420
}

func wgHostPrefixes(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Addr]bool{}
	for _, p := range in {
		a := p.Addr().Unmap()
		if seen[a] || !a.IsValid() || a.IsUnspecified() {
			continue
		}
		seen[a] = true
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out
}

func (s *wgSession) uapi() string {
	var sb strings.Builder
	sb.WriteString(s.conf.deviceUAPI())
	for _, t := range s.targets {
		p := t.peer
		sb.WriteString("public_key=" + t.hex + "\n")
		if p.hasPSK {
			sb.WriteString("preshared_key=" + hex.EncodeToString(p.psk[:]) + "\n")
		}
		sb.WriteString("endpoint=" + t.addr.String() + "\n")
		sb.WriteString("persistent_keepalive_interval=25\n")
		for _, a := range p.AllowedIPs {
			sb.WriteString("allowed_ip=" + a.String() + "\n")
		}
	}
	return sb.String()
}

type wgPeerStat struct {
	handshake time.Time
	rx        int64
}

func wgParseStats(s string) map[string]wgPeerStat {
	out := map[string]wgPeerStat{}
	cur := ""
	var sec, nsec int64
	flush := func() {
		if cur == "" {
			return
		}
		st := out[cur]
		if sec != 0 || nsec != 0 {
			st.handshake = time.Unix(sec, nsec)
		}
		out[cur] = st
	}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur, sec, nsec = v, 0, 0
			out[cur] = wgPeerStat{}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if cur != "" {
				st := out[cur]
				st.rx, _ = strconv.ParseInt(v, 10, 64)
				out[cur] = st
			}
		}
	}
	flush()
	return out
}

type WireGuardConnectivityTester struct{}

func (WireGuardConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	wgTest(ctx, c, p)
}

type AmneziaWgConnectivityTester struct{}

func (AmneziaWgConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	wgTest(ctx, c, p)
}

func wgResolveOther(ctx context.Context, p *probe, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ip.Unmap(), nil
	}
	sctx, cancel := p.StageCtx(ctx, StageDNS)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(sctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	if len(ips) == 0 {
		return netip.Addr{}, errors.New("no addresses")
	}
	return ips[0], nil
}

type wgTimeoutErr struct{ msg string }

func (e *wgTimeoutErr) Error() string { return e.msg }

func wgTest(ctx context.Context, c *Config, p *probe) {
	w, ok := c.Payload.(*wgConf)
	if !ok || w == nil {
		p.Fail(StageParse, StateInvalid, errors.New("missing WireGuard config"))
		return
	}
	engine := "wireguard-go"
	if w.Amnezia {
		engine = "amneziawg-go"
		if w.V3 {
			engine = "amneziawg-go v3"
		}
	}
	p.Engine(engine)
	addrs := p.Resolve(ctx, c.Host)
	if addrs == nil {
		return
	}
	primary := w.primary()
	s := &wgSession{conf: w, bind: &wgBind{reserved: map[netip.AddrPort][3]byte{}}}
	defer s.close()
	var skipped []string
	for _, peer := range w.Peers {
		if peer.Host == "" {
			continue
		}
		var ip netip.Addr
		if peer == primary {
			ip = addrs[0]
		} else {
			a, err := wgResolveOther(ctx, p, peer.Host)
			if err != nil {
				skipped = append(skipped, peer.Host)
				continue
			}
			ip = a
		}
		ap := netip.AddrPortFrom(ip.Unmap(), uint16(peer.Port))
		s.targets = append(s.targets, &wgTarget{peer: peer, addr: ap, hex: hex.EncodeToString(peer.pub[:])})
		s.bind.targets = append(s.bind.targets, ap)
		if len(peer.Reserved) == 3 && !w.Amnezia {
			s.bind.reserved[ap] = [3]byte{peer.Reserved[0], peer.Reserved[1], peer.Reserved[2]}
		}
	}
	if len(skipped) > 0 {
		p.Note("peer endpoint not resolved: %s", strings.Join(skipped, ", "))
	}
	if len(s.targets) == 0 {
		p.Fail(StageDNS, StateDNSFailed, errors.New("no peer endpoint could be resolved"))
		return
	}
	var up func()
	var td tun.Device
	if locals := wgHostPrefixes(w.Addresses); len(locals) > 0 {
		st, err := mipstack.New(mipstack.Config{LocalAddresses: locals, MTU: uint32(w.mtu())})
		if err == nil {
			err = st.Start()
			if err != nil {
				st.Close()
			}
		}
		if err == nil {
			s.stack = st
			t := &wgStackTun{Stack: st, events: make(chan tun.Event, 1)}
			td, up = t, t.up
		} else {
			p.Note("userspace IP stack unavailable: %s", shortErr(err))
		}
	}
	if td == nil {
		t := newWgNullTun(w.mtu())
		td, up = t, t.up
	}
	s.dev = wgNewDevice(w, td, s.bind, 1)
	if err := s.dev.IpcSet(s.uapi()); err != nil {
		p.Fail(StageParse, StateInvalid, wgCleanIPCErr(err))
		return
	}
	s.start = time.Now()
	up()
	hs, peer, ok := s.waitHandshake(ctx, p)
	if !ok {
		return
	}
	rtt := time.Duration(s.bind.rtt.Load())
	if rtt <= 0 {
		rtt = hs.Sub(s.start)
	}
	p.Pass(StageTransport, StageHandshake, StageAuth)
	p.Connectable(rtt)
	if len(s.targets) > 1 {
		p.Note("handshake with peer %s", net.JoinHostPort(peer.peer.Host, strconv.Itoa(peer.peer.Port)))
	}
	if !p.WantDataProbe() {
		return
	}
	s.dataProbe(ctx, p)
}

func (s *wgSession) waitHandshake(ctx context.Context, p *probe) (time.Time, *wgTarget, bool) {
	hctx, cancel := p.StageCtx(ctx, StageHandshake)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if out, err := s.dev.IpcGet(); err == nil {
			stats := wgParseStats(out)
			for _, t := range s.targets {
				if st, ok := stats[t.hex]; ok && !st.handshake.IsZero() {
					return st.handshake, t, true
				}
			}
		}
		if openErr, fails := s.bind.openState(); openErr != nil && fails >= len(s.targets) {
			p.Fail(StageTransport, classifyErr(StageTransport, openErr), openErr)
			return time.Time{}, nil, false
		}
		if s.bind.refused.Load() > 0 && s.bind.rx.Load() == 0 && len(s.targets) == 1 {
			p.Fail(StageTransport, StatePortUnreachable, fmt.Errorf("server port unreachable (ICMP) at %s", s.targets[0].addr))
			return time.Time{}, nil, false
		}
		select {
		case <-hctx.Done():
			s.failHandshake(p)
			return time.Time{}, nil, false
		case <-tick.C:
		}
	}
}

func (s *wgSession) failHandshake(p *probe) {
	wait := time.Since(s.start).Round(100 * time.Millisecond)
	lastErr, _ := s.bind.err()
	rx := s.bind.rx.Load()
	switch {
	case rx > 0:
		p.Pass(StageTransport)
		hint := "preshared key mismatch?"
		if s.conf.Amnezia {
			hint = "preshared key or AmneziaWG parameters mismatch?"
		}
		err := fmt.Errorf("server replied but the handshake response did not verify (%s)", hint)
		p.Fail(StageHandshake, StateAuthFailed, err)
		p.Fail(StageAuth, StateAuthFailed, err)
	case s.bind.refused.Load() > 0:
		p.Fail(StageTransport, StatePortUnreachable, errors.New("server port unreachable (ICMP)"))
	case lastErr != nil && s.bind.lastSend.Load() == 0:
		p.Fail(StageTransport, classifyErr(StageTransport, lastErr), lastErr)
	default:
		why := "wrong server public key, client key not authorized, or UDP blocked"
		if s.conf.Amnezia {
			why = "wrong keys, AmneziaWG parameters mismatch, or UDP blocked"
		}
		p.Fail(StageHandshake, StateHandshakeFailed, &wgTimeoutErr{fmt.Sprintf("handshake timeout: no response from server in %s (%s)", wait, why)})
	}
}

type wgStackDialer struct {
	stack  *mipstack.Stack
	routes []netip.Prefix
	has4   bool
	has6   bool
	mu     sync.Mutex
	cache  map[string][]netip.Addr
}

func (d *wgStackDialer) routed(ip netip.Addr) bool {
	if ip.Is4() && !d.has4 || !ip.Is4() && !d.has6 {
		return false
	}
	for _, r := range d.routes {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *wgStackDialer) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	d.mu.Lock()
	if v, ok := d.cache[host]; ok {
		d.mu.Unlock()
		return v, nil
	}
	d.mu.Unlock()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	out := append(v4, v6...)
	d.mu.Lock()
	d.cache[host] = out
	d.mu.Unlock()
	return out, nil
}

func (d *wgStackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	ips, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	tried := 0
	for _, ip := range ips {
		if !d.routed(ip) {
			continue
		}
		tried++
		c, err := d.stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(ip, uint16(port)))
		if err == nil {
			return c, nil
		}
		last = err
		if tried >= 2 || ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = fmt.Errorf("%s is not routed by AllowedIPs", host)
	}
	return nil, last
}

func (d *wgStackDialer) Close() error { return nil }

func (s *wgSession) dataProbe(ctx context.Context, p *probe) {
	if s.stack == nil {
		if len(s.conf.Addresses) == 0 {
			p.Note("no Interface Address; data probe skipped")
		} else {
			p.Note("data probe skipped")
		}
		return
	}
	d := &wgStackDialer{stack: s.stack, cache: map[string][]netip.Addr{}}
	for _, a := range wgHostPrefixes(s.conf.Addresses) {
		if a.Addr().Is4() {
			d.has4 = true
		} else {
			d.has6 = true
		}
	}
	for _, t := range s.targets {
		d.routes = append(d.routes, t.peer.AllowedIPs...)
	}
	routed := false
	var lookupErr error
	for _, u := range p.URLs() {
		pu, err := url.Parse(u)
		if err != nil {
			continue
		}
		lctx, cancel := p.StageCtx(ctx, StageDNS)
		ips, err := d.lookup(lctx, pu.Hostname())
		cancel()
		if err != nil {
			lookupErr = err
			continue
		}
		for _, ip := range ips {
			if d.routed(ip) {
				routed = true
				break
			}
		}
		if routed {
			break
		}
	}
	if !routed {
		if lookupErr != nil {
			p.DataPlaneFail(fmt.Errorf("probe host lookup failed: %v", lookupErr))
			return
		}
		p.Note("AllowedIPs do not route the probe URLs; data probe skipped")
		return
	}
	lat, err := raceURLs(ctx, d, p.URLs())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "deadline exceeded") {
			err = errors.New("timeout: no HTTP response through the tunnel")
		}
		p.DataPlaneFail(err)
		return
	}
	p.DataPlaneOK(lat)
}
