package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	ovpn "github.com/metacubex/mihomo/transport/openvpn"
	"github.com/metacubex/mipstack"
)

var (
	errOvpnNoReply      = errors.New("no reply to OpenVPN hard reset")
	errOvpnStageTimeout = errors.New("OpenVPN handshake timed out")
)

type OpenVpnConnectivityTester struct{}

type ovpnWatchIO struct {
	ovpn.PacketIO
	got   atomic.Bool
	any   atomic.Bool
	first chan struct{}
	once  sync.Once
}

func (w *ovpnWatchIO) ReadPacket() ([]byte, error) {
	b, err := w.PacketIO.ReadPacket()
	if len(b) > 0 {
		w.any.Store(true)
		op := b[0] >> 3
		if op == 7 || op == 8 {
			w.got.Store(true)
			w.once.Do(func() { close(w.first) })
		}
	}
	return b, err
}

type ovpnSess struct {
	cl    *ovpn.Client
	push  *ovpn.PushReply
	err   error
	got   bool
	any   bool
	cause error
	dur   time.Duration
}

func (s *ovpnSess) close() {
	if s != nil && s.cl != nil {
		s.cl.Close()
		s.cl = nil
	}
}

func (OpenVpnConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	p.Engine("mihomo-openvpn")
	m, _ := c.Payload.(*ovpnModel)
	if m == nil || len(m.Remotes) == 0 {
		p.Fail(StageParse, StateInvalid, errors.New("no remote server in config"))
		return
	}
	var best *probe
	bestRank := -1
	var tried []string
	for i, r := range m.Remotes {
		if i > 0 {
			if ctx.Err() != nil {
				break
			}
			if dl, ok := ctx.Deadline(); ok && time.Until(dl) < 1500*time.Millisecond {
				break
			}
		}
		sp := newProbe(p.opt, c)
		sp.ctx = ctx
		sp.res.ID = p.res.ID
		sp.res.Engine = p.res.Engine
		sp.Pass(StageParse)
		ovpnAttempt(ctx, m, r, sp)
		if !sp.failed && (sp.res.Result == StateConnectable || sp.res.Result == StateDataPlaneVerified) {
			if len(m.Remotes) > 1 {
				sp.Note("remote %d/%d %s worked", i+1, len(m.Remotes), r)
				if len(tried) > 0 {
					sp.Note("failed before: %s", strings.Join(tried, "; "))
				}
			}
			ovpnAdopt(p, sp)
			return
		}
		tried = append(tried, r.String()+" "+sp.res.Result)
		if rk := ovpnRank(sp.res.Result); rk > bestRank {
			best, bestRank = sp, rk
		}
	}
	if best == nil {
		p.Fail(StageHandshake, StateHandshakeFailed, context.DeadlineExceeded)
		return
	}
	if len(m.Remotes) > 1 {
		best.Note("tried %d/%d remotes: %s", len(tried), len(m.Remotes), strings.Join(tried, "; "))
	}
	ovpnAdopt(p, best)
}

func ovpnRank(state string) int {
	switch state {
	case StateDNSFailed:
		return 1
	case StateHostUnreachable, StatePortUnreachable:
		return 2
	case StateHandshakeFailed:
		return 3
	case StateAuthFailed:
		return 4
	}
	return 0
}

func ovpnAdopt(p, sp *probe) {
	id := p.res.ID
	*p.res = *sp.res
	p.res.ID = id
	p.res.Ev = "result"
	p.failed = sp.failed
	p.latency = sp.latency
	p.addrs = sp.addrs
}

func ovpnRandomSecret() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ovpnAttempt(ctx context.Context, m *ovpnModel, r ovpnRemote, p *probe) {
	user, pass := "", ""
	dummy := false
	if m.AuthUserPass {
		if m.HasCreds {
			user, pass = m.Username, m.Password
		} else {
			user, pass, dummy = "vpntester", ovpnRandomSecret(), true
		}
	}
	fpMode := len(m.CA) == 0 && len(m.PeerFingerprints) > 0
	cfg, err := ovpnClientConfig(m, r, m.CA, user, pass)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return
	}
	s := ovpnRun(ctx, p, r, cfg)
	if s == nil {
		return
	}
	if fpMode && s.err != nil {
		var uae x509.UnknownAuthorityError
		if errors.As(s.err, &uae) && uae.Cert != nil {
			sum := sha256.Sum256(uae.Cert.Raw)
			fp := hex.EncodeToString(sum[:])
			match := false
			for _, want := range m.PeerFingerprints {
				if want == fp {
					match = true
				}
			}
			if !match {
				if r.Proto == "udp" {
					p.Pass(StageTransport)
				}
				p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("server certificate fingerprint %s does not match peer-fingerprint", fp[:16]))
				return
			}
			leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: uae.Cert.Raw})
			cfg2, err := ovpnClientConfig(m, r, leaf, user, pass)
			if err != nil {
				p.Fail(StageHandshake, StateHandshakeFailed, err)
				return
			}
			p.addrs = nil
			s = ovpnRun(ctx, p, r, cfg2)
			if s == nil {
				return
			}
			p.Note("server verified by peer-fingerprint")
		}
	}
	defer s.close()
	ovpnVerdict(ctx, p, m, r, s, dummy)
}

func ovpnResolve(ctx context.Context, p *probe, host, family string) bool {
	addrs := p.Resolve(ctx, host)
	if addrs == nil {
		return false
	}
	if family == "" {
		return true
	}
	var out []netip.Addr
	for _, a := range addrs {
		if (family == "4") == a.Unmap().Is4() {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		p.Fail(StageDNS, StateDNSFailed, fmt.Errorf("no IPv%s address for %s", family, host))
		return false
	}
	p.addrs = out
	p.res.Address = out[0].String()
	return true
}

func ovpnRun(ctx context.Context, p *probe, r ovpnRemote, cfg *ovpn.ClientConfig) *ovpnSess {
	udp := r.Proto == "udp"
	var pio ovpn.PacketIO
	if udp {
		if !ovpnResolve(ctx, p, r.Host, r.Family) {
			return nil
		}
		uc := p.DialUDP(ctx, r.Host, r.Port)
		if uc == nil {
			return nil
		}
		pio = ovpn.NewDatagramPacketIO(uc)
	} else {
		conn := ovpnDialStream(ctx, p, r)
		if conn == nil {
			return nil
		}
		pio = ovpn.NewTCPPacketIO(conn)
	}
	w := &ovpnWatchIO{PacketIO: pio, first: make(chan struct{})}
	cl, err := ovpn.NewClient(cfg, w)
	if err != nil {
		w.Close()
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return nil
	}
	t := p.opt.Timeouts
	hctx, cancel := context.WithCancelCause(ctx)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		first := time.Duration(t.Handshake) * time.Millisecond
		if udp {
			first = time.Duration(t.Connect) * time.Millisecond
		}
		tm := time.NewTimer(first)
		defer tm.Stop()
		select {
		case <-w.first:
		case <-tm.C:
			cancel(errOvpnNoReply)
			return
		case <-stop:
			return
		}
		tm.Reset(time.Duration(t.Handshake+t.Auth) * time.Millisecond)
		select {
		case <-tm.C:
			cancel(errOvpnStageTimeout)
		case <-stop:
		}
	}()
	start := time.Now()
	push, err := cl.Handshake(hctx)
	close(stop)
	<-done
	s := &ovpnSess{cl: cl, push: push, err: err, got: w.got.Load(), any: w.any.Load(), cause: context.Cause(hctx), dur: time.Since(start)}
	cancel(nil)
	if err != nil {
		cl.Close()
		s.cl = nil
	}
	return s
}

func ovpnIsAuthFailed(err error) bool {
	s := err.Error()
	return strings.Contains(s, "AUTH_FAILED") || strings.Contains(s, "openvpn authentication failed")
}

func ovpnAuthMsg(err error) error {
	s := err.Error()
	if i := strings.Index(s, "AUTH_FAILED"); i >= 0 {
		reason := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s[i:], "AUTH_FAILED"), ","))
		if reason == "" {
			return errors.New("AUTH_FAILED: server rejected username/password")
		}
		return fmt.Errorf("AUTH_FAILED: %s", reason)
	}
	return errors.New("AUTH_FAILED: server rejected credentials")
}

func ovpnTLSAlert(err error) string {
	s := err.Error()
	if i := strings.Index(s, "remote error: tls: "); i >= 0 {
		return s[i+len("remote error: tls: "):]
	}
	return ""
}

func ovpnTLSReason(err error) string {
	var uae x509.UnknownAuthorityError
	if errors.As(err, &uae) {
		return "server certificate is not signed by the CA in the config"
	}
	var cie x509.CertificateInvalidError
	if errors.As(err, &cie) {
		switch cie.Reason {
		case x509.Expired:
			return "server certificate expired or not yet valid"
		case x509.IncompatibleUsage:
			return "server certificate lacks TLS server usage (EKU serverAuth)"
		case x509.NotAuthorizedToSign:
			return "server certificate chain has an issuer that is not a CA"
		}
		return "server certificate invalid: " + cie.Error()
	}
	s := err.Error()
	s = strings.TrimPrefix(s, "openvpn tls handshake: ")
	return "TLS: " + s
}

func ovpnClientCertAlert(alert string) bool {
	switch alert {
	case "bad certificate", "unknown certificate authority", "certificate required", "certificate revoked",
		"expired certificate", "unsupported certificate", "certificate unknown", "access denied", "decrypt error":
		return true
	}
	return false
}

func ovpnVerdict(ctx context.Context, p *probe, m *ovpnModel, r ovpnRemote, s *ovpnSess, dummy bool) {
	udp := r.Proto == "udp"
	authOK := func() {
		p.Pass(StageHandshake)
		if dummy {
			p.Note("%s", m.CredNote)
		} else {
			p.Pass(StageAuth)
		}
	}
	if s.err == nil {
		if udp {
			p.Pass(StageTransport)
		}
		authOK()
		if dummy {
			p.Note("server accepted placeholder credentials")
		}
		if m.VerifyX509 != "" {
			p.Note("verify-x509-name %s not enforced", m.VerifyX509)
		}
		p.Connectable(s.dur)
		if m.CipherUnsupported != "" && s.push != nil && s.push.Cipher == "" && len(s.push.DataCiphers) == 0 {
			p.DataPlaneFail(fmt.Errorf("server did not negotiate a data cipher and %s is not supported", m.CipherUnsupported))
			return
		}
		if !p.WantDataProbe() {
			return
		}
		cl := s.cl
		s.cl = nil
		d, err := ovpnDataProbe(ctx, cl, s.push, m.MTU, p.URLs())
		if err != nil {
			p.DataPlaneFail(err)
			return
		}
		p.DataPlaneOK(d)
		return
	}
	err := s.err
	msg := err.Error()
	if !s.got {
		switch {
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(msg, "connection refused"):
			if udp {
				p.Fail(StageTransport, StatePortUnreachable, errors.New("UDP port unreachable (ICMP)"))
			} else {
				p.Fail(StageTransport, StatePortUnreachable, errors.New("connection refused"))
			}
			return
		case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || strings.Contains(msg, "no route to host") || strings.Contains(msg, "network is unreachable"):
			p.Fail(StageTransport, StateHostUnreachable, err)
			return
		}
		hint := ""
		if len(m.TLSAuth) > 0 || len(m.TLSCrypt) > 0 || len(m.TLSCryptV2) > 0 {
			hint = "; check tls-auth/tls-crypt key"
		}
		if errors.Is(s.cause, context.DeadlineExceeded) || ctx.Err() != nil {
			p.Fail(StageHandshake, StateHandshakeFailed, context.DeadlineExceeded)
			return
		}
		if udp {
			p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("no response to OpenVPN hard reset over UDP%s", hint))
			return
		}
		if errors.Is(s.cause, errOvpnNoReply) {
			p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("no response to OpenVPN hard reset over TCP%s", hint))
			return
		}
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset") {
			what := "server closed the connection without an OpenVPN reply"
			if s.any {
				what = "server replied with non-OpenVPN data"
			}
			p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("%s%s", what, hint))
			return
		}
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return
	}
	if udp {
		p.Pass(StageTransport)
	}
	switch {
	case ovpnIsAuthFailed(err) && strings.Contains(strings.ToLower(msg), "cipher"):
		reason := ovpnAuthMsg(err).Error()
		if m.CipherUnsupported != "" {
			reason += "; config cipher " + m.CipherUnsupported + " is not supported by the userspace client"
		}
		p.Fail(StageHandshake, StateHandshakeFailed, errors.New(strings.TrimPrefix(reason, "AUTH_FAILED: ")))
	case ovpnIsAuthFailed(err) && strings.Contains(msg, "CRV1"):
		p.Pass(StageHandshake)
		p.Connectable(s.dur)
		p.Note("auth not completed: server requires an interactive challenge/OTP (CRV1)")
	case ovpnIsAuthFailed(err):
		p.Pass(StageHandshake)
		if dummy {
			p.Note("%s", m.CredNote)
			p.Connectable(s.dur)
			return
		}
		p.Fail(StageAuth, StateAuthFailed, ovpnAuthMsg(err))
	case strings.Contains(msg, "push reply missing ifconfig"):
		authOK()
		p.Connectable(s.dur)
		p.DataPlaneFail(errors.New("server pushed no tunnel address"))
	case strings.Contains(msg, "negotiate data cipher"):
		authOK()
		p.Connectable(s.dur)
		p.DataPlaneFail(err)
	case ovpnTLSAlert(err) != "":
		alert := ovpnTLSAlert(err)
		if ovpnClientCertAlert(alert) && (len(m.Cert) > 0 || alert == "certificate required") {
			p.Pass(StageHandshake)
			p.Fail(StageAuth, StateAuthFailed, fmt.Errorf("server rejected client certificate: %s", alert))
			return
		}
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("server sent TLS alert: %s", alert))
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "openvpn tls handshake"):
		p.Fail(StageHandshake, StateHandshakeFailed, errors.New(ovpnTLSReason(err)))
	case errors.Is(s.cause, errOvpnStageTimeout) || errors.Is(s.cause, context.DeadlineExceeded) || ctx.Err() != nil:
		hint := "server answered the hard reset but TLS/key exchange did not complete"
		if len(m.Cert) > 0 {
			hint += "; the server may have rejected the client certificate"
		}
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("timeout during handshake: %s", hint))
	case strings.Contains(msg, "server terminated the control session"):
		p.Fail(StageHandshake, StateHandshakeFailed, err)
	default:
		p.Fail(StageHandshake, StateHandshakeFailed, err)
	}
}

type ovpnStackDialer struct {
	st     *mipstack.Stack
	v4, v6 bool
}

func (d *ovpnStackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		res, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		ips = res
	}
	var last error = fmt.Errorf("no address for %s reachable through the tunnel", host)
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() && !d.v4 || !ip.Is4() && !d.v6 {
			continue
		}
		c, err := d.st.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(ip, uint16(pn)))
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (d *ovpnStackDialer) Close() error { return nil }

func ovpnDataProbe(ctx context.Context, cl *ovpn.Client, push *ovpn.PushReply, mtu int, urls []string) (time.Duration, error) {
	defer cl.Close()
	if push == nil || len(push.Prefixes) == 0 {
		return 0, errors.New("server pushed no tunnel address")
	}
	if mtu <= 0 {
		mtu = 1500
	}
	st, err := mipstack.New(mipstack.Config{LocalAddresses: push.Prefixes, MTU: uint32(mtu)})
	if err != nil {
		return 0, fmt.Errorf("ip stack: %w", err)
	}
	if err := st.Start(); err != nil {
		st.Close()
		return 0, fmt.Errorf("ip stack: %w", err)
	}
	lctx, lcancel := context.WithCancel(ctx)
	var loopErr atomic.Pointer[error]
	setErr := func(e error) {
		if e != nil && lctx.Err() == nil {
			loopErr.CompareAndSwap(nil, &e)
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer lcancel()
		buf := make([]byte, 65535)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for lctx.Err() == nil {
			if _, err := st.Read(bufs, sizes, 0); err != nil {
				setErr(err)
				return
			}
			if sizes[0] <= 0 {
				continue
			}
			if err := cl.WriteIPPacket(lctx, buf[:sizes[0]]); err != nil {
				setErr(fmt.Errorf("tunnel write: %w", err))
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer lcancel()
		for lctx.Err() == nil {
			pkt, err := cl.ReadIPPacket(lctx)
			if err != nil {
				setErr(fmt.Errorf("tunnel read: %w", err))
				return
			}
			if _, err := st.Write([][]byte{pkt}, 0); err != nil {
				setErr(err)
				return
			}
		}
	}()
	d := &ovpnStackDialer{st: st}
	for _, pf := range push.Prefixes {
		if pf.Addr().Unmap().Is4() {
			d.v4 = true
		} else {
			d.v6 = true
		}
	}
	dur, err := raceURLs(lctx, d, urls)
	if le := loopErr.Load(); err != nil && le != nil {
		err = *le
	}
	lcancel()
	cl.Close()
	st.Close()
	waited := make(chan struct{})
	go func() {
		wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
	}
	if err != nil && !push.Redirect {
		err = fmt.Errorf("%v (server does not push redirect-gateway)", err)
	}
	return dur, err
}

type ovpnBufConn struct {
	net.Conn
	r io.Reader
}

func (c *ovpnBufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func ovpnDialStream(ctx context.Context, p *probe, r ovpnRemote) net.Conn {
	if r.Proxy == nil {
		if !ovpnResolve(ctx, p, r.Host, r.Family) {
			return nil
		}
		return p.DialTCP(ctx, r.Host, r.Port)
	}
	px := r.Proxy
	if !ovpnResolve(ctx, p, px.Host, "") {
		return nil
	}
	conn := p.DialTCP(ctx, px.Host, px.Port)
	if conn == nil {
		return nil
	}
	sctx, cancel := p.StageCtx(ctx, StageTransport)
	defer cancel()
	if dl, ok := sctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stopWatch := context.AfterFunc(sctx, func() { conn.SetDeadline(time.Now()) })
	var out net.Conn
	var err error
	if px.Kind == "http-proxy" {
		out, err = ovpnHTTPConnect(conn, px, r)
	} else {
		out, err = ovpnSocks5Connect(conn, px, r)
	}
	stopWatch()
	conn.SetDeadline(time.Time{})
	where := px.Kind + " " + net.JoinHostPort(px.Host, strconv.Itoa(px.Port))
	if err != nil {
		conn.Close()
		state := classifyErr(StageTransport, err)
		p.Fail(StageTransport, state, fmt.Errorf("%s: %v", where, err))
		return nil
	}
	p.Note("via %s", where)
	return out
}

func ovpnHTTPConnect(conn net.Conn, px *ovpnProxy, r ovpnRemote) (net.Conn, error) {
	target := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	var b strings.Builder
	b.WriteString("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: OpenVPN\r\n")
	if px.User != "" {
		b.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(px.User+":"+px.Pass)) + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("bad proxy response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, errors.New("407 proxy authentication required")
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("CONNECT rejected: %s", resp.Status)
	}
	if n := br.Buffered(); n > 0 {
		pre, _ := br.Peek(n)
		return &ovpnBufConn{Conn: conn, r: io.MultiReader(bytes.NewReader(append([]byte(nil), pre...)), conn)}, nil
	}
	return conn, nil
}

func ovpnSocks5Connect(conn net.Conn, px *ovpnProxy, r ovpnRemote) (net.Conn, error) {
	methods := []byte{0x00}
	if px.User != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x05 {
		return nil, errors.New("not a SOCKS5 proxy")
	}
	switch hdr[1] {
	case 0x00:
	case 0x02:
		if len(px.User) > 255 || len(px.Pass) > 255 {
			return nil, errors.New("socks credentials too long")
		}
		req := []byte{0x01, byte(len(px.User))}
		req = append(req, px.User...)
		req = append(req, byte(len(px.Pass)))
		req = append(req, px.Pass...)
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, err
		}
		if hdr[1] != 0x00 {
			return nil, errors.New("socks proxy authentication failed")
		}
	default:
		return nil, errors.New("socks proxy requires an unsupported authentication method")
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(r.Host); err == nil {
		if ip.Unmap().Is4() {
			a := ip.Unmap().As4()
			req = append(req, 0x01)
			req = append(req, a[:]...)
		} else {
			a := ip.As16()
			req = append(req, 0x04)
			req = append(req, a[:]...)
		}
	} else {
		if len(r.Host) > 255 {
			return nil, errors.New("host name too long")
		}
		req = append(req, 0x03, byte(len(r.Host)))
		req = append(req, r.Host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(r.Port))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	var rep [4]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return nil, err
	}
	if rep[1] != 0x00 {
		reasons := map[byte]string{1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable", 4: "host unreachable", 5: "connection refused", 6: "TTL expired"}
		if s, ok := reasons[rep[1]]; ok {
			return nil, fmt.Errorf("socks connect: %s", s)
		}
		return nil, fmt.Errorf("socks connect failed (%d)", rep[1])
	}
	skip := 0
	switch rep[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		skip = int(l[0])
	default:
		return nil, errors.New("bad socks reply")
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return nil, err
	}
	return conn, nil
}
