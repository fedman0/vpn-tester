package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

func init() {
	buildIKEv1Config = ike1BuildConfig
}

type Ikev1ConnectivityTester struct{}

type ike1Validator struct{}

func (ike1Validator) Validate(c *Config) error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("missing server address")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}
	prm, _ := c.Payload.(*ike1Params)
	if prm == nil {
		return errors.New("missing IKEv1 parameters")
	}
	if prm.cisco && prm.aggressive && strings.TrimSpace(prm.spec.GroupName) == "" && prm.idType == 0 {
		return errors.New("Cisco IPsec profile has no group name")
	}
	return nil
}

func ike1BuildConfig(f *vfile, fs *vfs, s *ikeSpec) *Config {
	proto := "IKEv1"
	switch {
	case s.L2TP:
		proto = "L2TP/IPsec"
	case strings.EqualFold(s.Kind, "cisco"):
		proto = "Cisco IPsec"
	}
	c := newConfig(f, "IPsec", proto)
	c.Name = s.Name
	c.Host = strings.Trim(strings.TrimSpace(s.Host), "[]")
	c.Port = s.Port
	if c.Port == 0 {
		c.Port = 500
	}
	c.Transport = "udp"
	c.UDP = true
	c.Username, c.Password, c.PSK = s.Username, s.Password, s.PSK
	switch {
	case s.GroupName != "":
		c.Extra = "group=" + s.GroupName
	case s.LocalID != "":
		c.Extra = "id=" + s.LocalID
	}
	prm, warns, err := ike1Prepare(s)
	for _, w := range warns {
		c.Warn("%s", w)
	}
	if err != nil {
		c.Status = StateUnsupported
		c.Error = shortErr(err)
		return c
	}
	c.Security = prm.label()
	sum := sha256.Sum256([]byte(s.PSK + "\x00" + s.Password + "\x00" + string(prm.certDER)))
	c.Extra += "|" + c.Security + "|" + hex.EncodeToString(sum[:6])
	if prm.credNote != "" {
		c.Warn("%s", prm.credNote)
	}
	if prm.psk() && s.PSK == "" {
		c.Warn("no pre-shared key: only the IKE negotiation can be tested")
	}
	if prm.xauth && s.Username == "" {
		c.Warn("no XAUTH username: user authentication cannot be tested")
	}
	c.Payload = prm
	c.Tester = &Ikev1ConnectivityTester{}
	c.Validator = ike1Validator{}
	return c
}

func (prm *ike1Params) psk() bool {
	return !prm.sign && !prm.hybrid
}

type ike1Err struct {
	stage   string
	state   string
	msg     string
	timeout bool
}

func (e *ike1Err) Error() string { return e.msg }

func ike1HSErr(format string, args ...any) *ike1Err {
	return &ike1Err{stage: StageHandshake, state: StateHandshakeFailed, msg: fmt.Sprintf(format, args...)}
}

func ike1AuthErr(format string, args ...any) *ike1Err {
	return &ike1Err{stage: StageAuth, state: StateAuthFailed, msg: fmt.Sprintf(format, args...)}
}

type ike1VIDs struct {
	natRFC, natDraft, xauth, unity, dpd, frag bool
}

type ike1Session struct {
	ctx         context.Context
	p           *probe
	c           *Config
	prm         *ike1Params
	raddr       netip.Addr
	port        int
	local       netip.AddrPort
	conn        *net.UDPConn
	conns       []*net.UDPConn
	marker      bool
	buf         []byte
	icky        []byte
	rcky        []byte
	tr          ike1Transform
	hashFn      func() hash.Hash
	dh          ike1DH
	gxi, gxr    []byte
	gxy         []byte
	ni, nr      []byte
	sai, idi    []byte
	idr         []byte
	resp        []ike1Payload
	skeyid, ska []byte
	block       cipher.Block
	bs          int
	iv, p1iv    []byte
	ivs         map[uint32][]byte
	natdType    byte
	natDetected bool
	vids        ike1VIDs
	floated     bool
	answered    bool
	seen        map[[20]byte]bool
	pending     [][]byte
	deferred    [][]byte
	frags       map[uint16]map[byte][]byte
	fragLast    map[uint16]byte
	lastOut     []byte
	lastSend    time.Time
	lastDup     time.Time
	lastIn      [20]byte
	lastInAt    time.Time
	dupResends  int
	rtt         time.Duration
	established bool
	peerUp      bool
	username    string
	password    string
}

func (t *Ikev1ConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	prm, _ := c.Payload.(*ike1Params)
	if prm == nil {
		p.Unsupported("missing IKEv1 parameters")
		return
	}
	p.Engine("ikev1")
	if p.Resolve(ctx, c.Host) == nil {
		return
	}
	port := c.Port
	if port <= 0 {
		port = 500
	}
	conn := p.DialUDP(ctx, c.Host, port)
	if conn == nil {
		return
	}
	s := &ike1Session{ctx: ctx, p: p, c: c, prm: prm, port: port, conn: conn, conns: []*net.UDPConn{conn},
		buf: make([]byte, 65536), seen: map[[20]byte]bool{}, username: c.Username, password: c.Password}
	defer s.close()
	if ra, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		s.raddr = ra.AddrPort().Addr().Unmap()
	}
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		s.local = netip.AddrPortFrom(la.AddrPort().Addr().Unmap(), la.AddrPort().Port())
	}
	s.marker = port == 4500
	s.run()
}

func (s *ike1Session) fail(e *ike1Err) {
	s.p.Fail(e.stage, e.state, errors.New(e.msg))
	if e.timeout {
		s.p.res.ErrorCode = "TIMEOUT"
	}
}

func (s *ike1Session) run() {
	hctx, hcancel := s.p.StageCtx(s.ctx, StageHandshake)
	var e *ike1Err
	if s.prm.aggressive {
		e = s.aggrHandshake(hctx)
	} else {
		e = s.mainHandshake(hctx)
	}
	hcancel()
	if e != nil {
		s.fail(e)
		return
	}
	s.p.Pass(StageHandshake)
	s.p.Note("%s, %s", strings.TrimPrefix(s.prm.label(), "IKEv1 "), s.tr.String())
	if note := s.missingCreds(); note != "" {
		s.p.Note("auth not tested: %s", note)
		s.p.Connectable(s.rtt)
		return
	}
	if err := s.deriveKeys(); err != nil {
		s.fail(ike1HSErr("key derivation failed: %v", err))
		return
	}
	actx, acancel := s.p.StageCtx(s.ctx, StageAuth)
	defer acancel()
	if s.prm.aggressive {
		e = s.aggrAuth(actx)
	} else {
		e = s.mainAuth(actx)
	}
	if e != nil {
		s.fail(e)
		return
	}
	s.established = true
	if s.floated {
		s.p.Note("NAT detected, switched to UDP 4500")
	}
	s.afterPhase1(actx)
}

func (s *ike1Session) missingCreds() string {
	switch {
	case s.prm.psk() && s.prm.spec.PSK == "":
		return "no credentials in file (pre-shared key missing)"
	case s.prm.sign && s.prm.signer == nil:
		if s.prm.credNote != "" {
			return "no credentials in file (" + s.prm.credNote + ")"
		}
		return "no credentials in file (client certificate missing)"
	}
	return ""
}

func (s *ike1Session) close() {
	spi := append(append([]byte{}, s.icky...), s.rcky...)
	switch {
	case (s.established || s.peerUp) && s.block != nil && len(s.rcky) == 8:
		mid := s.newMsgID()
		s.send(s.protect(ike1ExInfo, mid, []ike1Payload{{Type: ike1PlDelete, Body: ike1DeletePayload(spi)}}))
	case len(s.rcky) == 8 && !bytes.Equal(s.rcky, make([]byte, 8)):
		typ := uint16(24)
		if s.prm.sign && s.prm.signer == nil {
			typ = 28
		}
		h := ike1Header{Next: ike1PlNotify, Version: 0x10, Exch: ike1ExInfo, MsgID: s.newMsgID()}
		copy(h.ICookie[:], s.icky)
		copy(h.RCookie[:], s.rcky)
		_, raw := ike1Chain([]ike1Payload{{Type: ike1PlNotify, Body: ike1Notification(1, typ, spi, nil)}})
		h.Length = uint32(ike1HdrLen + len(raw))
		s.send(append(h.marshal(), raw...))
	}
	for _, c := range s.conns {
		c.Close()
	}
}

func (s *ike1Session) newMsgID() uint32 {
	for {
		b := ike1Random(4)
		if v := binary.BigEndian.Uint32(b); v != 0 {
			return v
		}
	}
}

func (s *ike1Session) newCookies() {
	s.icky = ike1Random(8)
	s.rcky = make([]byte, 8)
	s.seen = map[[20]byte]bool{}
	s.frags, s.fragLast = nil, nil
}

func (s *ike1Session) send(b []byte) error {
	out := b
	if s.marker {
		out = append([]byte{0, 0, 0, 0}, b...)
	}
	s.lastOut = b
	s.lastSend = time.Now()
	_, err := s.conn.Write(out)
	return err
}

func (s *ike1Session) recv(deadline time.Time) ([]byte, error) {
	for {
		if len(s.pending) > 0 {
			b := s.pending[0]
			s.pending = s.pending[1:]
			return b, nil
		}
		s.conn.SetReadDeadline(deadline)
		n, err := s.conn.Read(s.buf)
		if err != nil {
			return nil, err
		}
		b := s.buf[:n]
		if s.marker {
			if n < 4 || b[0]|b[1]|b[2]|b[3] != 0 {
				continue
			}
			b = b[4:]
		}
		if len(b) < ike1HdrLen || !bytes.Equal(b[:8], s.icky) {
			continue
		}
		b = append([]byte(nil), b...)
		if !s.answered {
			s.answered = true
			s.p.Pass(StageTransport)
		}
		if b[16] == ike1PlFrag && b[17]>>4 == 1 {
			b = s.reassemble(b)
			if b == nil {
				continue
			}
		}
		sum := sha1.Sum(b)
		if s.seen[sum] {
			if sum == s.lastIn && s.lastOut != nil && s.dupResends < 3 && s.lastSend.After(s.lastInAt) && time.Since(s.lastDup) > 300*time.Millisecond {
				s.lastDup = time.Now()
				s.dupResends++
				s.send(s.lastOut)
			}
			continue
		}
		s.seen[sum] = true
		s.lastIn, s.lastInAt, s.dupResends = sum, time.Now(), 0
		return b, nil
	}
}

func (s *ike1Session) reassemble(b []byte) []byte {
	if len(b) < ike1HdrLen+8 {
		return nil
	}
	pl := b[ike1HdrLen:]
	l := int(binary.BigEndian.Uint16(pl[2:4]))
	if l < 8 || l > len(pl) {
		return nil
	}
	id := binary.BigEndian.Uint16(pl[4:6])
	num := pl[6]
	last := pl[7]&1 != 0
	if num == 0 {
		return nil
	}
	if s.frags == nil {
		s.frags = map[uint16]map[byte][]byte{}
		s.fragLast = map[uint16]byte{}
	}
	m := s.frags[id]
	if m == nil {
		if len(s.frags) > 8 {
			return nil
		}
		m = map[byte][]byte{}
		s.frags[id] = m
	}
	if len(m) > 32 {
		return nil
	}
	m[num] = append([]byte(nil), pl[8:l]...)
	if last {
		s.fragLast[id] = num
	}
	n, ok := s.fragLast[id]
	if !ok {
		return nil
	}
	var out []byte
	for i := byte(1); i <= n; i++ {
		d, ok := m[i]
		if !ok {
			return nil
		}
		out = append(out, d...)
	}
	delete(s.frags, id)
	if len(out) < ike1HdrLen || !bytes.Equal(out[:8], s.icky) {
		return nil
	}
	return out
}

func (s *ike1Session) await(ctx context.Context, out []byte, limit time.Duration, handle func(b []byte, h *ike1Header) (bool, *ike1Err)) *ike1Err {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	if limit > 0 && time.Now().Add(limit).Before(deadline) {
		deadline = time.Now().Add(limit)
	}
	rto := 500 * time.Millisecond
	if out != nil {
		if err := s.send(out); err != nil {
			return s.netErr(err)
		}
	}
	next := time.Now().Add(rto)
	for {
		wait := deadline
		if out != nil && next.Before(wait) {
			wait = next
		}
		b, err := s.recv(wait)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if !time.Now().Before(deadline) || ctx.Err() != nil {
					return &ike1Err{stage: StageHandshake, state: StateHandshakeFailed, msg: "timeout", timeout: true}
				}
				if out != nil {
					if err := s.send(out); err != nil {
						return s.netErr(err)
					}
					rto *= 2
					if rto > 2*time.Second {
						rto = 2 * time.Second
					}
					next = time.Now().Add(rto)
				}
				continue
			}
			return s.netErr(err)
		}
		h, err := ike1ParseHeader(b)
		if err != nil {
			continue
		}
		if h.Version>>4 != 1 {
			if h.Version>>4 == 2 {
				return ike1HSErr("server answered with IKEv2 only (IKEv1 not enabled on this server)")
			}
			continue
		}
		done, e := handle(b, h)
		if e != nil {
			return e
		}
		if done {
			return nil
		}
	}
}

func (s *ike1Session) netErr(err error) *ike1Err {
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "connection refused") {
		return &ike1Err{stage: StageTransport, state: StatePortUnreachable, msg: fmt.Sprintf("UDP port %d unreachable: no IKE service (ICMP port unreachable)", s.port)}
	}
	return &ike1Err{stage: StageTransport, state: classifyErr(StageTransport, err), msg: shortErr(err)}
}

func (s *ike1Session) header(exch, flags byte, mid uint32, next byte, bodyLen int) []byte {
	h := ike1Header{Next: next, Version: 0x10, Exch: exch, Flags: flags, MsgID: mid, Length: uint32(ike1HdrLen + bodyLen)}
	copy(h.ICookie[:], s.icky)
	copy(h.RCookie[:], s.rcky)
	return h.marshal()
}

func (s *ike1Session) plain(exch byte, pls []ike1Payload) []byte {
	first, raw := ike1Chain(pls)
	return append(s.header(exch, 0, 0, first, len(raw)), raw...)
}

func (s *ike1Session) body(b []byte, h *ike1Header) []byte {
	n := int(h.Length)
	if n < ike1HdrLen || n > len(b) {
		n = len(b)
	}
	return b[ike1HdrLen:n]
}

func (s *ike1Session) encP1(exch byte, pls []ike1Payload) []byte {
	first, raw := ike1Chain(pls)
	ct := ike1CBCEncrypt(s.block, s.iv, raw)
	s.iv = append([]byte(nil), ct[len(ct)-s.bs:]...)
	return append(s.header(exch, ike1FlagEnc, 0, first, len(ct)), ct...)
}

func (s *ike1Session) ivFor(mid uint32) []byte {
	if iv, ok := s.ivs[mid]; ok {
		return iv
	}
	return ike1Digest(s.hashFn, s.p1iv, ike1U32(mid))[:s.bs]
}

func ike1U32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func (s *ike1Session) protect(exch byte, mid uint32, pls []ike1Payload) []byte {
	first, raw := ike1Chain(pls)
	sum := ike1PRF(s.hashFn, s.ska, ike1U32(mid), raw)
	pt := make([]byte, 4, 4+len(sum)+len(raw))
	pt[0] = first
	binary.BigEndian.PutUint16(pt[2:], uint16(4+len(sum)))
	pt = append(pt, sum...)
	pt = append(pt, raw...)
	ct := ike1CBCEncrypt(s.block, s.ivFor(mid), pt)
	s.ivs[mid] = append([]byte(nil), ct[len(ct)-s.bs:]...)
	return append(s.header(exch, ike1FlagEnc, mid, ike1PlHash, len(ct)), ct...)
}

func (s *ike1Session) unprotect(b []byte, h *ike1Header) ([]ike1Payload, error) {
	if s.block == nil || s.p1iv == nil {
		return nil, errors.New("no keys")
	}
	ct := s.body(b, h)
	pt, err := ike1CBCDecrypt(s.block, s.ivFor(h.MsgID), ct)
	if err != nil {
		return nil, err
	}
	pls, err := ike1ParsePayloads(h.Next, pt)
	if err != nil {
		return nil, err
	}
	if len(pls) == 0 || pls[0].Type != ike1PlHash {
		return nil, errors.New("missing HASH payload")
	}
	end := 0
	for _, p := range pls {
		end += len(p.Raw)
	}
	want := ike1PRF(s.hashFn, s.ska, ike1U32(h.MsgID), pt[len(pls[0].Raw):end])
	if !hmac.Equal(want, pls[0].Body) {
		return nil, errors.New("HASH mismatch")
	}
	s.ivs[h.MsgID] = append([]byte(nil), ct[len(ct)-s.bs:]...)
	return pls[1:], nil
}

func (s *ike1Session) vidPayloads() []ike1Payload {
	v := [][]byte{ike1VIDNatRFC, ike1VIDNat03, ike1VIDNat02n, ike1VIDNat02, ike1VIDDPD, ike1VIDFragFull}
	if s.prm.xauth {
		v = append(v, ike1VIDXauth)
	}
	if s.prm.cisco {
		v = append(v, ike1VIDUnity)
	}
	out := make([]ike1Payload, 0, len(v))
	for _, b := range v {
		out = append(out, ike1Payload{Type: ike1PlVID, Body: b})
	}
	return out
}

func (s *ike1Session) recordVIDs(pls []ike1Payload) {
	for _, p := range ike1FindAll(pls, ike1PlVID) {
		b := p.Body
		switch {
		case bytes.Equal(b, ike1VIDNatRFC):
			s.vids.natRFC = true
		case bytes.Equal(b, ike1VIDNat02), bytes.Equal(b, ike1VIDNat02n), bytes.Equal(b, ike1VIDNat03):
			s.vids.natDraft = true
		case bytes.Equal(b, ike1VIDXauth):
			s.vids.xauth = true
		case bytes.HasPrefix(b, ike1VIDUnity[:14]):
			s.vids.unity = true
		case bytes.HasPrefix(b, ike1VIDDPD[:14]):
			s.vids.dpd = true
		case bytes.HasPrefix(b, ike1VIDFrag):
			s.vids.frag = true
		}
	}
	switch {
	case s.vids.natRFC:
		s.natdType = ike1PlNATD
	case s.vids.natDraft:
		s.natdType = ike1PlNATDOld
	}
}

func (s *ike1Session) natHash(ap netip.AddrPort) []byte {
	return ike1Digest(s.hashFn, s.icky, s.rcky, ap.Addr().Unmap().AsSlice(), []byte{byte(ap.Port() >> 8), byte(ap.Port())})
}

func (s *ike1Session) natdPayloads() []ike1Payload {
	if s.natdType == 0 || s.hashFn == nil {
		return nil
	}
	remote := netip.AddrPortFrom(s.raddr, uint16(s.port))
	return []ike1Payload{{Type: s.natdType, Body: s.natHash(remote)}, {Type: s.natdType, Body: s.natHash(s.local)}}
}

func (s *ike1Session) checkNAT(pls []ike1Payload) {
	var nd []ike1Payload
	for _, p := range pls {
		if p.Type == ike1PlNATD || p.Type == ike1PlNATDOld {
			nd = append(nd, p)
		}
	}
	if len(nd) < 2 {
		return
	}
	if s.natdType == 0 {
		s.natdType = nd[0].Type
	}
	me := !bytes.Equal(nd[0].Body, s.natHash(s.local))
	peer := true
	remote := s.natHash(netip.AddrPortFrom(s.raddr, uint16(s.port)))
	for _, p := range nd[1:] {
		if bytes.Equal(p.Body, remote) {
			peer = false
		}
	}
	s.natDetected = me || peer
}

func (s *ike1Session) float() {
	if !s.natDetected || s.marker || s.floated || s.natdType == 0 {
		return
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.raddr, 4500)))
	if err != nil {
		return
	}
	s.conns = append(s.conns, c)
	s.conn = c
	s.marker = true
	s.floated = true
}

func (s *ike1Session) idBody() []byte {
	typ, data := s.prm.idType, s.prm.idData
	if typ == 0 {
		a := s.local.Addr()
		if a.Is4() {
			typ = ike1IDIPv4
		} else {
			typ = ike1IDIPv6
		}
		data = a.AsSlice()
	}
	return append([]byte{typ, 17, 0x01, 0xf4}, data...)
}

func (s *ike1Session) crPayloads() []ike1Payload {
	if len(s.prm.caDNs) == 0 {
		return []ike1Payload{{Type: ike1PlCR, Body: []byte{4}}}
	}
	var out []ike1Payload
	for _, dn := range s.prm.caDNs {
		out = append(out, ike1Payload{Type: ike1PlCR, Body: append([]byte{4}, dn...)})
	}
	return out
}

func ike1PlainNotify(b []byte, h *ike1Header) *ike1Notify {
	if h.Exch != ike1ExInfo || h.Flags&ike1FlagEnc != 0 {
		return nil
	}
	n := int(h.Length)
	if n < ike1HdrLen || n > len(b) {
		n = len(b)
	}
	pls, _ := ike1ParsePayloads(h.Next, b[ike1HdrLen:n])
	for _, p := range pls {
		if p.Type == ike1PlNotify {
			if nt, err := ike1ParseNotify(p.Body); err == nil {
				return &nt
			}
		}
	}
	if ike1Find(pls, ike1PlDelete) != nil {
		return &ike1Notify{Type: ike1NotifyDeleted}
	}
	return nil
}

func ike1NotifyText(n *ike1Notify) string {
	s := ike1NotifyName(n.Type)
	if len(n.Data) > 0 && len(n.Data) < 200 {
		ok := true
		for _, c := range n.Data {
			if c < 0x20 || c > 0x7e {
				ok = false
				break
			}
		}
		if ok {
			s += " (" + string(n.Data) + ")"
		}
	}
	return s
}

func ike1IsProposalReject(t uint16) bool {
	switch t {
	case 12, 13, 14, 15, 17:
		return true
	}
	return false
}

func (s *ike1Session) setTransform(tr ike1Transform) *ike1Err {
	if tr.Enc == ike1EncAES && tr.KeyLen == 0 {
		tr.KeyLen = 128
	}
	if ike1HashFn(tr.Hash) == nil || ike1EncKeyBytes(tr.Enc, tr.KeyLen) == 0 || !ike1GroupSupported(tr.Group) {
		return ike1HSErr("server selected unsupported transform %s (auth %d)", tr.String(), tr.Auth)
	}
	if tr.Auth != 0 && tr.Auth != s.prm.auth {
		return ike1HSErr("server selected authentication method %d, offered %d", tr.Auth, s.prm.auth)
	}
	s.tr = tr
	s.hashFn = ike1HashFn(tr.Hash)
	return nil
}

func (s *ike1Session) mainHandshake(ctx context.Context) *ike1Err {
	chunks := s.prm.mmProposals()
	var rejected []string
	offered := 0
	for i, trs := range chunks {
		if i > 0 && ctx.Err() != nil {
			break
		}
		s.newCookies()
		s.sai = ike1BuildSA(trs)
		msg := s.plain(ike1ExMain, append([]ike1Payload{{Type: ike1PlSA, Body: s.sai}}, s.vidPayloads()...))
		reject := ""
		var limit time.Duration
		if i > 0 {
			limit = 3 * time.Second
		}
		var chosen ike1Transform
		e := s.await(ctx, msg, limit, func(b []byte, h *ike1Header) (bool, *ike1Err) {
			if n := ike1PlainNotify(b, h); n != nil {
				if ike1IsProposalReject(n.Type) {
					reject = ike1NotifyText(n)
					return true, nil
				}
				if n.Type < 8192 {
					return true, ike1HSErr("server refused phase 1: %s", ike1NotifyText(n))
				}
				return false, nil
			}
			if h.Exch != ike1ExMain || h.Flags&ike1FlagEnc != 0 {
				return false, nil
			}
			pls, err := ike1ParsePayloads(h.Next, s.body(b, h))
			sa := ike1Find(pls, ike1PlSA)
			if err != nil || sa == nil {
				return false, nil
			}
			tr, err := ike1ParseSA(sa.Body)
			if err != nil {
				return true, ike1HSErr("malformed SA in server reply: %v", err)
			}
			s.rtt = time.Since(s.lastSend)
			copy(s.rcky, h.RCookie[:])
			chosen = tr
			s.recordVIDs(pls)
			return true, nil
		})
		offered += len(trs)
		if e != nil {
			if e.timeout {
				if len(rejected) > 0 {
					return ike1HSErr("%s: server rejected %d offered IKEv1 proposals (auth %s)", rejected[0], offered-len(trs), ike1AuthName(s.prm.auth))
				}
				return &ike1Err{stage: StageHandshake, state: StateHandshakeFailed, msg: fmt.Sprintf("no response from IKE server on UDP %d (main mode)", s.port), timeout: true}
			}
			return e
		}
		if reject == "" {
			return s.mainKE(ctx, chosen)
		}
		rejected = append(rejected, reject)
	}
	r := "NO-PROPOSAL-CHOSEN"
	if len(rejected) > 0 {
		r = rejected[0]
	}
	return ike1HSErr("%s: server rejected all %d offered IKEv1 proposals (auth %s)", r, offered, ike1AuthName(s.prm.auth))
}

func ike1AuthName(a uint16) string {
	switch a {
	case ike1AuthPSK:
		return "PSK"
	case ike1AuthRSA:
		return "RSA"
	case ike1AuthXPSK:
		return "XAUTH-PSK"
	case ike1AuthXRSA:
		return "XAUTH-RSA"
	case ike1AuthHyb:
		return "hybrid-RSA"
	}
	return fmt.Sprint(a)
}

func (s *ike1Session) mainKE(ctx context.Context, tr ike1Transform) *ike1Err {
	if e := s.setTransform(tr); e != nil {
		return e
	}
	dh, err := ike1NewDH(s.tr.Group)
	if err != nil {
		return ike1HSErr("%v", err)
	}
	s.dh, s.gxi, s.ni = dh, dh.Public(), ike1Random(32)
	pls := []ike1Payload{{Type: ike1PlKE, Body: s.gxi}, {Type: ike1PlNonce, Body: s.ni}}
	if s.prm.sign || s.prm.hybrid {
		pls = append(pls, s.crPayloads()...)
	}
	pls = append(pls, s.natdPayloads()...)
	msg := s.plain(ike1ExMain, pls)
	e := s.await(ctx, msg, 0, func(b []byte, h *ike1Header) (bool, *ike1Err) {
		if n := ike1PlainNotify(b, h); n != nil {
			if n.Type < 8192 {
				return true, ike1HSErr("server refused key exchange: %s", ike1NotifyText(n))
			}
			return false, nil
		}
		if h.Exch != ike1ExMain || h.Flags&ike1FlagEnc != 0 {
			return false, nil
		}
		rp, err := ike1ParsePayloads(h.Next, s.body(b, h))
		ke, nonce := ike1Find(rp, ike1PlKE), ike1Find(rp, ike1PlNonce)
		if err != nil || ke == nil || nonce == nil {
			return false, nil
		}
		s.gxr, s.nr, s.resp = ke.Body, nonce.Body, rp
		s.recordVIDs(rp)
		return true, nil
	})
	if e != nil {
		if e.timeout {
			return &ike1Err{stage: StageHandshake, state: StateHandshakeFailed, msg: "no reply to key exchange (main mode message 3)", timeout: true}
		}
		return e
	}
	gxy, err := dh.Shared(s.gxr)
	if err != nil {
		return ike1HSErr("DH exchange failed: %v", err)
	}
	s.gxy = gxy
	s.checkNAT(s.resp)
	return nil
}

func (s *ike1Session) aggrHandshake(ctx context.Context) *ike1Err {
	var rejected []string
	firstReject := ""
	answered := false
	tried := 0
	for _, g := range s.prm.amGroups() {
		if tried > 0 && (ctx.Err() != nil || tried >= 6) {
			break
		}
		dh, err := ike1NewDH(g)
		if err != nil {
			continue
		}
		tried++
		s.newCookies()
		s.dh, s.gxi, s.ni = dh, dh.Public(), ike1Random(32)
		trs := s.prm.amTransforms(g)
		s.sai = ike1BuildSA(trs)
		s.idi = s.idBody()
		pls := []ike1Payload{{Type: ike1PlSA, Body: s.sai}, {Type: ike1PlKE, Body: s.gxi}, {Type: ike1PlNonce, Body: s.ni}, {Type: ike1PlID, Body: s.idi}}
		if s.prm.sign || s.prm.hybrid {
			pls = append(pls, s.crPayloads()...)
		}
		pls = append(pls, s.vidPayloads()...)
		msg := s.plain(ike1ExAggr, pls)
		var limit time.Duration
		if tried > 1 {
			limit = 2500 * time.Millisecond
		}
		reject := ""
		var chosen ike1Transform
		e := s.await(ctx, msg, limit, func(b []byte, h *ike1Header) (bool, *ike1Err) {
			if n := ike1PlainNotify(b, h); n != nil {
				if ike1IsProposalReject(n.Type) {
					reject = ike1NotifyText(n)
					return true, nil
				}
				if n.Type == 18 || n.Type == 24 {
					return true, ike1AuthErr("server rejected our identity %s: %s", s.idString(), ike1NotifyText(n))
				}
				if n.Type < 8192 {
					return true, ike1HSErr("server refused aggressive mode: %s", ike1NotifyText(n))
				}
				return false, nil
			}
			if h.Exch != ike1ExAggr || h.Flags&ike1FlagEnc != 0 {
				return false, nil
			}
			rp, err := ike1ParsePayloads(h.Next, s.body(b, h))
			sa, ke, nonce := ike1Find(rp, ike1PlSA), ike1Find(rp, ike1PlKE), ike1Find(rp, ike1PlNonce)
			if err != nil || sa == nil || ke == nil || nonce == nil {
				return false, nil
			}
			tr, err := ike1ParseSA(sa.Body)
			if err != nil {
				return true, ike1HSErr("malformed SA in server reply: %v", err)
			}
			s.rtt = time.Since(s.lastSend)
			copy(s.rcky, h.RCookie[:])
			chosen = tr
			s.gxr, s.nr, s.resp = ke.Body, nonce.Body, rp
			s.recordVIDs(rp)
			return true, nil
		})
		if e != nil {
			if e.timeout {
				if answered || len(rejected) > 0 {
					return ike1HSErr("%s: server rejected aggressive mode proposals for DH %s and did not answer for %s (auth %s)", firstReject, strings.Join(rejected, ", "), ike1GroupName(g), ike1AuthName(s.prm.auth))
				}
				return &ike1Err{stage: StageHandshake, state: StateHandshakeFailed, msg: fmt.Sprintf("no response from IKE server on UDP %d (aggressive mode, group %s)", s.port, s.groupID()), timeout: true}
			}
			return e
		}
		answered = true
		if reject != "" {
			rejected = append(rejected, ike1GroupName(g))
			firstReject = firstNonEmpty(firstReject, reject)
			continue
		}
		if chosen.Group != 0 && chosen.Group != g {
			return ike1HSErr("server selected DH group %d but aggressive mode offered %d", chosen.Group, g)
		}
		chosen.Group = g
		if e := s.setTransform(chosen); e != nil {
			return e
		}
		gxy, err := dh.Shared(s.gxr)
		if err != nil {
			return ike1HSErr("DH exchange failed: %v", err)
		}
		s.gxy = gxy
		return nil
	}
	if len(rejected) > 0 {
		return ike1HSErr("%s: server rejected all aggressive mode proposals, DH %s (auth %s)", firstReject, strings.Join(rejected, ", "), ike1AuthName(s.prm.auth))
	}
	return ike1HSErr("no usable DH group for aggressive mode")
}

func (s *ike1Session) idString() string {
	if len(s.idi) < 4 {
		return ""
	}
	d := s.idi[4:]
	switch s.idi[0] {
	case ike1IDIPv4, ike1IDIPv6:
		if a, ok := netip.AddrFromSlice(d); ok {
			return a.String()
		}
	case ike1IDDN:
		return "(certificate DN)"
	}
	return fmt.Sprintf("%q", string(d))
}

func (s *ike1Session) groupID() string {
	if s.prm.cisco && s.prm.spec.GroupName != "" {
		return fmt.Sprintf("%q", s.prm.spec.GroupName)
	}
	return s.idString()
}

func (s *ike1Session) deriveKeys() error {
	h := s.hashFn
	nn := append(append([]byte{}, s.ni...), s.nr...)
	if s.prm.psk() {
		s.skeyid = ike1PRF(h, []byte(s.prm.spec.PSK), nn)
	} else {
		s.skeyid = ike1PRF(h, nn, s.gxy)
	}
	d := ike1PRF(h, s.skeyid, s.gxy, s.icky, s.rcky, []byte{0})
	s.ska = ike1PRF(h, s.skeyid, d, s.gxy, s.icky, s.rcky, []byte{1})
	e := ike1PRF(h, s.skeyid, s.ska, s.gxy, s.icky, s.rcky, []byte{2})
	kl := ike1EncKeyBytes(s.tr.Enc, s.tr.KeyLen)
	key := e
	if len(key) < kl {
		k := ike1PRF(h, e, []byte{0})
		key = append([]byte{}, k...)
		for len(key) < kl {
			k = ike1PRF(h, e, k)
			key = append(key, k...)
		}
	}
	block, err := ike1NewCipher(s.tr.Enc, key[:kl])
	if err != nil {
		return err
	}
	s.block, s.bs = block, block.BlockSize()
	s.iv = ike1Digest(h, s.gxi, s.gxr)[:s.bs]
	s.ivs = map[uint32][]byte{}
	return nil
}

func (s *ike1Session) hashI() []byte {
	return ike1PRF(s.hashFn, s.skeyid, s.gxi, s.gxr, s.icky, s.rcky, s.sai, s.idi)
}

func (s *ike1Session) hashR() []byte {
	return ike1PRF(s.hashFn, s.skeyid, s.gxr, s.gxi, s.rcky, s.icky, s.sai, s.idr)
}

func (s *ike1Session) proofPayloads() ([]ike1Payload, *ike1Err) {
	hi := s.hashI()
	if !s.prm.sign {
		return []ike1Payload{{Type: ike1PlHash, Body: hi}}, nil
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.prm.signer, crypto.Hash(0), hi)
	if err != nil {
		return nil, ike1AuthErr("signing failed: %v", err)
	}
	return []ike1Payload{{Type: ike1PlCert, Body: append([]byte{4}, s.prm.certDER...)}, {Type: ike1PlSig, Body: sig}}, nil
}

func (s *ike1Session) mainAuth(ctx context.Context) *ike1Err {
	s.float()
	s.idi = s.idBody()
	proof, pe := s.proofPayloads()
	if pe != nil {
		return pe
	}
	msg := s.encP1(ike1ExMain, append([]ike1Payload{{Type: ike1PlID, Body: s.idi}}, proof...))
	sentIV := s.iv
	var got []ike1Payload
	what := "pre-shared key"
	if s.prm.sign {
		what = "client certificate"
	}
	if s.prm.hybrid {
		what = "server certificate/hybrid setup"
	}
	e := s.await(ctx, msg, 0, func(b []byte, h *ike1Header) (bool, *ike1Err) {
		if n := ike1PlainNotify(b, h); n != nil {
			if n.Type >= 8192 {
				return false, nil
			}
			if n.Type == 18 {
				return true, ike1AuthErr("server rejected our identity %s: %s", s.idString(), ike1NotifyText(n))
			}
			return true, ike1AuthErr("server rejected our encrypted identity proof (%s): %s wrong", ike1NotifyText(n), what)
		}
		if h.Flags&ike1FlagEnc == 0 {
			return false, nil
		}
		if h.MsgID != 0 {
			if h.Exch == ike1ExInfo {
				s.p1iv = sentIV
				pls, err := s.unprotect(b, h)
				s.p1iv = nil
				if err != nil {
					return true, ike1AuthErr("server answered with an encrypted error we cannot decrypt: keys differ, %s wrong", what)
				}
				for _, p := range ike1FindAll(pls, ike1PlNotify) {
					if n, err := ike1ParseNotify(p.Body); err == nil && n.Type < 8192 {
						return true, ike1AuthErr("server rejected our identity proof: %s", ike1NotifyText(&n))
					}
				}
				return false, nil
			}
			s.deferred = append(s.deferred, b)
			return false, nil
		}
		if h.Exch != ike1ExMain {
			return false, nil
		}
		ct := s.body(b, h)
		pt, err := ike1CBCDecrypt(s.block, s.iv, ct)
		if err != nil {
			return true, ike1AuthErr("server's encrypted identity reply is malformed: %v", err)
		}
		pls, err := ike1ParsePayloads(h.Next, pt)
		if err != nil || ike1Find(pls, ike1PlID) == nil {
			return true, ike1AuthErr("server's encrypted identity reply could not be decrypted: %s mismatch", what)
		}
		s.iv = append([]byte(nil), ct[len(ct)-s.bs:]...)
		got = pls
		return true, nil
	})
	if e != nil {
		if e.timeout {
			msg := fmt.Sprintf("no valid reply to our encrypted identity (main mode message 5): %s most likely wrong (the server drops what it cannot decrypt)", what)
			if s.floated {
				msg += ", or UDP 4500 is blocked"
			}
			return ike1AuthErr("%s", msg)
		}
		return e
	}
	s.p1iv, s.peerUp = s.iv, true
	return s.verifyResponder(got)
}

func (s *ike1Session) verifyResponder(pls []ike1Payload) *ike1Err {
	id := ike1Find(pls, ike1PlID)
	if id == nil {
		return ike1AuthErr("server reply has no identity payload")
	}
	s.idr = id.Body
	hr := s.hashR()
	if s.prm.sign || s.prm.hybrid {
		return s.verifySig(pls, hr)
	}
	hp := ike1Find(pls, ike1PlHash)
	if hp == nil {
		return ike1AuthErr("server reply has no HASH_R payload")
	}
	if !hmac.Equal(hp.Body, hr) {
		if s.prm.aggressive && s.prm.cisco {
			return ike1AuthErr("HASH_R mismatch: group password (PSK) is wrong or group %q unknown", s.prm.spec.GroupName)
		}
		return ike1AuthErr("HASH_R mismatch: pre-shared key is wrong")
	}
	return nil
}

func (s *ike1Session) verifySig(pls []ike1Payload, hr []byte) *ike1Err {
	sig := ike1Find(pls, ike1PlSig)
	if sig == nil {
		return ike1AuthErr("server reply has no signature payload")
	}
	var certs []*x509.Certificate
	for _, cp := range ike1FindAll(pls, ike1PlCert) {
		if len(cp.Body) > 1 && cp.Body[0] == 4 {
			if c, err := x509.ParseCertificate(cp.Body[1:]); err == nil {
				certs = append(certs, c)
			}
		}
	}
	if len(certs) == 0 {
		s.p.Note("server sent no certificate, signature not verified")
		return nil
	}
	var leaf *x509.Certificate
	for _, c := range certs {
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && rsa.VerifyPKCS1v15(pub, crypto.Hash(0), hr, sig.Body) == nil {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return ike1AuthErr("server signature (SIG_R) does not verify with its certificate %q", certs[0].Subject.CommonName)
	}
	if s.prm.caPool != nil {
		inter := x509.NewCertPool()
		for _, c := range certs {
			if c != leaf {
				inter.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: s.prm.caPool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return ike1AuthErr("server certificate %q is not trusted by the profile CA: %v", leaf.Subject.CommonName, err)
		}
	}
	s.p.Note("server certificate %q", leaf.Subject.CommonName)
	return nil
}

func (s *ike1Session) aggrAuth(ctx context.Context) *ike1Err {
	if e := s.verifyResponder(s.resp); e != nil {
		return e
	}
	s.checkNAT(s.resp)
	s.float()
	proof, pe := s.proofPayloads()
	if pe != nil {
		return pe
	}
	msg := s.encP1(ike1ExAggr, append(proof, s.natdPayloads()...))
	s.p1iv = s.iv
	if err := s.send(msg); err != nil {
		return s.netErr(err)
	}
	return nil
}

func (s *ike1Session) afterPhase1(ctx context.Context) {
	s.pending = append(s.pending, s.deferred...)
	s.deferred = nil
	if !s.prm.xauth {
		if s.prm.aggressive {
			if e := s.drainErrors(ctx, 800*time.Millisecond); e != nil {
				s.fail(e)
				return
			}
		}
		s.p.Pass(StageAuth)
		if s.prm.l2tp {
			s.p.Note("L2TP/PPP login not tested")
		}
		s.p.Connectable(s.rtt)
		return
	}
	if s.username == "" {
		s.p.Note("auth not tested: no credentials in file (XAUTH username missing, %s verified)", s.proofName())
		s.p.Connectable(s.rtt)
		return
	}
	e := s.xauth(ctx)
	if e != nil {
		s.fail(e)
		return
	}
	s.p.Pass(StageAuth)
	if s.prm.l2tp {
		s.p.Note("L2TP/PPP login not tested")
	}
	s.p.Connectable(s.rtt)
}

func (s *ike1Session) proofName() string {
	switch {
	case s.prm.hybrid:
		return "server certificate"
	case s.prm.sign:
		return "certificate"
	case s.prm.cisco:
		return "group PSK"
	}
	return "PSK"
}

func (s *ike1Session) protectedErr(b []byte, h *ike1Header, during string) (bool, *ike1Err) {
	pls, err := s.unprotect(b, h)
	if err != nil {
		return false, nil
	}
	for _, p := range ike1FindAll(pls, ike1PlNotify) {
		if n, err := ike1ParseNotify(p.Body); err == nil && n.Type < 8192 {
			return true, ike1AuthErr("server error %s: %s", during, ike1NotifyText(&n))
		}
	}
	if ike1Find(pls, ike1PlDelete) != nil {
		return true, ike1AuthErr("server deleted the IKE SA %s", during)
	}
	return false, nil
}

func (s *ike1Session) drainErrors(ctx context.Context, d time.Duration) *ike1Err {
	e := s.await(ctx, nil, d, func(b []byte, h *ike1Header) (bool, *ike1Err) {
		if n := ike1PlainNotify(b, h); n != nil && n.Type < 8192 {
			return true, ike1AuthErr("server rejected our HASH_I: %s", ike1NotifyText(n))
		}
		if h.Flags&ike1FlagEnc != 0 && h.MsgID != 0 && h.Exch == ike1ExInfo {
			return s.protectedErr(b, h, "after phase 1")
		}
		if h.Flags&ike1FlagEnc != 0 && h.MsgID != 0 {
			s.deferred = append(s.deferred, b)
		}
		return false, nil
	})
	s.pending = append(s.pending, s.deferred...)
	s.deferred = nil
	if e != nil && !e.timeout {
		return e
	}
	return nil
}

func (s *ike1Session) xauthReply(req ike1Cfg) ([]byte, string) {
	var attrs [][]byte
	for _, a := range req.Attrs {
		switch a.Type {
		case ike1XType:
			if a.Uint() != 0 {
				return nil, fmt.Sprintf("XAUTH type %d", a.Uint())
			}
			attrs = append(attrs, ike1AttrTV(ike1XType, 0))
		case ike1XUser:
			attrs = append(attrs, ike1AttrTLV(ike1XUser, []byte(s.username)))
		case ike1XPass:
			attrs = append(attrs, ike1AttrTLV(ike1XPass, []byte(s.password)))
		case ike1XPasscode:
			attrs = append(attrs, ike1AttrTLV(ike1XPasscode, []byte(s.password)))
		case ike1XDomain:
			attrs = append(attrs, ike1AttrTLV(ike1XDomain, nil))
		case ike1XChal, ike1XNextPin, ike1XAnswer:
			return nil, "XAUTH challenge/next-PIN"
		}
	}
	return ike1CfgPayload(ike1CfgReply, req.ID, attrs...), ""
}

func ike1XauthMsg(c ike1Cfg) string {
	if a, ok := c.get(ike1XMessage); ok && len(a.Value) > 0 && len(a.Value) < 200 {
		return ": " + strings.TrimSpace(string(a.Value))
	}
	return ""
}

func (s *ike1Session) xauth(ctx context.Context) *ike1Err {
	replied := false
	unsupported := ""
	var serverMsg string
	common := func(b []byte, h *ike1Header) (*ike1Cfg, uint32, bool, *ike1Err) {
		if n := ike1PlainNotify(b, h); n != nil && n.Type < 8192 {
			return nil, 0, true, ike1AuthErr("server error during XAUTH: %s", ike1NotifyText(n))
		}
		if h.Flags&ike1FlagEnc == 0 || h.MsgID == 0 {
			return nil, 0, false, nil
		}
		if h.Exch == ike1ExInfo {
			during := "before XAUTH"
			if replied {
				during = "after receiving XAUTH credentials (username/password rejected)"
			}
			done, e := s.protectedErr(b, h, during)
			return nil, 0, done, e
		}
		if h.Exch != ike1ExTrans {
			return nil, 0, false, nil
		}
		pls, err := s.unprotect(b, h)
		if err != nil {
			return nil, 0, false, nil
		}
		ap := ike1Find(pls, ike1PlAttr)
		if ap == nil {
			return nil, 0, false, nil
		}
		cfg, err := ike1ParseCfg(ap.Body)
		if err != nil {
			return nil, 0, false, nil
		}
		return &cfg, h.MsgID, false, nil
	}
	e := s.await(ctx, nil, 6*time.Second, func(b []byte, h *ike1Header) (bool, *ike1Err) {
		cfg, mid, done, e := common(b, h)
		if cfg == nil {
			return done, e
		}
		if cfg.Type != ike1CfgRequest || !(cfg.has(ike1XUser) || cfg.has(ike1XPass) || cfg.has(ike1XType) || cfg.has(ike1XPasscode)) {
			return false, nil
		}
		serverMsg = ike1XauthMsg(*cfg)
		reply, why := s.xauthReply(*cfg)
		if why != "" {
			unsupported = why
			return true, nil
		}
		s.send(s.protect(ike1ExTrans, mid, []ike1Payload{{Type: ike1PlAttr, Body: reply}}))
		replied = true
		return true, nil
	})
	if e != nil {
		if e.timeout {
			s.p.Note("server did not request XAUTH (%s verified)", s.proofName())
			return nil
		}
		return e
	}
	if unsupported != "" {
		return &ike1Err{stage: StageAuth, state: StateUnsupported, msg: unsupported + " is not supported"}
	}
	status := -1
	e = s.await(ctx, nil, 0, func(b []byte, h *ike1Header) (bool, *ike1Err) {
		cfg, mid, done, e := common(b, h)
		if cfg == nil {
			return done, e
		}
		switch cfg.Type {
		case ike1CfgRequest:
			if cfg.has(ike1XUser) || cfg.has(ike1XPass) || cfg.has(ike1XPasscode) {
				return true, ike1AuthErr("XAUTH: server asked for credentials again, username/password rejected%s", firstNonEmpty(ike1XauthMsg(*cfg), serverMsg))
			}
		case ike1CfgSet:
			st, ok := cfg.get(ike1XStatus)
			if !ok {
				s.ackSet(mid, *cfg)
				return false, nil
			}
			s.send(s.protect(ike1ExTrans, mid, []ike1Payload{{Type: ike1PlAttr, Body: ike1CfgPayload(ike1CfgAck, cfg.ID, ike1AttrTV(ike1XStatus, uint16(st.Uint())))}}))
			status = int(st.Uint())
			if status != 1 {
				return true, ike1AuthErr("XAUTH failed: server rejected username/password%s", firstNonEmpty(ike1XauthMsg(*cfg), serverMsg))
			}
			return true, nil
		}
		return false, nil
	})
	if e != nil {
		if e.timeout {
			return ike1AuthErr("XAUTH: no status from server after sending credentials")
		}
		return e
	}
	if s.prm.cisco || s.vids.unity {
		s.modeCfg(ctx)
	}
	return nil
}

func (s *ike1Session) ackSet(mid uint32, cfg ike1Cfg) string {
	var attrs [][]byte
	addr := ""
	for _, a := range cfg.Attrs {
		attrs = append(attrs, ike1AttrTLV(a.Type, nil))
		if a.Type == ike1CfgIP4Addr && len(a.Value) == 4 {
			addr = netip.AddrFrom4([4]byte(a.Value)).String()
		}
	}
	s.send(s.protect(ike1ExTrans, mid, []ike1Payload{{Type: ike1PlAttr, Body: ike1CfgPayload(ike1CfgAck, cfg.ID, attrs...)}}))
	return addr
}

func (s *ike1Session) modeCfg(ctx context.Context) {
	mid := s.newMsgID()
	id := binary.BigEndian.Uint16(ike1Random(2))
	req := ike1CfgPayload(ike1CfgRequest, id, ike1AttrTLV(ike1CfgIP4Addr, nil), ike1AttrTLV(ike1CfgIP4Mask, nil), ike1AttrTLV(ike1CfgIP4DNS, nil))
	msg := s.protect(ike1ExTrans, mid, []ike1Payload{{Type: ike1PlAttr, Body: req}})
	assigned := ""
	s.await(ctx, msg, 2500*time.Millisecond, func(b []byte, h *ike1Header) (bool, *ike1Err) {
		if h.Flags&ike1FlagEnc == 0 || h.MsgID == 0 || h.Exch != ike1ExTrans {
			return false, nil
		}
		pls, err := s.unprotect(b, h)
		if err != nil {
			return false, nil
		}
		ap := ike1Find(pls, ike1PlAttr)
		if ap == nil {
			return false, nil
		}
		cfg, err := ike1ParseCfg(ap.Body)
		if err != nil {
			return false, nil
		}
		switch {
		case cfg.Type == ike1CfgSet:
			assigned = s.ackSet(h.MsgID, cfg)
			return true, nil
		case cfg.Type == ike1CfgReply && h.MsgID == mid:
			if a, ok := cfg.get(ike1CfgIP4Addr); ok && len(a.Value) == 4 {
				assigned = netip.AddrFrom4([4]byte(a.Value)).String()
			}
			return true, nil
		}
		return false, nil
	})
	if assigned != "" {
		s.p.Note("mode-config assigned %s", assigned)
	}
}
