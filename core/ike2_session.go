package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

var (
	ike2ErrNoResponse = errors.New("no response")
	ike2ErrTimeout    = errors.New("read timeout")
)

const ike2FragMTU = 1200

type ike2Failure struct {
	stage string
	state string
	msg   string
	trust bool
}

func (e *ike2Failure) Error() string { return e.msg }

func ike2Fail(stage, state, format string, args ...any) error {
	return &ike2Failure{stage: stage, state: state, msg: fmt.Sprintf(format, args...)}
}

type ike2Redirect struct {
	target string
}

func (e *ike2Redirect) Error() string { return "redirected to " + e.target }

type ike2Session struct {
	addr         netip.Addr
	port         int
	natt         bool
	conn         *net.UDPConn
	spiI, spiR   [8]byte
	msgID        uint32
	keys         *ike2Keys
	ni, nr       []byte
	initReq      []byte
	initResp     []byte
	ke           ike2KE
	cookie       []byte
	redirFrom    []byte
	fragOK       bool
	childless    bool
	multiAuth    bool
	sigHashes    []uint16
	certReqs     [][]byte
	gotResponse  bool
	rtt          time.Duration
	natSwitched  bool
	fragSent     bool
	fragRecv     bool
	established  bool
	authRejected bool
	idr          []byte
	notes        []string
}

func newIke2Session(addr netip.Addr, port int) *ike2Session {
	if port <= 0 {
		port = 500
	}
	return &ike2Session{addr: addr.Unmap(), port: port, natt: port != 500}
}

func (s *ike2Session) note(format string, args ...any) {
	m := fmt.Sprintf(format, args...)
	for _, n := range s.notes {
		if n == m {
			return
		}
	}
	s.notes = append(s.notes, m)
}

func (s *ike2Session) dial() error {
	ua := net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.addr, uint16(s.port)))
	c, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

func (s *ike2Session) close() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

func (s *ike2Session) send(b []byte) error {
	if s.natt {
		b = append([]byte{0, 0, 0, 0}, b...)
	}
	_, err := s.conn.Write(b)
	return err
}

func (s *ike2Session) recv(deadline time.Time) ([]byte, error) {
	buf := make([]byte, 65536)
	for {
		s.conn.SetReadDeadline(deadline)
		n, err := s.conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, ike2ErrTimeout
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, ike2ErrTimeout
			}
			return nil, err
		}
		b := buf[:n]
		if s.natt {
			if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
				continue
			}
			b = b[4:]
		}
		if len(b) < ike2HdrLen {
			continue
		}
		return append([]byte(nil), b...), nil
	}
}

func ike2NextDeadline(ctx context.Context, d time.Duration) time.Time {
	t := time.Now().Add(d)
	if dl, ok := ctx.Deadline(); ok && dl.Before(t) {
		return dl
	}
	return t
}

func (s *ike2Session) localAP() netip.AddrPort {
	if ua, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func (s *ike2Session) remoteAP() netip.AddrPort {
	return netip.AddrPortFrom(s.addr, uint16(s.port))
}

func ike2NatHash(spiI, spiR [8]byte, ap netip.AddrPort) []byte {
	h := sha1.New()
	h.Write(spiI[:])
	h.Write(spiR[:])
	h.Write(ap.Addr().Unmap().AsSlice())
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], ap.Port())
	h.Write(pb[:])
	return h.Sum(nil)
}

func ike2Random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func ike2ProposalGroups(props []ike2Proposal) []uint16 {
	var out []uint16
	seen := map[uint16]bool{}
	for _, p := range props {
		for _, t := range p.ts {
			if t.typ == ike2TDH && !seen[t.id] && ike2KESupported(t.id) {
				seen[t.id] = true
				out = append(out, t.id)
			}
		}
	}
	return out
}

func (s *ike2Session) buildInit(props []ike2Proposal) []byte {
	var ps []ike2P
	if s.cookie != nil {
		ps = append(ps, ike2Notify(ike2NCookie, s.cookie))
	}
	g := s.ke.Group()
	ke := append([]byte{byte(g >> 8), byte(g), 0, 0}, s.ke.Public()...)
	ps = append(ps, ike2P{t: ike2PSA, body: ike2EncodeSA(props)}, ike2P{t: ike2PKE, body: ke}, ike2P{t: ike2PNonce, body: s.ni})
	var zero [8]byte
	ps = append(ps,
		ike2Notify(ike2NNatSrc, ike2NatHash(s.spiI, zero, s.localAP())),
		ike2Notify(ike2NNatDst, ike2NatHash(s.spiI, zero, s.remoteAP())),
		ike2Notify(ike2NFragSupported, nil),
		ike2Notify(ike2NSigHash, []byte{0, 2, 0, 3, 0, 4, 0, 1, 0, 5}),
		ike2Notify(ike2NChildless, nil),
	)
	if s.redirFrom != nil {
		ps = append(ps, ike2Notify(16408, s.redirFrom))
	} else {
		ps = append(ps, ike2Notify(ike2NRedirectSupported, nil))
	}
	first, body := ike2Chain(ps)
	msg := ike2Header(s.spiI, zero, first, ike2ExInit, ike2FlagI, 0, ike2HdrLen+len(body))
	return append(msg, body...)
}

func (s *ike2Session) initRoundTrip(ctx context.Context, pkt []byte) (*ike2Msg, time.Duration, error) {
	interval := time.Second
	for {
		sent := time.Now()
		if err := s.send(pkt); err != nil {
			return nil, 0, err
		}
		deadline := ike2NextDeadline(ctx, interval)
		for {
			b, err := s.recv(deadline)
			if err == ike2ErrTimeout {
				break
			}
			if err != nil {
				return nil, 0, err
			}
			m, err := ike2ParseMsg(b)
			if err != nil || m.exch != ike2ExInit || m.flags&ike2FlagR == 0 || m.spiI != s.spiI || m.id != 0 {
				continue
			}
			return m, time.Since(sent), nil
		}
		if ctx.Err() != nil {
			return nil, 0, ike2ErrNoResponse
		}
		interval = interval * 3 / 2
		if interval > 3*time.Second {
			interval = 3 * time.Second
		}
	}
}

func (s *ike2Session) saInit(ctx context.Context, sets [][]ike2Proposal) error {
	var lastErr error
	for si, props := range sets {
		groups := ike2ProposalGroups(props)
		if len(groups) == 0 {
			continue
		}
		group := groups[0]
		copy(s.spiI[:], ike2Random(8))
		s.ni = ike2Random(32)
		s.cookie = nil
		s.ke = nil
		cookies, kes := 0, 0
	attempt:
		for {
			if s.ke == nil || s.ke.Group() != group {
				ke, err := ike2NewKE(group)
				if err != nil {
					return ike2Fail(StageHandshake, StateHandshakeFailed, "DH: %v", err)
				}
				s.ke = ke
			}
			req := s.buildInit(props)
			m, rtt, err := s.initRoundTrip(ctx, req)
			if err != nil {
				return err
			}
			s.gotResponse = true
			if n, ok := ike2FindNotify(m.payloads, ike2NCookie); ok {
				cookies++
				if cookies > 3 {
					return ike2Fail(StageHandshake, StateHandshakeFailed, "responder keeps requesting cookies")
				}
				s.cookie = append([]byte(nil), n.data...)
				continue
			}
			if n, ok := ike2FindNotify(m.payloads, ike2NInvalidKE); ok && len(n.data) >= 2 {
				g := binary.BigEndian.Uint16(n.data)
				kes++
				if !ike2KESupported(g) {
					return ike2Fail(StageHandshake, StateUnsupported, "responder requires DH group %s which the tester does not implement", ike2GroupName(g))
				}
				if kes > 2 || g == group {
					return ike2Fail(StageHandshake, StateHandshakeFailed, "INVALID_KE_PAYLOAD loop (group %s)", ike2GroupName(g))
				}
				s.note("INVALID_KE_PAYLOAD: retried with %s", ike2GroupName(g))
				group = g
				continue
			}
			if n, ok := ike2FindNotify(m.payloads, ike2NRedirect); ok {
				if t := ike2RedirectTarget(n.data); t != "" {
					return &ike2Redirect{target: t}
				}
			}
			if n, ok := ike2ErrorNotify(m.payloads); ok {
				if n.typ == ike2NNoProposal {
					lastErr = ike2Fail(StageHandshake, StateHandshakeFailed, "NO_PROPOSAL_CHOSEN: responder rejected all offered IKE proposals")
					if si+1 < len(sets) {
						s.note("NO_PROPOSAL_CHOSEN for modern proposals, retried with legacy set")
					}
					break attempt
				}
				return ike2Fail(StageHandshake, StateHandshakeFailed, "IKE_SA_INIT rejected: %s", ike2NotifyName(n.typ))
			}
			if err := s.processInit(m, group); err != nil {
				return err
			}
			s.initReq = req
			s.initResp = m.raw
			s.rtt = rtt
			return nil
		}
	}
	if lastErr == nil {
		lastErr = ike2Fail(StageHandshake, StateUnsupported, "no usable IKE proposal (configured algorithms not supported by tester)")
	}
	return lastErr
}

func (s *ike2Session) processInit(m *ike2Msg, group uint16) error {
	var zero [8]byte
	if m.spiR == zero {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "responder SPI is zero")
	}
	sa := ike2Find(m.payloads, ike2PSA)
	ke := ike2Find(m.payloads, ike2PKE)
	nr := ike2Find(m.payloads, ike2PNonce)
	if sa == nil || ke == nil || nr == nil {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "IKE_SA_INIT response incomplete")
	}
	props, err := ike2DecodeSA(sa)
	if err != nil || len(props) == 0 || props[0].proto != 1 {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "IKE_SA_INIT response has invalid SA payload")
	}
	suite, err := ike2SuiteFrom(props[0])
	if err != nil {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "%v", err)
	}
	if len(ke) < 4 || binary.BigEndian.Uint16(ke) != group || suite.DH != group {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "responder KE group mismatch")
	}
	if len(nr) < 16 || len(nr) > 256 {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "invalid responder nonce")
	}
	gir, err := s.ke.Shared(ke[4:])
	if err != nil {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "DH exchange failed: %v", err)
	}
	s.spiR = m.spiR
	s.nr = append([]byte(nil), nr...)
	keys, err := ike2Derive(suite, s.ni, s.nr, gir, s.spiI, s.spiR)
	if err != nil {
		return ike2Fail(StageHandshake, StateUnsupported, "%v", err)
	}
	s.keys = keys
	s.msgID = 1
	for _, n := range ike2Notifies(m.payloads) {
		switch n.typ {
		case ike2NFragSupported:
			s.fragOK = true
		case ike2NChildless:
			s.childless = true
		case ike2NMultipleAuth:
			s.multiAuth = true
		case ike2NSigHash:
			s.sigHashes = nil
			for i := 0; i+1 < len(n.data); i += 2 {
				s.sigHashes = append(s.sigHashes, binary.BigEndian.Uint16(n.data[i:]))
			}
		}
	}
	for _, cr := range ike2FindAll(m.payloads, ike2PCertReq) {
		if len(cr) > 1 && cr[0] == 4 {
			for i := 1; i+20 <= len(cr); i += 20 {
				s.certReqs = append(s.certReqs, cr[i:i+20])
			}
		}
	}
	natted := false
	if n, ok := ike2FindNotify(m.payloads, ike2NNatDst); ok {
		if string(n.data) != string(ike2NatHash(s.spiI, s.spiR, s.localAP())) {
			natted = true
			s.note("NAT detected")
		}
	}
	srcs := 0
	srcMatch := false
	for _, n := range ike2Notifies(m.payloads) {
		if n.typ == ike2NNatSrc {
			srcs++
			if string(n.data) == string(ike2NatHash(s.spiI, s.spiR, s.remoteAP())) {
				srcMatch = true
			}
		}
	}
	if srcs > 0 && !srcMatch {
		natted = true
		s.note("responder is behind NAT")
	}
	if natted && !s.natt {
		s.close()
		s.port = 4500
		s.natt = true
		s.natSwitched = true
		if err := s.dial(); err != nil {
			return err
		}
	}
	return nil
}

func ike2RedirectTarget(d []byte) string {
	if len(d) < 2 || int(d[1])+2 > len(d) {
		return ""
	}
	v := d[2 : 2+int(d[1])]
	switch d[0] {
	case 1:
		if len(v) == 4 {
			return netip.AddrFrom4([4]byte(v)).String()
		}
	case 2:
		if len(v) == 16 {
			return netip.AddrFrom16([16]byte(v)).String()
		}
	case 3:
		return string(v)
	}
	return ""
}

func (s *ike2Session) sealMsg(exch byte, id uint32, first byte, inner []byte, num, total int) ([]byte, error) {
	ph, pt := 4, byte(ike2PSK)
	if total > 0 {
		ph, pt = 8, ike2PSKF
	}
	body := s.keys.sealedLen(len(inner))
	size := ike2HdrLen + ph + body
	msg := ike2Header(s.spiI, s.spiR, pt, exch, ike2FlagI, id, size)[:size]
	msg[28] = first
	binary.BigEndian.PutUint16(msg[30:], uint16(ph+body))
	if total > 0 {
		binary.BigEndian.PutUint16(msg[32:], uint16(num))
		binary.BigEndian.PutUint16(msg[34:], uint16(total))
	}
	if err := s.keys.seal(msg, ike2HdrLen+ph, inner); err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *ike2Session) encode(exch byte, id uint32, ps []ike2P) ([][]byte, error) {
	first, inner := ike2Chain(ps)
	full, err := s.sealMsg(exch, id, first, inner, 0, 0)
	if err != nil {
		return nil, err
	}
	if !s.fragOK || len(full) <= ike2FragMTU {
		return [][]byte{full}, nil
	}
	chunk := ike2FragMTU - ike2HdrLen - 8 - s.keys.sealedLen(0) - s.keys.block
	if chunk < 64 {
		chunk = 64
	}
	n := (len(inner) + chunk - 1) / chunk
	var out [][]byte
	for i := 0; i < n; i++ {
		end := (i + 1) * chunk
		if end > len(inner) {
			end = len(inner)
		}
		f := byte(0)
		if i == 0 {
			f = first
		}
		m, err := s.sealMsg(exch, id, f, inner[i*chunk:end], i+1, n)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	s.fragSent = true
	return out, nil
}

func (s *ike2Session) exchange(ctx context.Context, exch byte, ps []ike2P) ([]ike2P, error) {
	id := s.msgID
	s.msgID++
	pkts, err := s.encode(exch, id, ps)
	if err != nil {
		return nil, err
	}
	frags := map[uint16][]byte{}
	var fragFirst byte
	interval := time.Second
	for {
		for _, pk := range pkts {
			if err := s.send(pk); err != nil {
				return nil, err
			}
		}
		deadline := ike2NextDeadline(ctx, interval)
		for {
			b, err := s.recv(deadline)
			if err == ike2ErrTimeout {
				break
			}
			if err != nil {
				return nil, err
			}
			m, err := ike2ParseMsg(b)
			if err != nil || m.spiI != s.spiI || m.spiR != s.spiR || m.flags&ike2FlagR == 0 {
				continue
			}
			if m.id != id || m.exch != exch || m.encOff < 0 {
				continue
			}
			ph := 4
			if m.encType == ike2PSKF {
				ph = 8
			}
			plain, err := s.keys.open(m.raw, m.encOff+ph)
			if err != nil {
				continue
			}
			if m.encType == ike2PSK {
				return ike2ParseChain(m.encFirst, plain)
			}
			if m.fragNum == 0 || m.fragNum > m.fragTotal {
				continue
			}
			if _, ok := frags[m.fragNum]; !ok {
				frags[m.fragNum] = plain
			}
			if m.fragNum == 1 {
				fragFirst = m.encFirst
			}
			if len(frags) == int(m.fragTotal) {
				var all []byte
				for i := uint16(1); i <= m.fragTotal; i++ {
					all = append(all, frags[i]...)
				}
				s.fragRecv = true
				return ike2ParseChain(fragFirst, all)
			}
		}
		if ctx.Err() != nil {
			return nil, ike2ErrNoResponse
		}
		interval = interval * 3 / 2
		if interval > 3*time.Second {
			interval = 3 * time.Second
		}
	}
}

func (s *ike2Session) deleteSA(wait time.Duration) {
	if s.keys == nil || s.conn == nil || s.authRejected {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	s.exchange(ctx, ike2ExInfo, []ike2P{{t: ike2PDelete, body: []byte{1, 0, 0, 0}}})
}
