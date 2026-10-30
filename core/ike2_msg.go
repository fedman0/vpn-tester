package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ike2ExInit   = 34
	ike2ExAuth   = 35
	ike2ExChild  = 36
	ike2ExInfo   = 37
	ike2FlagI    = 0x08
	ike2FlagR    = 0x20
	ike2HdrLen   = 28
	ike2PSA      = 33
	ike2PKE      = 34
	ike2PIDi     = 35
	ike2PIDr     = 36
	ike2PCert    = 37
	ike2PCertReq = 38
	ike2PAuth    = 39
	ike2PNonce   = 40
	ike2PNotify  = 41
	ike2PDelete  = 42
	ike2PVendor  = 43
	ike2PTSi     = 44
	ike2PTSr     = 45
	ike2PSK      = 46
	ike2PCP      = 47
	ike2PEAP     = 48
	ike2PSKF     = 53
)

const (
	ike2NUnsupportedCritical = 1
	ike2NInvalidSPI          = 4
	ike2NInvalidMajor        = 5
	ike2NInvalidSyntax       = 7
	ike2NInvalidMsgID        = 9
	ike2NNoProposal          = 14
	ike2NInvalidKE           = 17
	ike2NAuthFailed          = 24
	ike2NSinglePair          = 34
	ike2NNoAdditionalSAs     = 35
	ike2NInternalAddr        = 36
	ike2NFailedCP            = 37
	ike2NTSUnacceptable      = 38
	ike2NTemporaryFailure    = 43
	ike2NInitialContact      = 16384
	ike2NNatSrc              = 16388
	ike2NNatDst              = 16389
	ike2NCookie              = 16390
	ike2NMultipleAuth        = 16404
	ike2NAnotherAuth         = 16405
	ike2NRedirectSupported   = 16406
	ike2NRedirect            = 16407
	ike2NEAPOnly             = 16417
	ike2NChildless           = 16418
	ike2NFragSupported       = 16430
	ike2NSigHash             = 16431
)

var ike2NotifyNames = map[uint16]string{
	1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX",
	9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
	24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED", 35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE",
	37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 40: "UNACCEPTABLE_ADDRESSES",
	41: "UNEXPECTED_NAT_DETECTED", 42: "USE_ASSIGNED_HoA", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
	45: "INVALID_GROUP_ID", 46: "AUTHORIZATION_FAILED", 47: "STATE_NOT_FOUND",
}

func ike2NotifyName(t uint16) string {
	if n, ok := ike2NotifyNames[t]; ok {
		return n
	}
	return fmt.Sprintf("NOTIFY_%d", t)
}

type ike2P struct {
	t    byte
	body []byte
}

type ike2Msg struct {
	spiI, spiR [8]byte
	next       byte
	exch       byte
	flags      byte
	id         uint32
	raw        []byte
	payloads   []ike2P
	encOff     int
	encType    byte
	encFirst   byte
	fragNum    uint16
	fragTotal  uint16
}

func ike2Chain(ps []ike2P) (byte, []byte) {
	if len(ps) == 0 {
		return 0, nil
	}
	var b []byte
	for i, p := range ps {
		next := byte(0)
		if i+1 < len(ps) {
			next = ps[i+1].t
		}
		l := 4 + len(p.body)
		b = append(b, next, 0, byte(l>>8), byte(l))
		b = append(b, p.body...)
	}
	return ps[0].t, b
}

func ike2ParseChain(first byte, b []byte) ([]ike2P, error) {
	var out []ike2P
	t := first
	for t != 0 {
		if len(b) < 4 {
			return out, errors.New("truncated payload")
		}
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if l < 4 || l > len(b) {
			return out, errors.New("bad payload length")
		}
		out = append(out, ike2P{t: t, body: b[4:l]})
		t = b[0]
		b = b[l:]
	}
	return out, nil
}

func ike2Header(spiI, spiR [8]byte, next, exch, flags byte, id uint32, length int) []byte {
	h := make([]byte, ike2HdrLen, length)
	copy(h[0:8], spiI[:])
	copy(h[8:16], spiR[:])
	h[16] = next
	h[17] = 0x20
	h[18] = exch
	h[19] = flags
	binary.BigEndian.PutUint32(h[20:24], id)
	binary.BigEndian.PutUint32(h[24:28], uint32(length))
	return h
}

func ike2ParseMsg(b []byte) (*ike2Msg, error) {
	if len(b) < ike2HdrLen {
		return nil, errors.New("short IKE message")
	}
	m := &ike2Msg{raw: b, encOff: -1}
	copy(m.spiI[:], b[0:8])
	copy(m.spiR[:], b[8:16])
	m.next = b[16]
	if b[17]>>4 != 2 {
		return nil, fmt.Errorf("unsupported IKE version %d.%d", b[17]>>4, b[17]&0xf)
	}
	m.exch = b[18]
	m.flags = b[19]
	m.id = binary.BigEndian.Uint32(b[20:24])
	l := int(binary.BigEndian.Uint32(b[24:28]))
	if l < ike2HdrLen || l > len(b) {
		return nil, errors.New("bad IKE length")
	}
	b = b[:l]
	m.raw = b
	off := ike2HdrLen
	t := m.next
	for t != 0 {
		if len(b)-off < 4 {
			return nil, errors.New("truncated payload")
		}
		pl := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if pl < 4 || off+pl > len(b) {
			return nil, errors.New("bad payload length")
		}
		if t == ike2PSK || t == ike2PSKF {
			m.encOff, m.encType, m.encFirst = off, t, b[off]
			if t == ike2PSKF {
				if pl < 8 {
					return nil, errors.New("bad fragment payload")
				}
				m.fragNum = binary.BigEndian.Uint16(b[off+4:])
				m.fragTotal = binary.BigEndian.Uint16(b[off+6:])
			}
			break
		}
		m.payloads = append(m.payloads, ike2P{t: t, body: b[off+4 : off+pl]})
		t = b[off]
		off += pl
	}
	return m, nil
}

func ike2Notify(typ uint16, data []byte) ike2P {
	b := []byte{0, 0, byte(typ >> 8), byte(typ)}
	return ike2P{t: ike2PNotify, body: append(b, data...)}
}

type ike2N struct {
	typ   uint16
	proto byte
	spi   []byte
	data  []byte
}

func ike2Notifies(ps []ike2P) []ike2N {
	var out []ike2N
	for _, p := range ps {
		if p.t != ike2PNotify || len(p.body) < 4 {
			continue
		}
		ss := int(p.body[1])
		if 4+ss > len(p.body) {
			continue
		}
		out = append(out, ike2N{typ: binary.BigEndian.Uint16(p.body[2:4]), proto: p.body[0], spi: p.body[4 : 4+ss], data: p.body[4+ss:]})
	}
	return out
}

func ike2FindNotify(ps []ike2P, typ uint16) (ike2N, bool) {
	for _, n := range ike2Notifies(ps) {
		if n.typ == typ {
			return n, true
		}
	}
	return ike2N{}, false
}

func ike2ErrorNotify(ps []ike2P) (ike2N, bool) {
	for _, n := range ike2Notifies(ps) {
		if n.typ > 0 && n.typ < 16384 {
			return n, true
		}
	}
	return ike2N{}, false
}

func ike2Find(ps []ike2P, t byte) []byte {
	for _, p := range ps {
		if p.t == t {
			return p.body
		}
	}
	return nil
}

func ike2FindAll(ps []ike2P, t byte) [][]byte {
	var out [][]byte
	for _, p := range ps {
		if p.t == t {
			out = append(out, p.body)
		}
	}
	return out
}

type ike2Transform struct {
	typ    byte
	id     uint16
	keyLen int
}

type ike2Proposal struct {
	num   byte
	proto byte
	spi   []byte
	ts    []ike2Transform
}

func ike2EncodeSA(props []ike2Proposal) []byte {
	var out []byte
	for i, p := range props {
		var tb []byte
		for j, t := range p.ts {
			last := byte(3)
			if j == len(p.ts)-1 {
				last = 0
			}
			body := []byte{t.typ, 0, byte(t.id >> 8), byte(t.id)}
			if t.keyLen > 0 {
				body = append(body, 0x80, 0x0e, byte(t.keyLen>>8), byte(t.keyLen))
			}
			l := 4 + len(body)
			tb = append(tb, last, 0, byte(l>>8), byte(l))
			tb = append(tb, body...)
		}
		last := byte(2)
		if i == len(props)-1 {
			last = 0
		}
		num := p.num
		if num == 0 {
			num = byte(i + 1)
		}
		l := 8 + len(p.spi) + len(tb)
		out = append(out, last, 0, byte(l>>8), byte(l), num, p.proto, byte(len(p.spi)), byte(len(p.ts)))
		out = append(out, p.spi...)
		out = append(out, tb...)
	}
	return out
}

func ike2DecodeSA(b []byte) ([]ike2Proposal, error) {
	var out []ike2Proposal
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errors.New("truncated proposal")
		}
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if l < 8 || l > len(b) {
			return nil, errors.New("bad proposal length")
		}
		p := ike2Proposal{num: b[4], proto: b[5]}
		ss := int(b[6])
		nt := int(b[7])
		pb := b[8:l]
		if ss > len(pb) {
			return nil, errors.New("bad proposal SPI")
		}
		p.spi = pb[:ss]
		pb = pb[ss:]
		for i := 0; i < nt && len(pb) >= 8; i++ {
			tl := int(binary.BigEndian.Uint16(pb[2:4]))
			if tl < 8 || tl > len(pb) {
				return nil, errors.New("bad transform length")
			}
			t := ike2Transform{typ: pb[4], id: binary.BigEndian.Uint16(pb[6:8])}
			attrs := pb[8:tl]
			for len(attrs) >= 4 {
				at := binary.BigEndian.Uint16(attrs[0:2])
				if at&0x8000 != 0 {
					if at&0x7fff == 14 {
						t.keyLen = int(binary.BigEndian.Uint16(attrs[2:4]))
					}
					attrs = attrs[4:]
				} else {
					al := int(binary.BigEndian.Uint16(attrs[2:4]))
					if 4+al > len(attrs) {
						break
					}
					attrs = attrs[4+al:]
				}
			}
			p.ts = append(p.ts, t)
			pb = pb[tl:]
		}
		out = append(out, p)
		if b[0] == 0 {
			break
		}
		b = b[l:]
	}
	return out, nil
}

func ike2SuiteFrom(p ike2Proposal) (ike2Suite, error) {
	var s ike2Suite
	for _, t := range p.ts {
		switch t.typ {
		case ike2TEncr:
			s.Encr, s.KeyBits = t.id, t.keyLen
		case ike2TPRF:
			s.PRF = t.id
		case ike2TInteg:
			s.Integ = t.id
		case ike2TDH:
			s.DH = t.id
		}
	}
	if s.Encr == 0 || s.PRF == 0 || s.DH == 0 {
		return s, errors.New("incomplete proposal selected by responder")
	}
	if s.Encr == ike2EncrDES3 {
		s.KeyBits = 192
	}
	if s.Encr == ike2EncrChaCha {
		s.KeyBits = 256
	}
	if !s.aead() && s.Integ == 0 {
		return s, errors.New("responder selected no integrity algorithm")
	}
	if s.aead() {
		s.Integ = 0
	}
	return s, nil
}
