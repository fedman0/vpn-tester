package main

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	sstpProtoLCP  = 0xC021
	sstpProtoPAP  = 0xC023
	sstpProtoCHAP = 0xC223
	sstpProtoEAP  = 0xC227

	sstpAlgMD5      = 0x05
	sstpAlgMSCHAPv2 = 0x81
	sstpAlgMSCHAPv1 = 0x80

	sstpRetransmit = 2 * time.Second
	sstpMaxTries   = 5
)

type sstpAuthFailure struct{ msg string }

func (e *sstpAuthFailure) Error() string { return e.msg }

type sstpOpt struct {
	t byte
	v []byte
}

type sstpPPP struct {
	user      string
	hashUser  string
	pass      string
	send      func(frame []byte) error
	magic     uint32
	opts      []sstpOpt
	reqID     uint8
	reqSent   time.Time
	reqTries  int
	ourAcked  bool
	peerAcked bool
	authProto uint16
	chapAlg   byte
	authNaks  int
	papID     uint8
	papSent   time.Time
	papTries  int
	chapID    int
	chapResp  []byte
	eapNaks   int
	eapInner  bool
	expectS   string
	method    string
	notes     []string
	done      bool
	err       error
}

func newSSTPPPP(user, domain, pass string, send func([]byte) error) *sstpPPP {
	full := user
	if domain != "" && !strings.Contains(user, "\\") {
		full = domain + "\\" + user
	}
	hu := full
	if i := strings.LastIndex(hu, "\\"); i >= 0 {
		hu = hu[i+1:]
	}
	var mb [4]byte
	rand.Read(mb[:])
	m := binary.BigEndian.Uint32(mb[:])
	if m == 0 {
		m = 0x5a17c0de
	}
	pp := &sstpPPP{user: full, hashUser: hu, pass: pass, send: send, magic: m, chapID: -1}
	mru := make([]byte, 2)
	binary.BigEndian.PutUint16(mru, 1400)
	mg := make([]byte, 4)
	binary.BigEndian.PutUint32(mg, m)
	pp.opts = []sstpOpt{{1, mru}, {5, mg}}
	return pp
}

func (pp *sstpPPP) start() error { return pp.sendConfReq() }

func (pp *sstpPPP) finish(err error) {
	if pp.done {
		return
	}
	pp.done = true
	pp.err = err
}

func (pp *sstpPPP) fail(format string, args ...any) {
	pp.finish(&sstpAuthFailure{msg: fmt.Sprintf(format, args...)})
}

func (pp *sstpPPP) sendFrame(proto uint16, payload []byte) error {
	f := make([]byte, 4+len(payload))
	f[0], f[1] = 0xFF, 0x03
	binary.BigEndian.PutUint16(f[2:], proto)
	copy(f[4:], payload)
	return pp.send(f)
}

func (pp *sstpPPP) sendCP(proto uint16, code, id byte, data []byte) error {
	pkt := make([]byte, 4+len(data))
	pkt[0], pkt[1] = code, id
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	copy(pkt[4:], data)
	return pp.sendFrame(proto, pkt)
}

func (pp *sstpPPP) sendConfReq() error {
	pp.reqID++
	pp.reqSent = time.Now()
	pp.reqTries++
	var b []byte
	for _, o := range pp.opts {
		b = append(b, o.t, byte(len(o.v)+2))
		b = append(b, o.v...)
	}
	return pp.sendCP(sstpProtoLCP, 1, pp.reqID, b)
}

func (pp *sstpPPP) terminate() error {
	return pp.sendCP(sstpProtoLCP, 5, pp.reqID+100, []byte("bye"))
}

func (pp *sstpPPP) tick(now time.Time) error {
	if pp.done {
		return nil
	}
	if !pp.ourAcked && now.Sub(pp.reqSent) >= sstpRetransmit {
		if pp.reqTries >= sstpMaxTries {
			pp.finish(errors.New("no LCP response from server"))
			return nil
		}
		return pp.sendConfReq()
	}
	if pp.authProto == sstpProtoPAP && pp.papTries > 0 && now.Sub(pp.papSent) >= sstpRetransmit {
		if pp.papTries >= sstpMaxTries {
			pp.finish(errors.New("no PAP response from server"))
			return nil
		}
		return pp.sendPAP(false)
	}
	return nil
}

func sstpCPParse(b []byte) (code, id byte, data []byte, ok bool) {
	if len(b) < 4 {
		return 0, 0, nil, false
	}
	l := int(binary.BigEndian.Uint16(b[2:]))
	if l < 4 || l > len(b) {
		return 0, 0, nil, false
	}
	return b[0], b[1], b[4:l], true
}

func sstpParseOpts(b []byte) ([]sstpOpt, bool) {
	var out []sstpOpt
	for len(b) > 0 {
		if len(b) < 2 || int(b[1]) < 2 || int(b[1]) > len(b) {
			return nil, false
		}
		out = append(out, sstpOpt{b[0], b[2:b[1]]})
		b = b[b[1]:]
	}
	return out, true
}

func sstpEncOpt(o sstpOpt) []byte {
	return append([]byte{o.t, byte(len(o.v) + 2)}, o.v...)
}

func (pp *sstpPPP) input(frame []byte) error {
	if len(frame) >= 2 && frame[0] == 0xFF && frame[1] == 0x03 {
		frame = frame[2:]
	}
	if len(frame) < 1 {
		return nil
	}
	var proto uint16
	if frame[0]&1 == 1 {
		proto = uint16(frame[0])
		frame = frame[1:]
	} else {
		if len(frame) < 2 {
			return nil
		}
		proto = binary.BigEndian.Uint16(frame)
		frame = frame[2:]
	}
	switch proto {
	case sstpProtoLCP:
		return pp.lcp(frame)
	case sstpProtoPAP:
		return pp.pap(frame)
	case sstpProtoCHAP:
		return pp.chap(frame)
	case sstpProtoEAP:
		return pp.eap(frame)
	}
	return nil
}

func (pp *sstpPPP) lcp(b []byte) error {
	code, id, data, ok := sstpCPParse(b)
	if !ok {
		return nil
	}
	switch code {
	case 1:
		return pp.lcpConfReq(id, data)
	case 2:
		if id == pp.reqID {
			pp.ourAcked = true
			return pp.opened()
		}
	case 3, 4:
		if id == pp.reqID && !pp.ourAcked {
			pp.lcpNakRej(code, data)
			if pp.reqTries >= sstpMaxTries+3 {
				pp.finish(errors.New("LCP negotiation did not converge"))
				return nil
			}
			return pp.sendConfReq()
		}
	case 5:
		pp.sendCP(sstpProtoLCP, 6, id, nil)
		msg := sstpPrintable(data)
		if msg != "" {
			pp.finish(fmt.Errorf("server terminated the PPP link: %s", msg))
		} else {
			pp.finish(errors.New("server terminated the PPP link"))
		}
	case 8:
		if len(data) >= 2 {
			rp := binary.BigEndian.Uint16(data)
			if rp == pp.authProto || rp == sstpProtoLCP {
				pp.finish(fmt.Errorf("server rejected PPP protocol 0x%04x", rp))
			}
		}
	case 9:
		if len(data) >= 4 {
			r := append([]byte(nil), data...)
			binary.BigEndian.PutUint32(r, pp.magic)
			return pp.sendCP(sstpProtoLCP, 10, id, r)
		}
	}
	return nil
}

func (pp *sstpPPP) lcpNakRej(code byte, data []byte) {
	opts, ok := sstpParseOpts(data)
	if !ok {
		return
	}
	for _, o := range opts {
		idx := -1
		for i, q := range pp.opts {
			if q.t == o.t {
				idx = i
			}
		}
		if code == 4 {
			if idx >= 0 {
				pp.opts = append(pp.opts[:idx], pp.opts[idx+1:]...)
			}
			continue
		}
		switch o.t {
		case 1:
			if len(o.v) == 2 && idx >= 0 {
				pp.opts[idx].v = append([]byte(nil), o.v...)
			}
		case 5:
			if idx >= 0 {
				var mb [4]byte
				rand.Read(mb[:])
				pp.magic = binary.BigEndian.Uint32(mb[:]) | 1
				binary.BigEndian.PutUint32(pp.opts[idx].v, pp.magic)
			}
		}
	}
}

func sstpAuthName(v []byte) string {
	if len(v) < 2 {
		return "invalid"
	}
	ap := binary.BigEndian.Uint16(v)
	switch ap {
	case sstpProtoPAP:
		return "PAP"
	case sstpProtoEAP:
		return "EAP"
	case sstpProtoCHAP:
		if len(v) >= 3 {
			switch v[2] {
			case sstpAlgMD5:
				return "CHAP-MD5"
			case sstpAlgMSCHAPv2:
				return "MS-CHAPv2"
			case sstpAlgMSCHAPv1:
				return "MS-CHAPv1"
			}
			return fmt.Sprintf("CHAP algorithm 0x%02x", v[2])
		}
		return "CHAP"
	case 0xC027:
		return "SPAP"
	}
	return fmt.Sprintf("protocol 0x%04x", ap)
}

func (pp *sstpPPP) lcpConfReq(id byte, data []byte) error {
	opts, ok := sstpParseOpts(data)
	if !ok {
		return nil
	}
	var nak, rej []byte
	var auth uint16
	var alg byte
	for _, o := range opts {
		switch o.t {
		case 1, 2, 5, 7, 8, 19:
			if o.t == 5 && len(o.v) == 4 && binary.BigEndian.Uint32(o.v) == pp.magic && pp.magic != 0 {
				pp.finish(errors.New("PPP loopback detected"))
				return nil
			}
		case 3:
			if len(o.v) < 2 {
				rej = append(rej, sstpEncOpt(o)...)
				continue
			}
			ap := binary.BigEndian.Uint16(o.v)
			switch {
			case ap == sstpProtoPAP && pp.authNaks > 0:
				auth = sstpProtoPAP
			case ap == sstpProtoCHAP && len(o.v) >= 3 && (o.v[2] == sstpAlgMSCHAPv2 || o.v[2] == sstpAlgMD5):
				auth, alg = sstpProtoCHAP, o.v[2]
			case ap == sstpProtoCHAP && len(o.v) >= 3 && o.v[2] == sstpAlgMSCHAPv1 && pp.authNaks > 0:
				auth, alg = sstpProtoCHAP, o.v[2]
			case ap == sstpProtoEAP && pp.authNaks > 0:
				auth = sstpProtoEAP
			default:
				pp.authNaks++
				if pp.authNaks > 4 {
					pp.finish(fmt.Errorf("server requires unsupported PPP authentication (%s)", sstpAuthName(o.v)))
					return nil
				}
				nak = append(nak, 3, 5, 0xC2, 0x23, sstpAlgMSCHAPv2)
			}
		default:
			rej = append(rej, sstpEncOpt(o)...)
		}
	}
	if len(rej) > 0 {
		return pp.sendCP(sstpProtoLCP, 4, id, rej)
	}
	if len(nak) > 0 {
		return pp.sendCP(sstpProtoLCP, 3, id, nak)
	}
	pp.authProto, pp.chapAlg = auth, alg
	pp.peerAcked = true
	switch {
	case auth == sstpProtoPAP:
		pp.method = "PAP"
	case auth == sstpProtoEAP:
		pp.method = "EAP"
	case alg == sstpAlgMD5:
		pp.method = "CHAP-MD5"
	case alg == sstpAlgMSCHAPv2:
		pp.method = "MS-CHAPv2"
	case alg == sstpAlgMSCHAPv1:
		pp.method = "MS-CHAPv1"
	}
	if err := pp.sendCP(sstpProtoLCP, 2, id, data); err != nil {
		return err
	}
	return pp.opened()
}

func (pp *sstpPPP) opened() error {
	if !pp.ourAcked || !pp.peerAcked || pp.done {
		return nil
	}
	switch pp.authProto {
	case 0:
		pp.notes = append(pp.notes, "server did not request PPP authentication")
		pp.method = "none"
		pp.finish(nil)
	case sstpProtoPAP:
		if pp.papTries == 0 {
			return pp.sendPAP(true)
		}
	}
	return nil
}

func (pp *sstpPPP) sendPAP(fresh bool) error {
	if fresh {
		pp.papID++
	}
	pp.papTries++
	pp.papSent = time.Now()
	u, p := []byte(pp.user), []byte(pp.pass)
	if len(u) > 255 {
		u = u[:255]
	}
	if len(p) > 255 {
		p = p[:255]
	}
	d := []byte{byte(len(u))}
	d = append(d, u...)
	d = append(d, byte(len(p)))
	d = append(d, p...)
	return pp.sendCP(sstpProtoPAP, 1, pp.papID, d)
}

func (pp *sstpPPP) pap(b []byte) error {
	code, _, data, ok := sstpCPParse(b)
	if !ok {
		return nil
	}
	msg := ""
	if len(data) >= 1 && int(data[0]) <= len(data)-1 {
		msg = sstpPrintable(data[1 : 1+int(data[0])])
	}
	switch code {
	case 2:
		pp.method = "PAP"
		pp.finish(nil)
	case 3:
		if msg != "" {
			pp.fail("PAP authentication rejected: %s", msg)
		} else {
			pp.fail("PAP authentication rejected")
		}
	}
	return nil
}

func (pp *sstpPPP) chap(b []byte) error {
	code, id, data, ok := sstpCPParse(b)
	if !ok {
		return nil
	}
	switch code {
	case 1:
		if len(data) < 1 || len(data) < 1+int(data[0]) {
			return nil
		}
		if int(id) == pp.chapID && pp.chapResp != nil {
			return pp.sendCP(sstpProtoCHAP, 2, id, pp.chapResp)
		}
		ch := data[1 : 1+int(data[0])]
		alg := pp.chapAlg
		if alg == 0 {
			alg = sstpAlgMSCHAPv2
			if len(ch) != 16 {
				alg = sstpAlgMD5
			}
		}
		var resp []byte
		if alg == sstpAlgMSCHAPv2 {
			if len(ch) != 16 {
				pp.finish(errors.New("invalid MS-CHAPv2 challenge"))
				return nil
			}
			pp.method = "MS-CHAPv2"
			val, s := sstpMSCHAPv2Value(ch, pp.hashUser, pp.pass)
			pp.expectS = s
			resp = append([]byte{byte(len(val))}, val...)
		} else if alg == sstpAlgMSCHAPv1 {
			if len(ch) != 8 {
				pp.finish(errors.New("invalid MS-CHAPv1 challenge"))
				return nil
			}
			pp.method = "MS-CHAPv1"
			resp = append([]byte{49}, make([]byte, 24)...)
			resp = append(resp, sstpChallengeResponse(ch, sstpNTHash(pp.pass))...)
			resp = append(resp, 1)
		} else {
			pp.method = "CHAP-MD5"
			h := md5.New()
			h.Write([]byte{id})
			h.Write([]byte(pp.pass))
			h.Write(ch)
			resp = append([]byte{16}, h.Sum(nil)...)
		}
		resp = append(resp, []byte(pp.user)...)
		pp.chapID = int(id)
		pp.chapResp = resp
		return pp.sendCP(sstpProtoCHAP, 2, id, resp)
	case 3:
		msg := string(data)
		if pp.method == "MS-CHAPv2" && pp.expectS != "" {
			if i := strings.Index(msg, "S="); i >= 0 && len(msg) >= i+42 {
				if !strings.EqualFold(msg[i:i+42], pp.expectS) {
					pp.finish(errors.New("MS-CHAPv2 server authenticator response is invalid"))
					return nil
				}
			} else {
				pp.notes = append(pp.notes, "server sent no MS-CHAPv2 authenticator response")
			}
		}
		pp.finish(nil)
	case 4:
		if strings.HasPrefix(pp.method, "MS-CHAP") || strings.Contains(string(data), "E=") {
			m := pp.method
			if !strings.HasPrefix(m, "MS-CHAP") {
				m = "MS-CHAP"
			}
			pp.fail("%s", sstpMSCHAPError(m, string(data)))
		} else if m := sstpPrintable(data); m != "" {
			pp.fail("CHAP authentication failed: %s", m)
		} else {
			pp.fail("CHAP authentication failed")
		}
	}
	return nil
}

func (pp *sstpPPP) sendEAP(id byte, typ byte, d []byte) error {
	body := append([]byte{typ}, d...)
	return pp.sendCP(sstpProtoEAP, 2, id, body)
}

func (pp *sstpPPP) eap(b []byte) error {
	code, id, body, ok := sstpCPParse(b)
	if !ok {
		return nil
	}
	switch code {
	case 1:
		if len(body) < 1 {
			return nil
		}
		typ, d := body[0], body[1:]
		switch typ {
		case 1:
			return pp.sendEAP(id, 1, []byte(pp.user))
		case 2:
			return pp.sendEAP(id, 2, nil)
		case 4:
			if len(d) < 1 || len(d) < 1+int(d[0]) {
				return nil
			}
			pp.method = "EAP-MD5"
			h := md5.New()
			h.Write([]byte{id})
			h.Write([]byte(pp.pass))
			h.Write(d[1 : 1+int(d[0])])
			r := append([]byte{16}, h.Sum(nil)...)
			r = append(r, []byte(pp.user)...)
			pp.eapInner = true
			return pp.sendEAP(id, 4, r)
		case 26:
			return pp.eapMSCHAPv2(id, d)
		default:
			pp.eapNaks++
			if pp.eapNaks > 2 {
				pp.finish(fmt.Errorf("server requires unsupported EAP method %d", typ))
				return nil
			}
			return pp.sendEAP(id, 3, []byte{26, 4})
		}
	case 3:
		pp.finish(nil)
	case 4:
		pp.fail("EAP authentication failed")
	}
	return nil
}

func (pp *sstpPPP) eapMSCHAPv2(id byte, d []byte) error {
	if len(d) < 4 {
		return nil
	}
	op, msid := d[0], d[1]
	rest := d[4:]
	switch op {
	case 1:
		if len(rest) < 17 || rest[0] != 16 {
			pp.finish(errors.New("invalid EAP-MSCHAPv2 challenge"))
			return nil
		}
		pp.method = "EAP-MSCHAPv2"
		val, s := sstpMSCHAPv2Value(rest[1:17], pp.hashUser, pp.pass)
		pp.expectS = s
		r := []byte{2, msid, 0, 0, byte(len(val))}
		r = append(r, val...)
		r = append(r, []byte(pp.user)...)
		binary.BigEndian.PutUint16(r[2:], uint16(len(r)))
		return pp.sendEAP(id, 26, r)
	case 3:
		msg := string(rest)
		if pp.expectS != "" {
			if i := strings.Index(msg, "S="); i >= 0 && len(msg) >= i+42 && !strings.EqualFold(msg[i:i+42], pp.expectS) {
				pp.finish(errors.New("EAP-MSCHAPv2 server authenticator response is invalid"))
				return nil
			}
		}
		pp.eapInner = true
		return pp.sendEAP(id, 26, []byte{3})
	case 4:
		pp.sendEAP(id, 26, []byte{4})
		pp.fail("%s", sstpMSCHAPError("EAP-MSCHAPv2", string(rest)))
	}
	return nil
}

func sstpPrintable(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, string(b))
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

var sstpMSCHAPCodes = map[int]string{
	646: "restricted logon hours",
	647: "account disabled",
	648: "password expired",
	649: "no dial-in permission",
	691: "authentication failure",
	709: "password change required",
}

func sstpMSCHAPError(method, msg string) string {
	code := -1
	text := ""
	for _, f := range strings.Fields(msg) {
		if strings.HasPrefix(f, "E=") {
			code, _ = strconv.Atoi(f[2:])
		}
	}
	if i := strings.Index(msg, "M="); i >= 0 {
		text = sstpPrintable([]byte(msg[i+2:]))
	}
	out := method + " authentication failed"
	if code >= 0 {
		out += fmt.Sprintf(": E=%d", code)
		if n, ok := sstpMSCHAPCodes[code]; ok {
			out += " (" + n + ")"
		}
	}
	if text != "" && !strings.EqualFold(text, sstpMSCHAPCodes[code]) {
		out += ": " + text
	}
	return out
}

func sstpNTHash(pass string) []byte {
	u := utf16.Encode([]rune(pass))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

func sstpChallengeHash(peer, auth []byte, user string) []byte {
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(user))
	return h.Sum(nil)[:8]
}

func sstpDESKey(k []byte) []byte {
	return []byte{
		k[0] & 0xFE,
		(k[0]<<7 | k[1]>>1) & 0xFE,
		(k[1]<<6 | k[2]>>2) & 0xFE,
		(k[2]<<5 | k[3]>>3) & 0xFE,
		(k[3]<<4 | k[4]>>4) & 0xFE,
		(k[4]<<3 | k[5]>>5) & 0xFE,
		(k[5]<<2 | k[6]>>6) & 0xFE,
		k[6] << 1,
	}
}

func sstpChallengeResponse(ch, hash []byte) []byte {
	z := make([]byte, 21)
	copy(z, hash)
	out := make([]byte, 24)
	for i := 0; i < 3; i++ {
		c, _ := des.NewCipher(sstpDESKey(z[i*7 : i*7+7]))
		c.Encrypt(out[i*8:], ch)
	}
	return out
}

func sstpNTResponse(auth, peer []byte, user, pass string) []byte {
	return sstpChallengeResponse(sstpChallengeHash(peer, auth, user), sstpNTHash(pass))
}

var (
	sstpMagic1 = []byte("Magic server to client signing constant")
	sstpMagic2 = []byte("Pad to make it do more than one iteration")
)

func sstpAuthenticatorResponse(pass string, nt, peer, auth []byte, user string) string {
	hh := md4.New()
	hh.Write(sstpNTHash(pass))
	phh := hh.Sum(nil)
	h := sha1.New()
	h.Write(phh)
	h.Write(nt)
	h.Write(sstpMagic1)
	d := h.Sum(nil)
	h = sha1.New()
	h.Write(d)
	h.Write(sstpChallengeHash(peer, auth, user))
	h.Write(sstpMagic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func sstpMSCHAPv2Value(auth []byte, user, pass string) ([]byte, string) {
	peer := make([]byte, 16)
	rand.Read(peer)
	nt := sstpNTResponse(auth, peer, user, pass)
	var v bytes.Buffer
	v.Write(peer)
	v.Write(make([]byte, 8))
	v.Write(nt)
	v.WriteByte(0)
	return v.Bytes(), sstpAuthenticatorResponse(pass, nt, peer, auth, user)
}
