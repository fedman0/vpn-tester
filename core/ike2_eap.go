package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	ike2EAPRequest  = 1
	ike2EAPResponse = 2
	ike2EAPSuccess  = 3
	ike2EAPFailure  = 4

	ike2EAPIdentity = 1
	ike2EAPNotify   = 2
	ike2EAPNak      = 3
	ike2EAPMD5      = 4
	ike2EAPGTC      = 6
	ike2EAPTLS      = 13
	ike2EAPTTLS     = 21
	ike2EAPPEAP     = 25
	ike2EAPMSCHAPv2 = 26
)

var ike2EAPNames = map[byte]string{
	ike2EAPIdentity: "Identity", ike2EAPNotify: "Notification", ike2EAPNak: "Nak", ike2EAPMD5: "EAP-MD5",
	5: "EAP-OTP", ike2EAPGTC: "EAP-GTC", ike2EAPTLS: "EAP-TLS", 18: "EAP-SIM", ike2EAPTTLS: "EAP-TTLS",
	23: "EAP-AKA", ike2EAPPEAP: "PEAP", ike2EAPMSCHAPv2: "EAP-MSCHAPv2", 38: "EAP-TNC", 43: "EAP-FAST", 50: "EAP-AKA'",
}

func ike2EAPName(t byte) string {
	if n, ok := ike2EAPNames[t]; ok {
		return n
	}
	return fmt.Sprintf("EAP type %d", t)
}

type ike2EAPState int

const (
	ike2EAPContinue ike2EAPState = iota
	ike2EAPDoneOK
	ike2EAPDoneFail
	ike2EAPCannot
)

type ike2EAP struct {
	identity  string
	password  string
	method    byte
	tls       *ike2EAPTLSState
	msk       []byte
	used      byte
	nakSent   bool
	requested byte
	failure   string
	mutual    bool
	authResp  string
}

func ike2EAPMethodByName(n string) byte {
	switch strings.ToLower(strings.TrimPrefix(strings.ToLower(n), "eap-")) {
	case "mschapv2", "mschap", "ms-chapv2":
		return ike2EAPMSCHAPv2
	case "md5":
		return ike2EAPMD5
	case "gtc":
		return ike2EAPGTC
	case "tls":
		return ike2EAPTLS
	case "ttls":
		return ike2EAPTTLS
	case "peap":
		return ike2EAPPEAP
	}
	return 0
}

func (e *ike2EAP) allowed(t byte) bool {
	if e.method != 0 {
		return t == e.method
	}
	switch t {
	case ike2EAPMSCHAPv2, ike2EAPMD5, ike2EAPGTC:
		return e.password != ""
	case ike2EAPTLS:
		return e.tls != nil
	}
	return false
}

func (e *ike2EAP) supported() []byte {
	if e.method != 0 {
		return []byte{e.method}
	}
	var out []byte
	if e.password != "" {
		out = append(out, ike2EAPMSCHAPv2, ike2EAPMD5, ike2EAPGTC)
	}
	if e.tls != nil {
		out = append(out, ike2EAPTLS)
	}
	return out
}

func ike2EAPPacket(code, id byte, typ byte, data []byte) []byte {
	l := 4
	if code == ike2EAPRequest || code == ike2EAPResponse {
		l += 1 + len(data)
	}
	b := []byte{code, id, byte(l >> 8), byte(l)}
	if l > 4 {
		b = append(b, typ)
		b = append(b, data...)
	}
	return b
}

func (e *ike2EAP) process(pkt []byte) ([]byte, ike2EAPState, error) {
	if len(pkt) < 4 {
		return nil, ike2EAPDoneFail, errors.New("short EAP packet")
	}
	code, id := pkt[0], pkt[1]
	l := int(binary.BigEndian.Uint16(pkt[2:4]))
	if l < 4 || l > len(pkt) {
		return nil, ike2EAPDoneFail, errors.New("bad EAP length")
	}
	pkt = pkt[:l]
	switch code {
	case ike2EAPSuccess:
		return nil, ike2EAPDoneOK, nil
	case ike2EAPFailure:
		if e.failure == "" {
			e.failure = "EAP failure"
		}
		return nil, ike2EAPDoneFail, nil
	case ike2EAPRequest:
	default:
		return nil, ike2EAPDoneFail, fmt.Errorf("unexpected EAP code %d", code)
	}
	if l < 5 {
		return nil, ike2EAPDoneFail, errors.New("EAP request without type")
	}
	typ := pkt[4]
	data := pkt[5:]
	switch typ {
	case ike2EAPIdentity:
		if e.identity == "" {
			return nil, ike2EAPCannot, errors.New("no EAP identity in config")
		}
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPIdentity, []byte(e.identity)), ike2EAPContinue, nil
	case ike2EAPNotify:
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPNotify, nil), ike2EAPContinue, nil
	}
	if !e.allowed(typ) {
		sup := e.supported()
		if len(sup) == 0 || e.nakSent || e.used != 0 {
			return nil, ike2EAPCannot, fmt.Errorf("server requested %s", ike2EAPName(typ))
		}
		e.nakSent = true
		e.requested = typ
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPNak, sup), ike2EAPContinue, nil
	}
	e.used = typ
	switch typ {
	case ike2EAPMSCHAPv2:
		return e.mschap(id, data)
	case ike2EAPMD5:
		if len(data) < 1 || int(data[0])+1 > len(data) {
			return nil, ike2EAPDoneFail, errors.New("bad EAP-MD5 challenge")
		}
		ch := data[1 : 1+int(data[0])]
		h := md5.New()
		h.Write([]byte{id})
		h.Write([]byte(e.password))
		h.Write(ch)
		v := h.Sum(nil)
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPMD5, append([]byte{16}, v...)), ike2EAPContinue, nil
	case ike2EAPGTC:
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPGTC, []byte(e.password)), ike2EAPContinue, nil
	case ike2EAPTLS:
		out, st, err := e.tls.process(id, data)
		if st == ike2EAPContinue && err == nil && e.tls.msk != nil {
			e.msk = e.tls.msk
		}
		return out, st, err
	}
	return nil, ike2EAPCannot, fmt.Errorf("server requested %s", ike2EAPName(typ))
}

func ike2UTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func ike2NTHash(pw string) []byte {
	h := md4.New()
	h.Write(ike2UTF16LE(pw))
	return h.Sum(nil)
}

func ike2DESKey(k []byte) []byte {
	out := []byte{
		k[0] >> 1,
		(k[0]&0x01)<<6 | k[1]>>2,
		(k[1]&0x03)<<5 | k[2]>>3,
		(k[2]&0x07)<<4 | k[3]>>4,
		(k[3]&0x0f)<<3 | k[4]>>5,
		(k[4]&0x1f)<<2 | k[5]>>6,
		(k[5]&0x3f)<<1 | k[6]>>7,
		k[6] & 0x7f,
	}
	for i := range out {
		out[i] <<= 1
	}
	return out
}

func ike2ChallengeResponse(ch, pwHash []byte) []byte {
	z := make([]byte, 21)
	copy(z, pwHash)
	out := make([]byte, 24)
	for i := 0; i < 3; i++ {
		c, _ := des.NewCipher(ike2DESKey(z[7*i : 7*i+7]))
		c.Encrypt(out[8*i:], ch)
	}
	return out
}

func ike2MSUser(u string) string {
	if i := strings.LastIndex(u, "\\"); i >= 0 {
		return u[i+1:]
	}
	return u
}

func ike2ChallengeHash(peer, auth []byte, user string) []byte {
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(ike2MSUser(user)))
	return h.Sum(nil)[:8]
}

func ike2AuthenticatorResponse(pwHash, nt, peer, auth []byte, user string) string {
	m1 := []byte("Magic server to client signing constant")
	m2 := []byte("Pad to make it do more than one iteration")
	hh := md4.New()
	hh.Write(pwHash)
	phh := hh.Sum(nil)
	h := sha1.New()
	h.Write(phh)
	h.Write(nt)
	h.Write(m1)
	d := h.Sum(nil)
	h = sha1.New()
	h.Write(d)
	h.Write(ike2ChallengeHash(peer, auth, user))
	h.Write(m2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func ike2MSCHAPMSK(pwHash, nt []byte) []byte {
	hh := md4.New()
	hh.Write(pwHash)
	phh := hh.Sum(nil)
	h := sha1.New()
	h.Write(phh)
	h.Write(nt)
	h.Write([]byte("This is the MPPE Master Key"))
	mk := h.Sum(nil)[:16]
	pad1 := make([]byte, 40)
	pad2 := make([]byte, 40)
	for i := range pad2 {
		pad2[i] = 0xf2
	}
	start := func(magic string) []byte {
		h := sha1.New()
		h.Write(mk)
		h.Write(pad1)
		h.Write([]byte(magic))
		h.Write(pad2)
		return h.Sum(nil)[:16]
	}
	recv := start("On the client side, this is the send key; on the server side, it is the receive key.")
	send := start("On the client side, this is the receive key; on the server side, it is the send key.")
	return append(append(append([]byte{}, recv...), send...), make([]byte, 32)...)
}

func (e *ike2EAP) mschap(id byte, data []byte) ([]byte, ike2EAPState, error) {
	if len(data) < 4 {
		return nil, ike2EAPDoneFail, errors.New("short EAP-MSCHAPv2 packet")
	}
	op, msid := data[0], data[1]
	switch op {
	case 1:
		if len(data) < 5 || data[4] != 16 || len(data) < 21 {
			return nil, ike2EAPDoneFail, errors.New("bad EAP-MSCHAPv2 challenge")
		}
		authCh := data[5:21]
		peerCh := ike2Random(16)
		pwHash := ike2NTHash(e.password)
		nt := ike2ChallengeResponse(ike2ChallengeHash(peerCh, authCh, e.identity), pwHash)
		val := make([]byte, 0, 49)
		val = append(val, peerCh...)
		val = append(val, make([]byte, 8)...)
		val = append(val, nt...)
		val = append(val, 0)
		name := []byte(e.identity)
		msl := 5 + 49 + len(name)
		body := []byte{2, msid, byte(msl >> 8), byte(msl), 49}
		body = append(body, val...)
		body = append(body, name...)
		e.authResp = ike2AuthenticatorResponse(pwHash, nt, peerCh, authCh, e.identity)
		e.msk = ike2MSCHAPMSK(pwHash, nt)
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPMSCHAPv2, body), ike2EAPContinue, nil
	case 3:
		msg := string(data[4:])
		if len(msg) < 42 || subtle.ConstantTimeCompare([]byte(strings.ToUpper(msg[:42])), []byte(e.authResp)) != 1 {
			e.failure = "EAP-MSCHAPv2 authenticator response mismatch (server does not know the password)"
			return nil, ike2EAPDoneFail, nil
		}
		e.mutual = true
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPMSCHAPv2, []byte{3}), ike2EAPContinue, nil
	case 4:
		msg := string(data[4:])
		e.failure = "EAP-MSCHAPv2 failure"
		for _, f := range strings.Fields(msg) {
			if strings.HasPrefix(f, "E=") {
				code := f[2:]
				switch code {
				case "691":
					e.failure = "EAP-MSCHAPv2 failure E=691 (wrong username or password)"
				case "648":
					e.failure = "EAP-MSCHAPv2 failure E=648 (password expired)"
				case "647":
					e.failure = "EAP-MSCHAPv2 failure E=647 (account disabled)"
				case "649":
					e.failure = "EAP-MSCHAPv2 failure E=649 (no dial-in permission)"
				default:
					e.failure = "EAP-MSCHAPv2 failure E=" + code
				}
			}
		}
		e.msk = nil
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPMSCHAPv2, []byte{4}), ike2EAPContinue, nil
	}
	return nil, ike2EAPDoneFail, fmt.Errorf("unexpected EAP-MSCHAPv2 opcode %d", op)
}
