package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	ike1PlSA       = 1
	ike1PlProp     = 2
	ike1PlTrans    = 3
	ike1PlKE       = 4
	ike1PlID       = 5
	ike1PlCert     = 6
	ike1PlCR       = 7
	ike1PlHash     = 8
	ike1PlSig      = 9
	ike1PlNonce    = 10
	ike1PlNotify   = 11
	ike1PlDelete   = 12
	ike1PlVID      = 13
	ike1PlAttr     = 14
	ike1PlNATD     = 20
	ike1PlNATOA    = 21
	ike1PlNATDOld  = 130
	ike1PlNATOAOld = 131
	ike1PlFrag     = 132

	ike1ExMain  = 2
	ike1ExAggr  = 4
	ike1ExInfo  = 5
	ike1ExTrans = 6
	ike1ExQuick = 32

	ike1FlagEnc    = 0x01
	ike1FlagCommit = 0x02

	ike1IDIPv4  = 1
	ike1IDFQDN  = 2
	ike1IDUFQDN = 3
	ike1IDIPv6  = 5
	ike1IDDN    = 9
	ike1IDKeyID = 11

	ike1AttrEnc     = 1
	ike1AttrHash    = 2
	ike1AttrAuth    = 3
	ike1AttrGroup   = 4
	ike1AttrLifeTyp = 11
	ike1AttrLifeDur = 12
	ike1AttrKeyLen  = 14

	ike1CfgRequest = 1
	ike1CfgReply   = 2
	ike1CfgSet     = 3
	ike1CfgAck     = 4

	ike1XType     = 16520
	ike1XUser     = 16521
	ike1XPass     = 16522
	ike1XPasscode = 16523
	ike1XMessage  = 16524
	ike1XChal     = 16525
	ike1XDomain   = 16526
	ike1XStatus   = 16527
	ike1XNextPin  = 16528
	ike1XAnswer   = 16529

	ike1CfgIP4Addr  = 1
	ike1CfgIP4Mask  = 2
	ike1CfgIP4DNS   = 3
	ike1CfgAppVer   = 7
	ike1UnityBanner = 28672
	ike1UnityDomain = 28674
	ike1UnitySplit  = 28676
)

const ike1HdrLen = 28

type ike1Header struct {
	ICookie [8]byte
	RCookie [8]byte
	Next    byte
	Version byte
	Exch    byte
	Flags   byte
	MsgID   uint32
	Length  uint32
}

func (h *ike1Header) marshal() []byte {
	b := make([]byte, ike1HdrLen)
	copy(b[0:8], h.ICookie[:])
	copy(b[8:16], h.RCookie[:])
	b[16] = h.Next
	b[17] = h.Version
	b[18] = h.Exch
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:24], h.MsgID)
	binary.BigEndian.PutUint32(b[24:28], h.Length)
	return b
}

func ike1ParseHeader(b []byte) (*ike1Header, error) {
	if len(b) < ike1HdrLen {
		return nil, errors.New("short ISAKMP packet")
	}
	h := &ike1Header{}
	copy(h.ICookie[:], b[0:8])
	copy(h.RCookie[:], b[8:16])
	h.Next = b[16]
	h.Version = b[17]
	h.Exch = b[18]
	h.Flags = b[19]
	h.MsgID = binary.BigEndian.Uint32(b[20:24])
	h.Length = binary.BigEndian.Uint32(b[24:28])
	return h, nil
}

type ike1Payload struct {
	Type byte
	Body []byte
	Raw  []byte
}

func ike1Chain(pls []ike1Payload) (byte, []byte) {
	var out []byte
	for i, p := range pls {
		next := byte(0)
		if i+1 < len(pls) {
			next = pls[i+1].Type
		}
		hdr := []byte{next, 0, 0, 0}
		binary.BigEndian.PutUint16(hdr[2:], uint16(4+len(p.Body)))
		out = append(out, hdr...)
		out = append(out, p.Body...)
	}
	if len(pls) == 0 {
		return 0, nil
	}
	return pls[0].Type, out
}

func ike1ParsePayloads(first byte, b []byte) ([]ike1Payload, error) {
	var out []ike1Payload
	next := first
	off := 0
	for next != 0 {
		if off+4 > len(b) {
			return out, fmt.Errorf("truncated payload chain (type %d)", next)
		}
		l := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if l < 4 || off+l > len(b) {
			return out, fmt.Errorf("bad payload length %d (type %d)", l, next)
		}
		out = append(out, ike1Payload{Type: next, Body: b[off+4 : off+l], Raw: b[off : off+l]})
		next = b[off]
		off += l
		if len(out) > 64 {
			return out, errors.New("too many payloads")
		}
	}
	return out, nil
}

func ike1Find(pls []ike1Payload, t byte) *ike1Payload {
	for i := range pls {
		if pls[i].Type == t {
			return &pls[i]
		}
	}
	return nil
}

func ike1FindAll(pls []ike1Payload, t byte) []ike1Payload {
	var out []ike1Payload
	for _, p := range pls {
		if p.Type == t {
			out = append(out, p)
		}
	}
	return out
}

type ike1Attr struct {
	Type  uint16
	TV    bool
	Value []byte
}

func (a ike1Attr) Uint() uint32 {
	var v uint32
	for _, c := range a.Value {
		v = v<<8 | uint32(c)
	}
	return v
}

func ike1AttrTV(t uint16, v uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], 0x8000|t)
	binary.BigEndian.PutUint16(b[2:], v)
	return b
}

func ike1AttrTLV(t uint16, v []byte) []byte {
	b := make([]byte, 4+len(v))
	binary.BigEndian.PutUint16(b[0:], t&0x7fff)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	copy(b[4:], v)
	return b
}

func ike1AttrNum(t uint16, v uint32) []byte {
	if v <= 0xffff {
		return ike1AttrTV(t, uint16(v))
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return ike1AttrTLV(t, b)
}

func ike1ParseAttrs(b []byte) ([]ike1Attr, error) {
	var out []ike1Attr
	off := 0
	for off+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[off:])
		v := b[off+2 : off+4]
		if t&0x8000 != 0 {
			out = append(out, ike1Attr{Type: t & 0x7fff, TV: true, Value: v})
			off += 4
			continue
		}
		l := int(binary.BigEndian.Uint16(v))
		if off+4+l > len(b) {
			return out, errors.New("truncated attribute")
		}
		out = append(out, ike1Attr{Type: t, Value: b[off+4 : off+4+l]})
		off += 4 + l
	}
	return out, nil
}

type ike1Transform struct {
	Enc    uint16
	KeyLen uint16
	Hash   uint16
	Auth   uint16
	Group  uint16
	Life   uint32
}

func (t ike1Transform) String() string {
	return ike1EncName(t.Enc, t.KeyLen) + "-" + ike1HashName(t.Hash) + "-" + ike1GroupName(t.Group)
}

func (t ike1Transform) same(o ike1Transform) bool {
	kl := func(x ike1Transform) uint16 {
		if x.Enc == ike1EncAES && x.KeyLen == 0 {
			return 128
		}
		if x.Enc != ike1EncAES {
			return 0
		}
		return x.KeyLen
	}
	return t.Enc == o.Enc && kl(t) == kl(o) && t.Hash == o.Hash && t.Auth == o.Auth && t.Group == o.Group
}

func ike1BuildSA(trs []ike1Transform) []byte {
	var tb []byte
	for i, t := range trs {
		var attrs []byte
		attrs = append(attrs, ike1AttrTV(ike1AttrEnc, t.Enc)...)
		if t.Enc == ike1EncAES {
			kl := t.KeyLen
			if kl == 0 {
				kl = 128
			}
			attrs = append(attrs, ike1AttrTV(ike1AttrKeyLen, kl)...)
		}
		attrs = append(attrs, ike1AttrTV(ike1AttrHash, t.Hash)...)
		attrs = append(attrs, ike1AttrTV(ike1AttrAuth, t.Auth)...)
		attrs = append(attrs, ike1AttrTV(ike1AttrGroup, t.Group)...)
		life := t.Life
		if life == 0 {
			life = 28800
		}
		attrs = append(attrs, ike1AttrTV(ike1AttrLifeTyp, 1)...)
		attrs = append(attrs, ike1AttrNum(ike1AttrLifeDur, life)...)
		next := byte(ike1PlTrans)
		if i == len(trs)-1 {
			next = 0
		}
		h := []byte{next, 0, 0, 0, byte(i + 1), 1, 0, 0}
		binary.BigEndian.PutUint16(h[2:], uint16(len(h)+len(attrs)))
		tb = append(tb, h...)
		tb = append(tb, attrs...)
	}
	prop := []byte{0, 0, 0, 0, 1, 1, 0, byte(len(trs))}
	binary.BigEndian.PutUint16(prop[2:], uint16(len(prop)+len(tb)))
	body := []byte{0, 0, 0, 1, 0, 0, 0, 1}
	body = append(body, prop...)
	return append(body, tb...)
}

func ike1ParseSA(body []byte) (ike1Transform, error) {
	var t ike1Transform
	if len(body) < 8+8 {
		return t, errors.New("short SA payload")
	}
	if binary.BigEndian.Uint32(body[0:4]) != 1 {
		return t, errors.New("SA payload DOI is not IPsec")
	}
	pb := body[8:]
	pl := int(binary.BigEndian.Uint16(pb[2:4]))
	if pl < 8 || pl > len(pb) {
		return t, errors.New("bad proposal length")
	}
	spi := int(pb[6])
	ntr := int(pb[7])
	off := 8 + spi
	if ntr < 1 || off+8 > pl {
		return t, errors.New("proposal has no transform")
	}
	tr := pb[off:pl]
	tl := int(binary.BigEndian.Uint16(tr[2:4]))
	if tl < 8 || tl > len(tr) {
		return t, errors.New("bad transform length")
	}
	attrs, err := ike1ParseAttrs(tr[8:tl])
	if err != nil {
		return t, err
	}
	for _, a := range attrs {
		v := a.Uint()
		switch a.Type {
		case ike1AttrEnc:
			t.Enc = uint16(v)
		case ike1AttrHash:
			t.Hash = uint16(v)
		case ike1AttrAuth:
			t.Auth = uint16(v)
		case ike1AttrGroup:
			t.Group = uint16(v)
		case ike1AttrKeyLen:
			t.KeyLen = uint16(v)
		case ike1AttrLifeDur:
			t.Life = v
		}
	}
	return t, nil
}

type ike1Notify struct {
	Type uint16
	SPI  []byte
	Data []byte
}

func ike1ParseNotify(body []byte) (ike1Notify, error) {
	if len(body) < 8 {
		return ike1Notify{}, errors.New("short notify")
	}
	spi := int(body[5])
	if 8+spi > len(body) {
		return ike1Notify{}, errors.New("bad notify SPI size")
	}
	return ike1Notify{Type: binary.BigEndian.Uint16(body[6:8]), SPI: body[8 : 8+spi], Data: body[8+spi:]}, nil
}

var ike1NotifyNames = map[uint16]string{
	1: "INVALID-PAYLOAD-TYPE", 2: "DOI-NOT-SUPPORTED", 3: "SITUATION-NOT-SUPPORTED", 4: "INVALID-COOKIE",
	5: "INVALID-MAJOR-VERSION", 6: "INVALID-MINOR-VERSION", 7: "INVALID-EXCHANGE-TYPE", 8: "INVALID-FLAGS",
	9: "INVALID-MESSAGE-ID", 10: "INVALID-PROTOCOL-ID", 11: "INVALID-SPI", 12: "INVALID-TRANSFORM-ID",
	13: "ATTRIBUTES-NOT-SUPPORTED", 14: "NO-PROPOSAL-CHOSEN", 15: "BAD-PROPOSAL-SYNTAX", 16: "PAYLOAD-MALFORMED",
	17: "INVALID-KEY-INFORMATION", 18: "INVALID-ID-INFORMATION", 19: "INVALID-CERT-ENCODING", 20: "INVALID-CERTIFICATE",
	21: "CERT-TYPE-UNSUPPORTED", 22: "INVALID-CERT-AUTHORITY", 23: "INVALID-HASH-INFORMATION", 24: "AUTHENTICATION-FAILED",
	25: "INVALID-SIGNATURE", 26: "ADDRESS-NOTIFICATION", 27: "NOTIFY-SA-LIFETIME", 28: "CERTIFICATE-UNAVAILABLE",
	29: "UNSUPPORTED-EXCHANGE-TYPE", 30: "UNEQUAL-PAYLOAD-LENGTHS", 16384: "CONNECTED", 24576: "RESPONDER-LIFETIME",
	24577: "REPLAY-STATUS", 24578: "INITIAL-CONTACT", 36136: "R-U-THERE", 36137: "R-U-THERE-ACK",
	ike1NotifyDeleted: "DELETE (server tore down the IKE SA)",
}

const ike1NotifyDeleted = 8191

func ike1NotifyName(t uint16) string {
	if s, ok := ike1NotifyNames[t]; ok {
		return s
	}
	return fmt.Sprintf("NOTIFY-%d", t)
}

func ike1Notification(proto byte, typ uint16, spi, data []byte) []byte {
	b := []byte{0, 0, 0, 1, proto, byte(len(spi)), 0, 0}
	binary.BigEndian.PutUint16(b[6:], typ)
	b = append(b, spi...)
	return append(b, data...)
}

func ike1DeletePayload(spi []byte) []byte {
	b := []byte{0, 0, 0, 1, 1, byte(len(spi)), 0, 1}
	return append(b, spi...)
}

func ike1CfgPayload(typ byte, id uint16, attrs ...[]byte) []byte {
	b := []byte{typ, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], id)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

type ike1Cfg struct {
	Type  byte
	ID    uint16
	Attrs []ike1Attr
}

func ike1ParseCfg(body []byte) (ike1Cfg, error) {
	if len(body) < 4 {
		return ike1Cfg{}, errors.New("short attribute payload")
	}
	attrs, err := ike1ParseAttrs(body[4:])
	return ike1Cfg{Type: body[0], ID: binary.BigEndian.Uint16(body[2:4]), Attrs: attrs}, err
}

func (c ike1Cfg) has(t uint16) bool {
	for _, a := range c.Attrs {
		if a.Type == t {
			return true
		}
	}
	return false
}

func (c ike1Cfg) get(t uint16) (ike1Attr, bool) {
	for _, a := range c.Attrs {
		if a.Type == t {
			return a, true
		}
	}
	return ike1Attr{}, false
}

func ike1MustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

var (
	ike1VIDNatRFC   = ike1MustHex("4a131c81070358455c5728f20e95452f")
	ike1VIDNat02    = ike1MustHex("cd60464335df21f87cfdb2fc68b6a448")
	ike1VIDNat02n   = ike1MustHex("90cb80913ebb696e086381b5ec427b1f")
	ike1VIDNat03    = ike1MustHex("7d9419a65310ca6f2c179d9215529d56")
	ike1VIDXauth    = ike1MustHex("09002689dfd6b712")
	ike1VIDUnity    = ike1MustHex("12f5f28c457168a9702d9fe274cc0100")
	ike1VIDDPD      = ike1MustHex("afcad71368a1f1c96b8696fc77570100")
	ike1VIDFrag     = ike1MustHex("4048b7d56ebce88525e7de7f00d6c2d3")
	ike1VIDFragFull = ike1MustHex("4048b7d56ebce88525e7de7f00d6c2d380000000")
)
