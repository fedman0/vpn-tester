package main

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
)

type ckHelloFields struct {
	random     []byte
	sessionID  []byte
	keyShare   []byte
	serverName string
	browser    string
}

func ckGrease() uint16 {
	var b [1]byte
	rand.Read(b[:])
	v := uint16(b[0]&0xf0) | 0x0a
	return v<<8 | v
}

type ckExt struct {
	typ  uint16
	data []byte
}

func ckU16(v int) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

func ckU16List(vals ...uint16) []byte {
	b := ckU16(len(vals) * 2)
	for _, v := range vals {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

func ckSNIExt(name string) []byte {
	if name == "" {
		return nil
	}
	entry := append([]byte{0}, ckU16(len(name))...)
	entry = append(entry, name...)
	return append(ckU16(len(entry)), entry...)
}

func ckALPN(protos ...string) []byte {
	var l []byte
	for _, p := range protos {
		l = append(l, byte(len(p)))
		l = append(l, p...)
	}
	return append(ckU16(len(l)), l...)
}

func ckKeyShareExt(grease uint16, x25519 []byte) []byte {
	var shares []byte
	if grease != 0 {
		shares = binary.BigEndian.AppendUint16(shares, grease)
		shares = append(shares, 0, 1, 0)
	}
	shares = binary.BigEndian.AppendUint16(shares, 0x001d)
	shares = append(shares, ckU16(len(x25519))...)
	shares = append(shares, x25519...)
	return append(ckU16(len(shares)), shares...)
}

func ckVersionsExt(grease uint16) []byte {
	var v []byte
	if grease != 0 {
		v = binary.BigEndian.AppendUint16(v, grease)
	}
	v = append(v, 0x03, 0x04, 0x03, 0x03)
	return append([]byte{byte(len(v))}, v...)
}

func ckChromeHello(f ckHelloFields) ([]uint16, []ckExt) {
	g := ckGrease()
	suites := []uint16{g, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	gg := ckGrease()
	for gg == g {
		gg = ckGrease()
	}
	mid := []ckExt{
		{0x0000, ckSNIExt(f.serverName)},
		{0x0017, nil},
		{0xff01, []byte{0}},
		{0x000a, ckU16List(gg, 0x001d, 0x0017, 0x0018)},
		{0x000b, []byte{1, 0}},
		{0x0023, nil},
		{0x0010, ckALPN("h2", "http/1.1")},
		{0x0005, []byte{1, 0, 0, 0, 0}},
		{0x000d, ckU16List(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)},
		{0x0012, nil},
		{0x0033, ckKeyShareExt(gg, f.keyShare)},
		{0x002d, []byte{1, 1}},
		{0x002b, ckVersionsExt(ckGrease())},
		{0x001b, []byte{2, 0, 2}},
		{0x4469, ckALPN("h2")},
	}
	if f.serverName == "" {
		mid = mid[1:]
	}
	mrand.Shuffle(len(mid), func(i, j int) { mid[i], mid[j] = mid[j], mid[i] })
	exts := append([]ckExt{{ckGrease(), nil}}, mid...)
	exts = append(exts, ckExt{ckGrease(), []byte{0}})
	return suites, exts
}

func ckFirefoxHello(f ckHelloFields) ([]uint16, []ckExt) {
	suites := []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	exts := []ckExt{
		{0x0000, ckSNIExt(f.serverName)},
		{0x0017, nil},
		{0xff01, []byte{0}},
		{0x000a, ckU16List(0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101)},
		{0x000b, []byte{1, 0}},
		{0x0023, nil},
		{0x0010, ckALPN("h2", "http/1.1")},
		{0x0005, []byte{1, 0, 0, 0, 0}},
		{0x0022, ckU16List(0x0403, 0x0503, 0x0603, 0x0203)},
		{0x0033, ckKeyShareExt(0, f.keyShare)},
		{0x002b, ckVersionsExt(0)},
		{0x000d, ckU16List(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201)},
		{0x002d, []byte{1, 1}},
		{0x001c, []byte{0x40, 0x01}},
	}
	if f.serverName == "" {
		exts = exts[1:]
	}
	return suites, exts
}

func ckBuildHello(f ckHelloFields) []byte {
	var suites []uint16
	var exts []ckExt
	chrome := f.browser != "firefox" && f.browser != "safari"
	if chrome {
		suites, exts = ckChromeHello(f)
	} else {
		suites, exts = ckFirefoxHello(f)
	}
	body := []byte{0x03, 0x03}
	body = append(body, f.random...)
	body = append(body, byte(len(f.sessionID)))
	body = append(body, f.sessionID...)
	body = append(body, ckU16List(suites...)...)
	body = append(body, 1, 0)
	var eb []byte
	for _, e := range exts {
		eb = binary.BigEndian.AppendUint16(eb, e.typ)
		eb = append(eb, ckU16(len(e.data))...)
		eb = append(eb, e.data...)
	}
	if chrome {
		l := 4 + len(body) + 2 + len(eb)
		if l > 0xff && l < 0x200 {
			pad := 0x200 - l
			if pad >= 5 {
				pad -= 4
			} else {
				pad = 1
			}
			eb = append(eb, 0x00, 0x15)
			eb = append(eb, ckU16(pad)...)
			eb = append(eb, make([]byte, pad)...)
		}
	}
	body = append(body, ckU16(len(eb))...)
	body = append(body, eb...)
	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	msg = append(msg, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, ckU16(len(msg))...)
	return append(rec, msg...)
}
