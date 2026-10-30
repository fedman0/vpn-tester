package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	tagAbridged     = 0xefefefef
	tagIntermediate = 0xeeeeeeee
	tagPadded       = 0xdddddddd
)

type mtSecret struct {
	key    []byte
	mode   byte
	domain string
}

func parseMTSecret(s string) (*mtSecret, error) {
	s = strings.TrimSpace(s)
	var b []byte
	if hb, err := hex.DecodeString(s); err == nil {
		b = hb
	} else {
		raw := strings.TrimRight(s, "=")
		if bb, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
			b = bb
		} else if bb, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
			b = bb
		} else {
			return nil, errors.New("bad mtproxy secret")
		}
	}
	switch {
	case len(b) == 16:
		return &mtSecret{key: b}, nil
	case len(b) == 17 && b[0] == 0xdd:
		return &mtSecret{key: b[1:17], mode: 0xdd}, nil
	case len(b) > 17 && b[0] == 0xee:
		return &mtSecret{key: b[1:17], mode: 0xee, domain: string(b[17:])}, nil
	}
	return nil, errors.New("bad mtproxy secret length")
}

func mtproxyFromQuery(q url.Values) (*node, error) {
	host := qget(q, "server")
	port, err := strconv.Atoi(qget(q, "port"))
	if host == "" || err != nil {
		return &node{Proto: "mtproto"}, errors.New("bad mtproxy link")
	}
	sec, err := parseMTSecret(qget(q, "secret"))
	if err != nil {
		return &node{Proto: "mtproto"}, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	proto := "mtproto"
	if sec.mode == 0xee {
		proto = "mtproto-faketls"
	}
	return &node{Proto: proto, Candidates: one(candidate{
		Engine: "mtproto",
		Debug:  map[string]any{"server": addr, "mode": fmt.Sprintf("%x", sec.mode), "domain": sec.domain},
		Probe: func(ctx context.Context) (time.Duration, error) {
			return mtprotoProbe(ctx, addr, sec)
		},
	})}, nil
}

func mtprotoProbe(ctx context.Context, addr string, sec *mtSecret) (time.Duration, error) {
	start := time.Now()
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	deadlineFrom(ctx, c)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	var rw io.ReadWriter = c
	tag := uint32(tagIntermediate)
	if sec.mode != 0 {
		tag = tagPadded
	}
	if sec.mode == 0xee {
		ft, err := fakeTLSHandshake(c, sec)
		if err != nil {
			return 0, err
		}
		rw = ft
	}
	header, enc, dec, err := obfs2Header(sec.key, tag, 2)
	if err != nil {
		return 0, err
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	msg := reqPQMulti(nonce)
	frame := make([]byte, 0, 4+len(msg)+16)
	if tag == tagPadded {
		padLen := int(randByte() % 16)
		frame = binary.LittleEndian.AppendUint32(frame, uint32(len(msg)+padLen))
		frame = append(frame, msg...)
		pad := make([]byte, padLen)
		rand.Read(pad)
		frame = append(frame, pad...)
	} else {
		frame = binary.LittleEndian.AppendUint32(frame, uint32(len(msg)))
		frame = append(frame, msg...)
	}
	encFrame := make([]byte, len(frame))
	enc.XORKeyStream(encFrame, frame)
	if _, err := rw.Write(append(header, encFrame...)); err != nil {
		return 0, err
	}
	sr := cipher.StreamReader{S: dec, R: rw}
	var lb [4]byte
	if _, err := io.ReadFull(sr, lb[:]); err != nil {
		return 0, fmt.Errorf("%w: no mtproto response", errRejected)
	}
	n := int(binary.LittleEndian.Uint32(lb[:]) & 0x7fffffff)
	if n < 4 || n > 1<<16 {
		return 0, fmt.Errorf("%w: bad mtproto frame", errRejected)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(sr, body); err != nil {
		return 0, err
	}
	if n == 4 {
		code := int32(binary.LittleEndian.Uint32(body))
		return 0, fmt.Errorf("%w: mtproto error %d", errRejected, code)
	}
	if n < 40 || binary.LittleEndian.Uint32(body[20:24]) != 0x05162463 || !bytes.Equal(body[24:40], nonce) {
		return 0, fmt.Errorf("%w: unexpected mtproto response", errRejected)
	}
	return time.Since(start), nil
}

func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

func reqPQMulti(nonce []byte) []byte {
	now := time.Now()
	msgID := uint64(now.Unix())<<32 | (uint64(now.Nanosecond()) & 0xfffffffc)
	b := make([]byte, 0, 40)
	b = binary.LittleEndian.AppendUint64(b, 0)
	b = binary.LittleEndian.AppendUint64(b, msgID)
	b = binary.LittleEndian.AppendUint32(b, 20)
	b = binary.LittleEndian.AppendUint32(b, 0xbe7e8ef1)
	return append(b, nonce...)
}

func obfs2Header(key []byte, tag uint32, dc int16) ([]byte, cipher.Stream, cipher.Stream, error) {
	buf := make([]byte, 64)
	for {
		rand.Read(buf)
		if buf[0] == 0xef {
			continue
		}
		first := binary.LittleEndian.Uint32(buf[0:4])
		switch first {
		case 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0x02010316, tagPadded, tagIntermediate:
			continue
		}
		if binary.LittleEndian.Uint32(buf[4:8]) == 0 {
			continue
		}
		break
	}
	binary.LittleEndian.PutUint32(buf[56:60], tag)
	binary.LittleEndian.PutUint16(buf[60:62], uint16(dc))
	rev := make([]byte, 48)
	for i := 0; i < 48; i++ {
		rev[i] = buf[55-i]
	}
	encKey, encIV := append([]byte(nil), buf[8:40]...), buf[40:56]
	decKey, decIV := append([]byte(nil), rev[0:32]...), rev[32:48]
	if len(key) > 0 {
		h := sha256.Sum256(append(encKey, key...))
		encKey = h[:]
		h2 := sha256.Sum256(append(decKey, key...))
		decKey = h2[:]
	}
	eb, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, err
	}
	db, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, nil, nil, err
	}
	enc := cipher.NewCTR(eb, encIV)
	dec := cipher.NewCTR(db, decIV)
	encrypted := make([]byte, 64)
	enc.XORKeyStream(encrypted, buf)
	copy(buf[56:64], encrypted[56:64])
	return buf, enc, dec, nil
}

type fakeTLSConn struct {
	c       net.Conn
	pending []byte
	sentCCS bool
}

func (f *fakeTLSConn) Write(p []byte) (int, error) {
	var out []byte
	if !f.sentCCS {
		out = append(out, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
		f.sentCCS = true
	}
	for off := 0; off < len(p); {
		n := len(p) - off
		if n > 16384 {
			n = 16384
		}
		out = append(out, 0x17, 0x03, 0x03, byte(n>>8), byte(n))
		out = append(out, p[off:off+n]...)
		off += n
	}
	if _, err := f.c.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *fakeTLSConn) Read(p []byte) (int, error) {
	for len(f.pending) == 0 {
		var h [5]byte
		if _, err := io.ReadFull(f.c, h[:]); err != nil {
			return 0, err
		}
		l := int(binary.BigEndian.Uint16(h[3:5]))
		body := make([]byte, l)
		if _, err := io.ReadFull(f.c, body); err != nil {
			return 0, err
		}
		if h[0] == 0x17 {
			f.pending = body
		}
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func fakeTLSHandshake(c net.Conn, sec *mtSecret) (*fakeTLSConn, error) {
	hello := buildClientHello(sec.domain)
	mac := hmac.New(sha256.New, sec.key)
	mac.Write(hello)
	digest := mac.Sum(nil)
	ts := uint32(time.Now().Unix())
	var tsb [4]byte
	binary.LittleEndian.PutUint32(tsb[:], ts)
	for i := 0; i < 4; i++ {
		digest[28+i] ^= tsb[i]
	}
	copy(hello[11:43], digest)
	clientRandom := append([]byte(nil), digest...)
	if _, err := c.Write(hello); err != nil {
		return nil, err
	}
	var resp []byte
	gotApp := false
	for !gotApp {
		var h [5]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return nil, fmt.Errorf("%w: faketls handshake failed", errRejected)
		}
		l := int(binary.BigEndian.Uint16(h[3:5]))
		body := make([]byte, l)
		if _, err := io.ReadFull(c, body); err != nil {
			return nil, err
		}
		resp = append(resp, h[:]...)
		resp = append(resp, body...)
		if h[0] == 0x17 {
			gotApp = true
		}
		if h[0] == 0x15 {
			return nil, fmt.Errorf("%w: faketls alert", errRejected)
		}
	}
	if len(resp) < 43 {
		return nil, fmt.Errorf("%w: short faketls response", errRejected)
	}
	serverRandom := append([]byte(nil), resp[11:43]...)
	zeroed := append([]byte(nil), resp...)
	for i := 11; i < 43; i++ {
		zeroed[i] = 0
	}
	vm := hmac.New(sha256.New, sec.key)
	vm.Write(clientRandom)
	vm.Write(zeroed)
	if !hmac.Equal(vm.Sum(nil), serverRandom) {
		return nil, fmt.Errorf("%w: wrong mtproxy secret (fronting reply)", errRejected)
	}
	return &fakeTLSConn{c: c}, nil
}

func grease() uint16 {
	g := uint16(randByte()&0xf0) | 0x0a
	return g<<8 | g
}

func buildClientHello(domain string) []byte {
	var ext []byte
	addExt := func(typ uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, typ)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	addExt(grease(), nil)
	sni := []byte{0}
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(domain)))
	sni = append(sni, domain...)
	addExt(0x0000, append(binary.BigEndian.AppendUint16(nil, uint16(len(sni))), sni...))
	addExt(0x0017, nil)
	addExt(0xff01, []byte{0})
	groups := []uint16{grease(), 0x001d, 0x0017, 0x0018}
	gb := binary.BigEndian.AppendUint16(nil, uint16(len(groups)*2))
	for _, g := range groups {
		gb = binary.BigEndian.AppendUint16(gb, g)
	}
	addExt(0x000a, gb)
	addExt(0x000b, []byte{1, 0})
	addExt(0x0023, nil)
	alpn := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	addExt(0x0010, append(binary.BigEndian.AppendUint16(nil, uint16(len(alpn))), alpn...))
	addExt(0x0005, []byte{1, 0, 0, 0, 0})
	sigs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	sb := binary.BigEndian.AppendUint16(nil, uint16(len(sigs)*2))
	for _, s := range sigs {
		sb = binary.BigEndian.AppendUint16(sb, s)
	}
	addExt(0x000d, sb)
	addExt(0x0012, nil)
	key := make([]byte, 32)
	rand.Read(key)
	ks := binary.BigEndian.AppendUint16(nil, grease())
	ks = append(ks, 0, 1, 0)
	ks = binary.BigEndian.AppendUint16(ks, 0x001d)
	ks = binary.BigEndian.AppendUint16(ks, 32)
	ks = append(ks, key...)
	addExt(0x0033, append(binary.BigEndian.AppendUint16(nil, uint16(len(ks))), ks...))
	addExt(0x002d, []byte{1, 1})
	vers := []byte{6}
	vers = binary.BigEndian.AppendUint16(vers, grease())
	vers = append(vers, 0x03, 0x04, 0x03, 0x03)
	addExt(0x002b, vers)
	addExt(0x001b, []byte{2, 0, 2})
	addExt(grease(), []byte{0})

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	sid := make([]byte, 32)
	rand.Read(sid)
	body = append(body, 32)
	body = append(body, sid...)
	suites := []uint16{grease(), 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0)
	const target = 517
	cur := 5 + 4 + len(body) + 2 + len(ext)
	if pad := target - cur - 4; pad > 0 {
		addExt(0x0015, make([]byte, pad))
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}
