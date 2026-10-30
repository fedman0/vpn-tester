package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func ckTestParseHello(rec []byte) (random, sid, share []byte, sni string, err error) {
	if len(rec) < 9 || !bytes.Equal(rec[:3], []byte{0x16, 0x03, 0x01}) || rec[5] != 0x01 {
		return nil, nil, nil, "", errors.New("not a ClientHello")
	}
	b := rec[5:]
	if int(b[1])<<16|int(b[2])<<8|int(b[3]) != len(b)-4 {
		return nil, nil, nil, "", errors.New("hello length mismatch")
	}
	p := 4 + 2
	random = b[p : p+32]
	p += 32
	sid = b[p+1 : p+1+int(b[p])]
	p += 1 + int(b[p])
	p += 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 1 + int(b[p])
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	if end != len(b) {
		return nil, nil, nil, "", errors.New("extensions length mismatch")
	}
	p += 2
	for p < end {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		d := b[p+4 : p+4+l]
		p += 4 + l
		switch typ {
		case 0x0000:
			sni = string(d[5:])
		case 0x0033:
			for q := 2; q < len(d); {
				g := binary.BigEndian.Uint16(d[q:])
				kl := int(binary.BigEndian.Uint16(d[q+2:]))
				if g == 0x001d {
					share = d[q+4 : q+4+kl]
				}
				q += 4 + kl
			}
		}
	}
	return
}

type ckTestServer struct {
	priv *ecdh.PrivateKey
	uid  []byte
}

func (s *ckTestServer) serve(t *testing.T, c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	io.ReadFull(br, body)
	random, sid, share, sni, err := ckTestParseHello(append(hdr[:], body...))
	if err != nil || len(share) != 32 || len(sid) != 32 || sni == "" {
		t.Errorf("bad hello: %v share=%d sid=%d sni=%q", err, len(share), len(sid), sni)
		return
	}
	pub, _ := ecdh.X25519().NewPublicKey(random)
	shared, _ := s.priv.ECDH(pub)
	gcm, _ := ckGCM(shared)
	plain, err := gcm.Open(nil, random[:12], append(append([]byte{}, sid...), share...), nil)
	if err != nil || !bytes.Equal(plain[:16], s.uid) || string(bytes.Trim(plain[16:28], "\x00")) != "openvpn" {
		c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76})
		c.Write(make([]byte, 118))
		return
	}
	var key [32]byte
	rand.Read(key[:])
	nonce := make([]byte, 12)
	rand.Read(nonce)
	enc := gcm.Seal(nil, nonce, key[:], nil)
	sh := []byte{0x02, 0x00, 0x00, 0x76, 0x03, 0x03}
	sh = append(sh, nonce...)
	sh = append(sh, enc[:20]...)
	sh = append(sh, 0x20)
	sh = append(sh, sid...)
	sh = append(sh, 0x13, 0x02, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	sh = append(sh, enc[20:48]...)
	sh = append(sh, 0, 0, 0, 0, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	out := append([]byte{0x16, 0x03, 0x03, byte(len(sh) >> 8), byte(len(sh))}, sh...)
	out = append(out, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	out = append(out, 0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5)
	c.Write(out)
	sc := &ckConn{raw: c, br: br, stream: 1}
	sc.key = key
	sc.aead, _ = ckGCM(key[:])
	buf := make([]byte, 4096)
	for {
		n, err := sc.Read(buf)
		if err != nil {
			return
		}
		sc.Write(append([]byte("echo:"), buf[:n]...))
	}
}

func ckTestSetup(t *testing.T) (*ckTestServer, string, int) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	uid := make([]byte, 16)
	rand.Read(uid)
	srv := &ckTestServer{priv: priv, uid: uid}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(t, c)
		}
	}()
	return srv, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func ckTestConfig(srv *ckTestServer, host string, port int, uid []byte, browser string) *ckConfig {
	m := map[string]any{
		"ServerName": "tile.openstreetmap.org", "ProxyMethod": "openvpn", "EncryptionMethod": "aes-gcm",
		"UID": base64.StdEncoding.EncodeToString(uid), "PublicKey": base64.StdEncoding.EncodeToString(srv.priv.PublicKey().Bytes()),
		"RemoteHost": host, "RemotePort": "1", "BrowserSig": browser, "NumConn": 1, "Transport": "direct",
	}
	ck, err := ckParseConfig(m, "", 0)
	if err != nil {
		panic(err)
	}
	ck.RemotePort = port
	return ck
}

func TestCloakHandshakeAndStream(t *testing.T) {
	srv, host, port := ckTestSetup(t)
	for _, browser := range []string{"chrome", "firefox"} {
		ck := ckTestConfig(srv, host, port, srv.uid, browser)
		raw, err := net.Dial("tcp", net.JoinHostPort(ck.RemoteHost, strconv.Itoa(ck.RemotePort)))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cc, err := ckHandshake(ctx, raw, ck)
		cancel()
		if err != nil {
			t.Fatalf("%s: handshake: %v", browser, err)
		}
		big := bytes.Repeat([]byte("x"), 40000)
		if _, err := cc.Write(big[:5]); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		n, err := io.ReadAtLeast(cc, got, 10)
		if err != nil || string(got[:n]) != "echo:xxxxx" {
			t.Fatalf("%s: echo got %q err %v", browser, got[:n], err)
		}
		cc.Close()
	}
}

func TestCloakWrongUID(t *testing.T) {
	srv, host, port := ckTestSetup(t)
	bad := make([]byte, 16)
	ck := ckTestConfig(srv, host, port, bad, "chrome")
	raw, err := net.Dial("tcp", net.JoinHostPort(ck.RemoteHost, strconv.Itoa(ck.RemotePort)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ckHandshake(ctx, raw, ck); !errors.Is(err, errCkRejected) {
		t.Fatalf("want rejection, got %v", err)
	}
}

func TestCloakHelloSize(t *testing.T) {
	for _, b := range []string{"chrome", "firefox", "safari"} {
		h := ckBuildHello(ckHelloFields{random: make([]byte, 32), sessionID: make([]byte, 32), keyShare: make([]byte, 32), serverName: "tile.openstreetmap.org", browser: b})
		if len(h) > 1400 {
			t.Fatalf("%s hello too large: %d", b, len(h))
		}
		if _, _, share, sni, err := ckTestParseHello(h); err != nil || len(share) != 32 || sni != "tile.openstreetmap.org" {
			t.Fatalf("%s: %v %d %q", b, err, len(share), sni)
		}
	}
}

func TestCloakConfigErrors(t *testing.T) {
	base := map[string]any{"ServerName": "a.com", "ProxyMethod": "openvpn", "EncryptionMethod": "aes-gcm",
		"UID": base64.StdEncoding.EncodeToString(make([]byte, 16)), "PublicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)), "RemoteHost": "h"}
	if _, err := ckParseConfig(base, "", 0); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{"Transport": "cdn", "EncryptionMethod": "rc4", "PublicKey": "AAAA", "ProxyMethod": ""} {
		m := map[string]any{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		if _, err := ckParseConfig(m, "", 0); err == nil {
			t.Fatalf("%s=%v accepted", k, v)
		}
	}
	old := map[string]any{}
	for a, b := range base {
		old[a] = b
	}
	delete(old, "RemoteHost")
	old["remote"], old["port"] = "1.2.3.4", "8443"
	ck, err := ckParseConfig(old, "", 0)
	if err != nil || ck.RemoteHost != "1.2.3.4" || ck.RemotePort != 8443 {
		t.Fatalf("legacy remote/port: %v %+v", err, ck)
	}
}
