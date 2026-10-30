package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func sstpHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSSTPMSCHAPv2Vectors(t *testing.T) {
	auth := sstpHex(t, "5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28")
	peer := sstpHex(t, "21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E")
	if got, want := sstpChallengeHash(peer, auth, "User"), sstpHex(t, "D0 2E 43 86 BC E9 12 26"); !bytes.Equal(got, want) {
		t.Fatalf("challenge hash %x want %x", got, want)
	}
	if got, want := sstpNTHash("clientPass"), sstpHex(t, "44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE"); !bytes.Equal(got, want) {
		t.Fatalf("nt hash %x want %x", got, want)
	}
	nt := sstpNTResponse(auth, peer, "User", "clientPass")
	if want := sstpHex(t, "82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF"); !bytes.Equal(nt, want) {
		t.Fatalf("nt response %x want %x", nt, want)
	}
	if got, want := sstpAuthenticatorResponse("clientPass", nt, peer, auth, "User"), "S=407A5589115FD0D6209F510FE9C04566932CDA56"; got != want {
		t.Fatalf("authenticator %s want %s", got, want)
	}
}

func TestSSTPMSCHAPError(t *testing.T) {
	got := sstpMSCHAPError("MS-CHAPv2", "E=691 R=0 C=00112233445566778899AABBCCDDEEFF V=3 M=Bad user")
	if !strings.Contains(got, "E=691") || !strings.Contains(got, "authentication failure") || !strings.Contains(got, "Bad user") {
		t.Fatal(got)
	}
}

func TestSSTPHostPort(t *testing.T) {
	cases := []struct {
		in   string
		port int
		h    string
		p    int
	}{
		{"vpn.example.com", 0, "vpn.example.com", 443},
		{"vpn.example.com:4433", 0, "vpn.example.com", 4433},
		{"https://vpn.example.com:8443/x", 0, "vpn.example.com", 8443},
		{"[2001:db8::1]:444", 0, "2001:db8::1", 444},
		{"2001:db8::1", 0, "2001:db8::1", 443},
		{"1.2.3.4", 555, "1.2.3.4", 555},
	}
	for _, c := range cases {
		h, p := sstpHostPort(c.in, c.port, 443)
		if h != c.h || p != c.p {
			t.Fatalf("%s -> %s %d", c.in, h, p)
		}
	}
}

func TestSSTPLCPNegotiation(t *testing.T) {
	var sent [][]byte
	pp := newSSTPPPP("user", "", "pw", func(f []byte) error { sent = append(sent, append([]byte(nil), f...)); return nil })
	if err := pp.start(); err != nil {
		t.Fatal(err)
	}
	eapReq := []byte{0xFF, 0x03, 0xC0, 0x21, 1, 7, 0, 8, 3, 4, 0xC2, 0x27}
	pp.input(eapReq)
	last := sent[len(sent)-1]
	if last[4] != 3 || !bytes.Equal(last[8:], []byte{3, 5, 0xC2, 0x23, 0x81}) {
		t.Fatalf("expected nak towards mschapv2, got %x", last)
	}
	req := []byte{0xFF, 0x03, 0xC0, 0x21, 1, 8, 0, 9, 3, 5, 0xC2, 0x23, 0x81}
	pp.input(req)
	last = sent[len(sent)-1]
	if last[4] != 2 || pp.method != "MS-CHAPv2" {
		t.Fatalf("expected ack, got %x", last)
	}
	pp.input([]byte{0xFF, 0x03, 0xC0, 0x21, 2, pp.reqID, 0, 4})
	ch := append([]byte{0xC2, 0x23, 1, 9, 0, 0, 16}, bytes.Repeat([]byte{7}, 16)...)
	ch = append(ch, 's', 'r', 'v')
	ch[5] = byte(len(ch) - 2)
	pp.input(ch)
	last = sent[len(sent)-1]
	if last[4] != 2 || last[5] != 9 || last[8] != 49 {
		t.Fatalf("bad chap response %x", last)
	}
	pp.input([]byte{0xC2, 0x23, 4, 9, 0, 0x14, 'E', '=', '6', '9', '1', ' ', 'R', '=', '0', ' ', 'V', '=', '3', ' ', 'M', '='})
	if !pp.done {
		t.Fatal("not done")
	}
	if _, ok := pp.err.(*sstpAuthFailure); !ok {
		t.Fatalf("expected auth failure, got %v", pp.err)
	}
}
