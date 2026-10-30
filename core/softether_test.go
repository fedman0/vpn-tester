package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestSESHA0(t *testing.T) {
	s := seSHA0([]byte("abc"))
	if hex.EncodeToString(s[:]) != "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880" {
		t.Fatalf("sha0(abc) = %x", s)
	}
	long := seSHA0(bytes.Repeat([]byte("a"), 1000000))
	if hex.EncodeToString(long[:]) != "3232affa48628a26653b5aaa44541fd90d690603" {
		t.Fatalf("sha0(1M a) = %x", long)
	}
	if got := base64.StdEncoding.EncodeToString(seHashPassword("vpn", "vpn")); got != "H8N7rT8BH44q0nFXC9NlFxetGzQ=" {
		t.Fatalf("hash(vpn,vpn) = %s", got)
	}
}

func TestSEWaterMark(t *testing.T) {
	if len(seWaterMark) != 1411 || !bytes.HasPrefix(seWaterMark, []byte("GIF89a")) {
		t.Fatalf("watermark length %d", len(seWaterMark))
	}
}

func TestSEPackRoundTrip(t *testing.T) {
	p := &sePack{}
	p.addStr("hello", "SoftEther VPN Server")
	p.addInt("version", 443)
	p.addData("random", bytes.Repeat([]byte{7}, 20))
	p.set("big", sePackInt64, 1<<40, nil)
	p.set("uni", sePackUniStr, 0, []byte("héllo"))
	q, err := seDecodePack(p.encode())
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := q.getStr("HELLO"); s != "SoftEther VPN Server" || q.getInt("version") != 443 || len(q.getData("random")) != 20 {
		t.Fatalf("roundtrip mismatch")
	}
	if s, _ := q.getStr("uni"); s != "héllo" {
		t.Fatalf("unistr %q", s)
	}
	if e := q.get("big"); e == nil || e.Nums[0] != 1<<40 {
		t.Fatalf("int64 mismatch")
	}
	if _, err := seDecodePack([]byte{0, 0, 0, 1, 0, 0, 0, 9, 'a'}); err == nil {
		t.Fatal("truncated pack accepted")
	}
}

func TestSECfgRoundTrip(t *testing.T) {
	root := seParseText("declare root\r\n{\r\n\tstring Name A$20b$24\r\n\tstring Empty $\r\n\tbyte B AQID\r\n\tdeclare Sub\r\n\t{\r\n\t\tuint X 5\r\n\t}\r\n}\r\n")
	if root == nil || root.str("Name") != "A b$" || root.str("Empty") != "" || !bytes.Equal(root.data("B"), []byte{1, 2, 3}) || root.folder("sub").num("x") != 5 {
		t.Fatalf("parse mismatch")
	}
	again := seParseText(string(seSerialize(root, seBanner)))
	if again == nil || again.str("Name") != "A b$" || again.folder("Sub").num("X") != 5 {
		t.Fatalf("serialize mismatch")
	}
}

func TestSEPasswordDecrypt(t *testing.T) {
	for _, s := range []string{"secret123", ""} {
		enc, _ := seDecryptPassword([]byte(s))
		dec, ok := seDecryptPassword([]byte(enc))
		if !ok || dec != s {
			t.Fatalf("rc4 roundtrip %q -> %q", s, dec)
		}
	}
}
