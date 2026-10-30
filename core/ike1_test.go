package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
)

func pcfEncrypt(plain string) string {
	h1 := make([]byte, 20)
	rand.Read(h1)
	pt := []byte(plain)
	pad := 8 - len(pt)%8
	for i := 0; i < pad; i++ {
		pt = append(pt, byte(pad))
	}
	block, _ := des.NewTripleDESCipher(pcfDeriveKey(h1))
	enc := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, h1[:8]).CryptBlocks(enc, pt)
	h4 := sha1.Sum(enc)
	return strings.ToUpper(hex.EncodeToString(append(append(h1, h4[:]...), enc...)))
}

func TestPcfCryptRoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "TestPsk123", "exactly8", "a much longer group password with spaces!"} {
		enc := pcfEncrypt(s)
		got, err := pcfDecrypt(enc)
		if err != nil || got != s {
			t.Fatalf("%q: got %q err %v", s, got, err)
		}
	}
	enc := []byte(pcfEncrypt("secret"))
	enc[len(enc)-1] ^= 1
	if _, err := pcfDecrypt(string(enc)); err == nil {
		t.Fatal("corrupted value accepted")
	}
	if v := os.Getenv("IKE1_PCF_ENCRYPT"); v != "" {
		fmt.Println(pcfEncrypt(v))
	}
}

func TestIke1ModpPrimes(t *testing.T) {
	for g := range ike1ModpHex {
		p := ike1Modp(g)
		q := new(big.Int).Rsh(p, 1)
		if !p.ProbablyPrime(10) || !q.ProbablyPrime(10) {
			t.Fatalf("group %d is not a safe prime", g)
		}
	}
	for _, g := range []uint16{1, 2, 5, 14, 19, 20, 21, 31} {
		a, err := ike1NewDH(g)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := ike1NewDH(g)
		x, err1 := a.Shared(b.Public())
		y, err2 := b.Shared(a.Public())
		if err1 != nil || err2 != nil || !bytes.Equal(x, y) {
			t.Fatalf("group %d: DH mismatch %v %v", g, err1, err2)
		}
	}
}

func TestIke1Proposals(t *testing.T) {
	trs, err := ike1ParseProposals("aes256-sha2_256;modp2048,3des-md5-modp1024!")
	if err != nil || len(trs) != 2 || trs[0].String() != "aes256-sha256-modp2048" || trs[1].String() != "3des-md5-modp1024" {
		t.Fatalf("%v %v", trs, err)
	}
	trs, _ = ike1ParseProposals("aes128-aes256-sha1-sha256-modp2048-ecp256")
	if len(trs) != 8 {
		t.Fatalf("cross product %d", len(trs))
	}
}

func TestPcfParse(t *testing.T) {
	enc := pcfEncrypt("grouppw")
	txt := "[main]\r\nDescription=office\r\n!Host=vpn.example.com\r\nAuthType=1\r\nGroupName=staff\r\nGroupPwd=\r\nenc_GroupPwd=" + enc + "\r\nUsername=bob\r\nEnableNat=1\r\nDHGroup=2\r\n"
	f := newVFile("office.pcf", []byte(txt))
	if (CiscoPcfDetector{}).Detect(f) < 80 {
		t.Fatal("not detected")
	}
	cs, err := CiscoPcfConfigParser{}.Parse(f, newVFS())
	if err != nil || len(cs) != 1 {
		t.Fatal(err)
	}
	c := cs[0]
	if c.Status != StateParsed || c.Protocol != "Cisco IPsec" || c.PSK != "grouppw" || c.Host != "vpn.example.com" || c.Username != "bob" {
		t.Fatalf("%+v", c)
	}
	prm := c.Payload.(*ike1Params)
	if !prm.aggressive || prm.auth != ike1AuthXPSK || prm.idType != ike1IDKeyID || string(prm.idData) != "staff" || prm.amGroups()[0] != 2 {
		t.Fatalf("%+v", prm)
	}
	f2 := newVFile("tcp.pcf", []byte(strings.Replace(txt, "EnableNat=1", "TunnelingMode=1\r\nTcpTunnelingPort=10000", 1)))
	cs, _ = CiscoPcfConfigParser{}.Parse(f2, newVFS())
	if cs[0].Status != StateUnsupported {
		t.Fatalf("tcp tunnel: %s", cs[0].Status)
	}
	if (CiscoPcfDetector{}).Detect(newVFile("x.ini", []byte("[main]\nfoo=bar\n"))) != 0 {
		t.Fatal("false positive")
	}
}

type ike1LiveCase struct {
	Name     string
	Spec     ikeSpec
	CertFile string
	KeyFile  string
	CAFile   string
	Expect   string
}

func TestIke1Live(t *testing.T) {
	path := os.Getenv("IKE1_CASES")
	if path == "" {
		t.Skip("set IKE1_CASES to a JSON file of live IKEv1 test cases")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []ike1LiveCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	initRuntime(nil)
	opt := &scanOptions{}
	opt.normalize()
	for i, lc := range cases {
		spec := lc.Spec
		spec.Version = 1
		if lc.CertFile != "" {
			spec.ClientCert, _ = os.ReadFile(lc.CertFile)
		}
		if lc.KeyFile != "" {
			spec.ClientKey, _ = os.ReadFile(lc.KeyFile)
		}
		if lc.CAFile != "" {
			ca, _ := os.ReadFile(lc.CAFile)
			spec.CACerts = [][]byte{ca}
		}
		f := newVFile(lc.Name+".spec", nil)
		c := ikeConfig(f, newVFS(), &spec)
		c.ID = i + 1
		validateConfig(c)
		if c.Status != StateParsed {
			t.Errorf("%s: config %s %s", lc.Name, c.Status, c.Error)
			continue
		}
		r := testConfig(opt, c)
		st := func(b *bool) string {
			if b == nil {
				return "-"
			}
			if *b {
				return "Y"
			}
			return "N"
		}
		s := r.Stages
		line := fmt.Sprintf("=> %-28s %-12s %-34s %-20s %5dms [p%s d%s t%s h%s a%s x%s] %s %s %s", lc.Name, c.Protocol, c.Security, r.Result, r.Latency,
			st(s.Parse), st(s.DNS), st(s.Transport), st(s.Handshake), st(s.Authentication), st(s.DataPlane), r.ErrorCode, r.ErrorMessage, r.Note)
		t.Log(line)
		if lc.Expect != "" && r.Result != lc.Expect {
			t.Errorf("%s: want %s got %s", lc.Name, lc.Expect, r.Result)
		}
	}
}
