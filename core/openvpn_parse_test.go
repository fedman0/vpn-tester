package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ovpnTestCert(t *testing.T) (string, string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func TestOvpnTokens(t *testing.T) {
	cases := map[string][]string{
		`remote "my host" 1194 # trailing`:  {"remote", "my host", "1194"},
		`  ; full comment`:                  nil,
		`auth-user-pass 'C:\Users\a b.txt'`: {"auth-user-pass", `C:\Users\a b.txt`},
		`ca C:\\certs\\ca.crt`:              {"ca", `C:\certs\ca.crt`},
		`setenv FRIENDLY_NAME "a \"q\" b"`:  {"setenv", "FRIENDLY_NAME", `a "q" b`},
		`dhcp-option DNS 1.1.1.1;x`:         {"dhcp-option", "DNS", "1.1.1.1;x"},
	}
	for in, want := range cases {
		if got := ovpnTokens(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestOvpnDetect(t *testing.T) {
	d := OpenVpnConfigDetector{}
	yes := []string{
		"client\ndev tun\nproto udp\nremote 1.2.3.4 1194\n<ca>\nx\n</ca>\n",
		"remote vpn.example.com 443 tcp\nnobind\npersist-key\nauth-user-pass\n",
		"dev tun\ntls-client\npull\nca ca.crt\ncert c.crt\nkey c.key\n",
	}
	no := []string{
		"[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = 1.2.3.4:51820\n",
		"config setup\nconn x\n  left=%defaultroute\n  right=vpn.example.com\n  auto=add\n",
		"[General]\nloglevel = notify\n[Proxy]\np = ss, 1.2.3.4, 8388\n",
		"[connection]\nid=x\ntype=vpn\n[vpn]\nremote=1.2.3.4\nconnection-type=tls\n",
		"To connect use the client app.\nThe remote server is at vpn.example.com.\n",
		"proxies:\n  - name: a\n    type: openvpn\n    server: 1.2.3.4\n    remote: x\n",
	}
	for _, s := range yes {
		if d.Detect(newVFile("a.txt", []byte(s))) == 0 {
			t.Errorf("not detected: %q", s)
		}
	}
	for _, s := range no {
		if n := d.Detect(newVFile("a.conf", []byte(s))); n != 0 {
			t.Errorf("wrongly detected (%d): %q", n, s)
		}
	}
}

func TestOvpnParseChildAndSanitize(t *testing.T) {
	ca, key := ovpnTestCert(t)
	fs := newVFS()
	container := newVFile("vpn/amnezia.json", []byte("{}"))
	fs.add(container)
	fs.add(newVFile("vpn/keys/ca.crt", []byte(ca)))
	fs.add(newVFile("vpn/keys/creds.txt", []byte("bob\npw\n")))
	text := "client\ndev tun\nproto tcp\nremote 10.0.0.1 443\nremote 10.0.0.2\nport 1443\nca keys/ca.crt\nauth-user-pass keys/creds.txt\nscript-security 2\nup /bin/evil.sh\nmanagement 127.0.0.1 7505\n<cert>\n" + ca + "</cert>\n<key>\n" + key + "</key>\n"
	child := container.Child("openvpn", "openvpn.ovpn", []byte(text))
	cs, err := parseAs("OpenVPN", child, fs)
	if err != nil || len(cs) != 1 {
		t.Fatalf("parse: %v %d", err, len(cs))
	}
	c := cs[0]
	validateConfig(c)
	if c.Status != StateParsed {
		t.Fatalf("status %s %s", c.Status, c.Error)
	}
	if c.File != "vpn/amnezia.json" || c.Host != "10.0.0.1" || c.Port != 443 || c.Transport != "tcp" || c.Username != "bob" || c.Password != "pw" {
		t.Fatalf("bad view %+v", c)
	}
	m := c.Payload.(*ovpnModel)
	if len(m.Remotes) != 2 || m.Remotes[1].Port != 1443 {
		t.Fatalf("remotes %+v", m.Remotes)
	}
	if !reflect.DeepEqual(c.Dependencies, []string{"vpn/keys/ca.crt", "vpn/keys/creds.txt"}) {
		t.Fatalf("deps %v", c.Dependencies)
	}
	if len(c.Warnings) == 0 || !strings.Contains(c.Warnings[0], "up") || !strings.Contains(c.Warnings[0], "management") {
		t.Fatalf("warnings %v", c.Warnings)
	}
	raw := string(c.RawConfig)
	if strings.Contains(raw, "evil") || strings.Contains(raw, "script-security") || strings.Contains(raw, "management") || !strings.Contains(raw, "remote 10.0.0.2") {
		t.Fatalf("sanitized %q", raw)
	}
}

func TestOvpnParseErrors(t *testing.T) {
	ca, _ := ovpnTestCert(t)
	fs := newVFS()
	f := newVFile("a.ovpn", []byte("client\ndev tun\nremote 1.2.3.4\nca nope.crt\nauth-user-pass\n"))
	fs.add(f)
	cs, _ := parseAs("OpenVPN", f, fs)
	if cs[0].Status != StateInvalid || !strings.Contains(cs[0].Error, "nope.crt") {
		t.Fatalf("missing ref: %s %s", cs[0].Status, cs[0].Error)
	}
	g := newVFile("b.ovpn", []byte("client\ndev tap\nremote 1.2.3.4\nauth-user-pass\n<ca>\n"+ca+"</ca>\n"))
	cs, _ = parseAs("OpenVPN", g, fs)
	if cs[0].Status != StateUnsupported {
		t.Fatalf("tap: %s", cs[0].Status)
	}
	h := newVFile("c.ovpn", []byte("client\ndev tun\nremote 1.2.3.4\nauth-user-pass\n<ca>\n"+ca+"</ca>\n"))
	cs, _ = parseAs("OpenVPN", h, fs)
	validateConfig(cs[0])
	m := cs[0].Payload.(*ovpnModel)
	if cs[0].Status != StateParsed || m.HasCreds || m.CredNote == "" || cs[0].Port != 1194 || cs[0].Transport != "udp" {
		t.Fatalf("no creds: %s %s %+v", cs[0].Status, cs[0].Error, m)
	}
	s := newVFile("server.conf", []byte("port 1194\nproto udp\ndev tun\nca /etc/ca.crt\nserver 10.8.0.0 255.255.255.0\ndh dh.pem\n"))
	cs, _ = parseAs("OpenVPN", s, fs)
	if cs[0].Status != StateUnsupported || len(cs[0].Dependencies) != 0 {
		t.Fatalf("server: %s %v", cs[0].Status, cs[0].Dependencies)
	}
}

func TestOvpnCiphers(t *testing.T) {
	type res struct {
		primary string
		list    []string
		fb      string
		unsup   string
	}
	check := func(cipher string, list []string, fb string, ncp bool, want res) {
		p, l, f, u := ovpnCiphers(cipher, list, fb, ncp)
		got := res{p, l, f, u}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q %v %q: got %+v want %+v", cipher, list, fb, got, want)
		}
	}
	def := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	check("", nil, "", false, res{"AES-256-GCM", def, "", ""})
	check("AES-128-CBC", nil, "", false, res{"AES-128-CBC", append([]string{"AES-128-CBC"}, def...), "", ""})
	check("BF-CBC", nil, "", false, res{"AES-256-GCM", def, "", "BF-CBC"})
	check("", []string{"AES-128-GCM", "BF-CBC"}, "AES-256-CBC", false, res{"AES-256-CBC", []string{"AES-128-GCM"}, "AES-256-CBC", ""})
	check("aes-256-cbc", nil, "", true, res{"AES-256-CBC", []string{"AES-256-CBC"}, "", ""})
}
