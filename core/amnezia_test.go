package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func amzTestKey() (string, string) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func amzTestServer(t *testing.T, host, desc string) map[string]any {
	priv, _ := amzTestKey()
	_, pub := amzTestKey()
	hpk, _ := amzTestKey()
	native := "[Interface]\nAddress = 10.8.1.2/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nPrivateKey = " + priv +
		"\nJc = 5\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n\n[Peer]\nPublicKey = " + pub +
		"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + host + ":55424\nPersistentKeepalive = 25-35\n"
	last, _ := json.Marshal(map[string]any{"config": native, "HeaderProtectionKey": hpk, "RandomTrailers": "on", "RekeyAfterTime": "100-120"})
	return map[string]any{
		"hostName": host, "description": desc, "defaultContainer": "amnezia-mtproxy",
		"containers": []any{
			map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"port": "55424", "protocol_version": "3.1", "last_config": string(last)}},
			map[string]any{"container": "amnezia-dns"},
			map[string]any{"container": "amnezia-socks5proxy", "socks5proxy": map[string]any{"port": "38080", "userName": "u", "password": "p"}},
			map[string]any{"container": "amnezia-mtproxy", "mtproxy": map[string]any{"port": "443", "mtproxy_secret": "0123456789abcdef0123456789abcdef", "mtproxy_transport_mode": "faketls", "mtproxy_tls_domain": "example.com"}},
			map[string]any{"container": "amnezia-tproxy", "tproxy": map[string]any{"port": "443"}},
		},
	}
}

func TestAmneziaBackupParseAndFilter(t *testing.T) {
	list, _ := json.MarshalIndent([]any{
		amzTestServer(t, "198.51.100.1", "first"),
		map[string]any{"config_version": 2, "api_config": map[string]any{"service_type": "amnezia-free"}, "auth_data": map[string]any{"api_key": "x"}, "name": "free"},
		amzTestServer(t, "198.51.100.2", "second"),
		map[string]any{"h": "198.51.100.3", "u": "root", "w": "pw", "p": 22},
	}, "", "    ")
	backup, _ := json.Marshal(map[string]any{"Servers/serversList": string(list), "Servers/defaultServerIndex": 2, "Conf/autoStart": true})
	f := newVFile("AmneziaVPN.backup", backup)
	if (AmneziaVpnDetector{}).Detect(f) < 90 {
		t.Fatal("backup not detected")
	}
	cs, owners, docs, err := amzParse(f, newVFS())
	if err != nil || len(docs) != 4 {
		t.Fatalf("parse: %v docs=%d", err, len(docs))
	}
	var protos []string
	for _, c := range cs {
		protos = append(protos, c.Protocol+"/"+c.Status)
	}
	got := strings.Join(protos, " ")
	if !strings.HasPrefix(got, "mtproto-faketls/Parsed AmneziaWG/Parsed socks5/Parsed tproxy/Unsupported") {
		t.Fatalf("unexpected order/protocols: %s", got)
	}
	if cs[1].Status != StateParsed || !strings.Contains(cs[1].source.Text(), "HeaderProtectionKey = ") || strings.Contains(cs[1].source.Text(), "$PRIMARY_DNS") {
		t.Fatalf("awg v3 keys not injected: %s %s", cs[1].Status, cs[1].Error)
	}
	if !strings.Contains(cs[4].Error, "Amnezia Free key") || !strings.Contains(cs[len(cs)-1].Error, "SSH credentials only") {
		t.Fatalf("api/ssh reasons: %q / %q", cs[4].Error, cs[len(cs)-1].Error)
	}
	idx := -1
	for i, o := range owners {
		if o.doc == 2 && cs[i].Protocol == "socks5" {
			idx = i
		}
	}
	out, err := (AmneziaVpnFilter{}).Filter(f, []int{idx})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	var kept []map[string]any
	json.Unmarshal([]byte(root["Servers/serversList"].(string)), &kept)
	if len(kept) != 1 || kept[0]["description"] != "second" || root["Servers/defaultServerIndex"].(float64) != 0 || root["Conf/autoStart"] != true {
		t.Fatalf("filtered backup wrong: %s", out)
	}
	conts := kept[0]["containers"].([]any)
	if len(conts) != 1 || kept[0]["defaultContainer"] != "amnezia-socks5proxy" {
		t.Fatalf("filtered containers wrong: %v", kept[0])
	}
}

func TestAmneziaTgLink(t *testing.T) {
	l := amzTgLink(map[string]any{"port": "8443", "mtproxy_secret": "0123456789abcdef0123456789abcdef", "mtproxy_transport_mode": "faketls"}, "mtproxy", "1.2.3.4")
	if !strings.Contains(l, "secret=ee0123456789abcdef0123456789abcdef") || !strings.Contains(l, "port=8443") || !strings.Contains(l, "server=1.2.3.4") {
		t.Fatal(l)
	}
	l = amzTgLink(map[string]any{"telemt_tme_link": "https://t.me/proxy?server=0.0.0.0&port=443&secret=dd00"}, "telemt", "5.6.7.8")
	if !strings.HasPrefix(l, "tg://proxy?") || !strings.Contains(l, "server=5.6.7.8") {
		t.Fatal(l)
	}
}
