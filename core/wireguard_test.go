package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

const (
	wgtPriv = "yt8vArJNipFVUvXPhmZX6BZS+Gmuu2c7ItJhXjfZFFI="
	wgtPub  = "ZvjPnKns2gQ+ADK3CzJ/N0l3oIoPKCBrGw3/GrMGXV4="
	wgtPSK  = "69a/lbPlsENRpPY7MFULmaNVoNHV0mXc0dkrZ8w5rfY="
)

func wgtParse(t *testing.T, name, text string) []*Config {
	t.Helper()
	f := newVFile(name, []byte(text))
	ff := detectFormat(f)
	if ff == nil {
		t.Fatalf("%s: not detected", name)
	}
	cs, err := ff.Parser.Parse(f, newVFS())
	if err != nil {
		cs = []*Config{invalidConfig(f, ff.Name, err)}
	}
	for _, c := range cs {
		validateConfig(c)
	}
	return cs
}

func TestWgParseBasic(t *testing.T) {
	text := "[Interface]\nPrivateKey = " + wgtPriv + "\nAddress = 10.0.0.2, fd00::2/128\nDNS = 1.1.1.1\nPostUp = rm -rf /\nTable = off\n\n[Peer]\nPublicKey = " + wgtPub + "\nPresharedKey = " + wgtPSK + "\nAllowedIPs = 0.0.0.0/1\nAllowedIPs = 128.0.0.0/1, ::/0\nEndpoint = [2001:db8::1]:51820 # comment\nPersistentKeepalive = 25\n"
	cs := wgtParse(t, "a.txt", text)
	if len(cs) != 1 {
		t.Fatalf("configs %d", len(cs))
	}
	c := cs[0]
	if c.Format != "WireGuard" || c.Protocol != "WireGuard" || c.Status != StateParsed {
		t.Fatalf("bad config %+v", c)
	}
	if c.Host != "2001:db8::1" || c.Port != 51820 || !c.UDP || c.Transport != "udp" {
		t.Fatalf("endpoint %s %d", c.Host, c.Port)
	}
	if c.PublicKey != wgtPub || c.PrivateKey != wgtPriv || c.PSK != wgtPSK {
		t.Fatal("keys not filled")
	}
	w := c.Payload.(*wgConf)
	if len(w.Addresses) != 2 || len(w.Peers[0].AllowedIPs) != 3 {
		t.Fatalf("addresses %v allowed %v", w.Addresses, w.Peers[0].AllowedIPs)
	}
	joined := strings.Join(c.Warnings, ";")
	if !strings.Contains(joined, "PostUp") || !strings.Contains(joined, "Table") {
		t.Fatalf("warnings %v", c.Warnings)
	}
}

func TestWgParseErrors(t *testing.T) {
	cases := map[string]string{
		"[Interface]\nPrivateKey = abc\n[Peer]\nPublicKey = " + wgtPub + "\nEndpoint = 1.2.3.4:1\n":                          "PrivateKey",
		"[Interface]\nPrivateKey = " + wgtPriv + "\n[Peer]\nEndpoint = 1.2.3.4:1\n":                                          "missing PublicKey",
		"[Interface]\nPrivateKey = " + wgtPriv + "\n[Peer]\nPublicKey = " + wgtPub + "\nEndpoint = 1.2.3.4\n":                "invalid Endpoint",
		"[Interface]\nPrivateKey = " + wgtPriv + "\n[Peer]\nPublicKey = " + wgtPub + "\nEndpoint = h:1\nJc = 1\n":            "",
		"[Interface]\nPrivateKey = " + wgtPriv + "\n[Peer]\nPublicKey = " + wgtPub + "\nPresharedKey = xx\nEndpoint = h:1\n": "PresharedKey",
	}
	for text, want := range cases {
		cs := wgtParse(t, "x.conf", text)
		if want == "" {
			continue
		}
		if cs[0].Status != StateInvalid || !strings.Contains(cs[0].Error, want) {
			t.Errorf("want invalid %q, got %s %q", want, cs[0].Status, cs[0].Error)
		}
	}
	cs := wgtParse(t, "srv.conf", "[Interface]\nListenPort = 51820\nPrivateKey = "+wgtPriv+"\n[Peer]\nPublicKey = "+wgtPub+"\nAllowedIPs = 10.0.0.2/32\n")
	if cs[0].Status != StateUnsupported {
		t.Errorf("server config: %s %s", cs[0].Status, cs[0].Error)
	}
}

func TestWgAwgVersions(t *testing.T) {
	base := "[Interface]\nPrivateKey = " + wgtPriv + "\nAddress = 10.0.0.2/32\n%s\n[Peer]\nPublicKey = " + wgtPub + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"
	cases := []struct {
		params, label string
		v3            bool
		status        string
	}{
		{"Jc = 4\nJmin = 40\nJmax = 70\nS1 = 52\nS2 = 77\nH1 = 1020325451\nH2 = 3288052141\nH3 = 1766607858\nH4 = 2528465083", "awg v1", false, StateParsed},
		{"Jc = 3\nJmin = 50\nJmax = 900\nS1 = 68\nS2 = 149\nH1 = 1340232681\nH2 = 2102394730\nH3 = 3184924312\nH4 = 4021457263\nI1 = <b 0xc700><c><t><r 50>\nJ1 = <r 40>\nItime = 120", "awg v1.5", false, StateParsed},
		{"Jc = 5\nJmin = 10\nJmax = 50\nS1 = 15\nS2 = 18\nS3 = 20\nS4 = 23\nH1 = 100000000-200000000\nH2 = 300000000-400000000\nH3 = 500000000-600000000\nH4 = 700000000-800000000\nI1 = <b 0xf6ab3267fa><r 16><rc 8><rd 4><t>", "awg v2", false, StateParsed},
		{"S1 = 24\nS2 = 28\nS3 = 16\nS4 = 12\nH1 = 110000000-120000000\nH2 = 130000000-140000000\nH3 = 150000000-160000000\nH4 = 170000000-180000000\nHeaderProtectionKey = " + wgtPSK + "\nRandomTrailers = on", "awg v3", true, StateParsed},
		{"Jc = 4\nH1 = 5\nH2 = 5\nH3 = 6\nH4 = 7", "awg v1", false, StateInvalid},
		{"S1 = 1\nS2 = 2\nS3 = 3\nS4 = 4\nHeaderProtectionKey = " + wgtPSK, "awg v3", true, StateInvalid},
	}
	for i, tc := range cases {
		text := strings.Replace(base, "%s", tc.params, 1)
		cs := wgtParse(t, "awg.conf", text)
		c := cs[0]
		if c.Format != "AmneziaWG" || c.Protocol != "AmneziaWG" {
			t.Errorf("#%d format %s/%s", i, c.Format, c.Protocol)
		}
		if c.Status != tc.status {
			t.Errorf("#%d status %s %s", i, c.Status, c.Error)
			continue
		}
		if c.Security != tc.label {
			t.Errorf("#%d label %q", i, c.Security)
		}
		if w, ok := c.Payload.(*wgConf); ok && w.V3 != tc.v3 {
			t.Errorf("#%d v3=%v", i, w.V3)
		}
	}
	mixed := strings.Replace(base, "%s", "J1 = <r 4>\nHeaderProtectionKey = "+wgtPSK, 1)
	if cs := wgtParse(t, "m.conf", mixed); cs[0].Status != StateInvalid {
		t.Errorf("mixed v1.5/v3 accepted")
	}
	cs, err := parseAs("WireGuard", newVFile("nm#wg", []byte(strings.Replace(base, "%s", "Jc = 4\nS1 = 10", 1))), nil)
	if err != nil || cs[0].Format != "AmneziaWG" || cs[0].Protocol != "AmneziaWG" {
		t.Errorf("parseAs WireGuard with AWG keys: %+v %v", cs[0], err)
	}
}

func TestWgDetectAndUTF16(t *testing.T) {
	text := "[Interface]\r\nPrivateKey = " + wgtPriv + "\r\nAddress = 10.0.0.2/32\r\n[Peer]\r\nPublicKey = " + wgtPub + "\r\nAllowedIPs = 0.0.0.0/0\r\nEndpoint = 1.2.3.4:51820\r\n"
	u := utf16.Encode([]rune(text))
	b := []byte{0xFF, 0xFE}
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	f := newVFile("w.conf", b)
	if ff := detectFormat(f); ff == nil || ff.Name != "WireGuard" {
		t.Fatalf("utf16 not detected")
	}
	cs, err := WireGuardConfigParser{}.Parse(f, nil)
	if err != nil || cs[0].Host != "1.2.3.4" {
		t.Fatalf("utf16 parse %v", err)
	}
	soft := "# VPN Client VPN Connection Setting File\r\ndeclare root\r\n{\r\n\tstring Hostname vpn.example.com\r\n}\r\n"
	sf := newVFile("x.vpn", []byte(soft))
	if (wgDetector{}).Detect(sf) != 0 || (wgDetector{amnezia: true}).Detect(sf) != 0 || (AmneziaVpnDetector{}).Detect(sf) != 0 {
		t.Fatalf("softether detected")
	}
}

func wgtAmzDoc() map[string]any {
	awgText := "[Interface]\nPrivateKey = " + wgtPriv + "\nAddress = 10.8.1.2/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 52\nS2 = 77\nH1 = 1020325451\nH2 = 3288052141\nH3 = 1766607858\nH4 = 2528465083\n\n[Peer]\nPublicKey = " + wgtPub + "\nPresharedKey = " + wgtPSK + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.5:32542\nPersistentKeepalive = 25\n"
	lc, _ := json.Marshal(map[string]any{"config": awgText, "hostName": "203.0.113.5", "port": 32542})
	wgText := strings.NewReplacer("Jc = 4\n", "", "Jmin = 10\n", "", "Jmax = 50\n", "", "S1 = 52\n", "", "S2 = 77\n", "", "H1 = 1020325451\n", "", "H2 = 3288052141\n", "", "H3 = 1766607858\n", "", "H4 = 2528465083\n", "").Replace(awgText)
	wlc, _ := json.Marshal(map[string]any{"config": wgText})
	return map[string]any{
		"containers": []any{
			map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(lc), "port": "32542", "transport_proto": "udp"}},
			map[string]any{"container": "amnezia-dns"},
			map[string]any{"container": "amnezia-wireguard", "wireguard": map[string]any{"last_config": string(wlc), "port": "51820"}},
			map[string]any{"container": "amnezia-openvpn-cloak", "cloak": map[string]any{"last_config": "{}"}},
		},
		"defaultContainer": "amnezia-awg",
		"description":      "Srv",
		"dns1":             "9.9.9.9",
		"hostName":         "203.0.113.5",
	}
}

func TestAmneziaVpnRoundTrip(t *testing.T) {
	link, err := amzEncode(wgtAmzDoc(), true)
	if err != nil {
		t.Fatal(err)
	}
	cs := wgtParse(t, "key.vpn", "my key:\n"+link+"\n")
	if len(cs) != 3 {
		t.Fatalf("configs %d", len(cs))
	}
	if cs[0].Format != "AmneziaVPN" || cs[0].Protocol != "AmneziaWG" || cs[0].Status != StateParsed || cs[0].Host != "203.0.113.5" || cs[0].Port != 32542 {
		t.Fatalf("awg %+v", cs[0])
	}
	if w := cs[0].Payload.(*wgConf); len(w.DNS) == 0 || w.DNS[0] != "9.9.9.9" {
		t.Fatalf("dns placeholder not substituted: %v", w.DNS)
	}
	if cs[1].Protocol != "WireGuard" || cs[1].Status != StateParsed {
		t.Fatalf("wg %+v", cs[1])
	}
	if cs[2].Status != StateUnsupported {
		t.Fatalf("cloak %+v", cs[2])
	}
	out, err := AmneziaVpnFilter{}.Filter(newVFile("key.vpn", []byte(link)), []int{1})
	if err != nil {
		t.Fatal(err)
	}
	docs, _ := amzExtract(string(out))
	if len(docs) != 1 {
		t.Fatalf("filtered docs %d", len(docs))
	}
	conts := amzContainers(docs[0].obj)
	if len(conts) != 1 || amzStr(conts[0], "container") != "amnezia-wireguard" || amzStr(docs[0].obj, "defaultContainer") != "amnezia-wireguard" {
		t.Fatalf("filtered %s", out)
	}
	raw, _ := amzEncode(wgtAmzDoc(), false)
	if cs := wgtParse(t, "server.json", raw); len(cs) != 3 {
		t.Fatalf("raw json configs %d", len(cs))
	}
}
