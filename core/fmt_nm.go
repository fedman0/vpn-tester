package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type NetworkManagerDetector struct{}

func (NetworkManagerDetector) Detect(f *vfile) int {
	if !f.IsText() {
		return 0
	}
	secs := parseINI(f.Text())
	conn := iniFind(secs, "connection")
	if conn == nil || conn.Get("type") == "" {
		return 0
	}
	if iniFind(secs, "vpn") != nil || iniFind(secs, "wireguard") != nil || conn.Get("id") != "" {
		if f.Ext == "nmconnection" {
			return 95
		}
		return 85
	}
	return 0
}

type NetworkManagerParser struct{}

func nmSplitHostPort(s string, defPort int) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			p, _ := strconv.Atoi(u.Port())
			if p == 0 {
				p = defPort
			}
			return u.Hostname(), p
		}
	}
	if i := strings.IndexAny(s, "/ "); i > 0 && !strings.HasPrefix(s, "[") {
		s = s[:i]
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		if n == 0 {
			n = defPort
		}
		return strings.Trim(h, "[]"), n
	}
	return strings.Trim(s, "[]"), defPort
}

func nmList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nmVal(vpn, sec *iniSection, keys ...string) string {
	for _, k := range keys {
		if v := sec.Get(k); v != "" {
			return v
		}
		if v := vpn.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func nmFileData(f *vfile, fs *vfs, c *Config, ref string, cert bool) ([]byte, error) {
	if ref == "" {
		return nil, nil
	}
	if strings.HasPrefix(ref, "data:") || strings.Contains(ref, "-----BEGIN") {
		return []byte(ref), nil
	}
	g := fs.Resolve(f, ref)
	if g == nil {
		return nil, fmt.Errorf("referenced file not found: %s", ref)
	}
	if c != nil {
		c.AddDep(fs, g, cert)
	}
	return g.Data, nil
}

func (NetworkManagerParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	secs := parseINI(f.Text())
	conn := iniFind(secs, "connection")
	name := conn.Get("id")
	typ := strings.ToLower(conn.Get("type"))
	var cs []*Config
	var err error
	switch typ {
	case "wireguard":
		cs, err = nmWireGuard(f, fs, secs, name)
	case "vpn":
		cs, err = nmVPN(f, fs, secs, name)
	default:
		return []*Config{unsupportedConfig(f, "NetworkManager", typ, "NetworkManager connection type "+typ+" is not a VPN")}, nil
	}
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		c.Format = "NetworkManager"
		c.File = f.Root().Path
		if c.Name == "" {
			c.Name = name
		}
	}
	return cs, nil
}

func nmWireGuard(f *vfile, fs *vfs, secs []*iniSection, name string) ([]*Config, error) {
	wg := iniFind(secs, "wireguard")
	if wg == nil {
		return nil, errors.New("missing [wireguard] section")
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if v := wg.Get("private-key"); v != "" {
		b.WriteString("PrivateKey = " + v + "\n")
	}
	var addrs, dns []string
	for _, fam := range []string{"ipv4", "ipv6"} {
		s := iniFind(secs, fam)
		if s == nil {
			continue
		}
		for _, kv := range s.Keys {
			k := strings.ToLower(kv.Key)
			if strings.HasPrefix(k, "address") {
				a := strings.TrimSpace(strings.Split(kv.Value, ",")[0])
				if a != "" {
					addrs = append(addrs, a)
				}
			}
			if k == "dns" {
				dns = append(dns, nmList(kv.Value)...)
			}
		}
	}
	if len(addrs) > 0 {
		b.WriteString("Address = " + strings.Join(addrs, ", ") + "\n")
	}
	if len(dns) > 0 {
		b.WriteString("DNS = " + strings.Join(dns, ", ") + "\n")
	}
	if v := wg.Get("mtu"); v != "" && v != "0" {
		b.WriteString("MTU = " + v + "\n")
	}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if v := wg.Get(k); v != "" {
			b.WriteString(strings.ToUpper(k[:1]) + k[1:] + " = " + v + "\n")
		}
	}
	peers := 0
	for _, s := range secs {
		if !strings.HasPrefix(strings.ToLower(s.Name), "wireguard-peer.") {
			continue
		}
		peers++
		b.WriteString("\n[Peer]\nPublicKey = " + s.Name[len("wireguard-peer."):] + "\n")
		if v := s.Get("preshared-key"); v != "" {
			b.WriteString("PresharedKey = " + v + "\n")
		}
		if v := s.Get("endpoint"); v != "" {
			b.WriteString("Endpoint = " + v + "\n")
		}
		if v := nmList(s.Get("allowed-ips")); len(v) > 0 {
			b.WriteString("AllowedIPs = " + strings.Join(v, ", ") + "\n")
		}
		if v := s.Get("persistent-keepalive"); v != "" && v != "0" {
			b.WriteString("PersistentKeepalive = " + v + "\n")
		}
	}
	if peers == 0 {
		return nil, errors.New("wireguard connection has no peers")
	}
	return parseAs("WireGuard", f.Child("wireguard", name+".conf", []byte(b.String())), fs)
}

func nmVPN(f *vfile, fs *vfs, secs []*iniSection, name string) ([]*Config, error) {
	vpn := iniFind(secs, "vpn")
	if vpn == nil {
		return nil, errors.New("missing [vpn] section")
	}
	sec := iniFind(secs, "vpn-secrets")
	st := strings.ToLower(vpn.Get("service-type"))
	st = strings.TrimPrefix(st, "org.freedesktop.networkmanager.")
	switch st {
	case "openvpn":
		return nmOpenVPN(f, fs, vpn, sec, name)
	case "strongswan":
		return nmStrongSwan(f, fs, vpn, sec, name)
	case "libreswan", "openswan":
		return nmLibreswan(f, fs, vpn, sec, name)
	case "vpnc":
		host, port := nmSplitHostPort(vpn.Get("IPSec gateway"), 500)
		spec := &ikeSpec{
			Name: name, Kind: "cisco", Version: 1, Host: host, Port: port, Aggressive: true,
			GroupName: vpn.Get("IPSec ID"), LocalID: vpn.Get("IPSec ID"),
			PSK:      nmVal(vpn, sec, "IPSec secret"),
			Username: vpn.Get("Xauth username"), Password: nmVal(vpn, sec, "Xauth password"),
			Auth: "xauth-psk",
		}
		if host == "" {
			return nil, errors.New("vpnc gateway is missing")
		}
		return []*Config{ikeConfig(f, fs, spec)}, nil
	case "l2tp":
		host, _ := nmSplitHostPort(vpn.Get("gateway"), 0)
		if host == "" {
			return nil, errors.New("l2tp gateway is missing")
		}
		if !strings.EqualFold(vpn.Get("ipsec-enabled"), "yes") {
			return []*Config{unsupportedConfig(f, "NetworkManager", "L2TP", "plain L2TP without IPsec is not supported")}, nil
		}
		spec := &ikeSpec{
			Name: name, Kind: "l2tp", Version: 1, Host: host, Port: 500, L2TP: true, Auth: "psk",
			PSK:      nmVal(vpn, sec, "ipsec-psk"),
			LocalID:  vpn.Get("ipsec-group-name"),
			Username: vpn.Get("user"), Password: nmVal(vpn, sec, "password"),
		}
		if v := vpn.Get("ipsec-gateway-id"); v != "" {
			spec.RemoteID = v
		}
		if p := vpn.Get("ipsec-ike"); p != "" {
			spec.IKEProposals = nmList(p)
		}
		return []*Config{ikeConfig(f, fs, spec)}, nil
	case "openconnect":
		gw := vpn.Get("gateway")
		host, port := nmSplitHostPort(gw, 443)
		if host == "" {
			return nil, errors.New("openconnect gateway is missing")
		}
		spec := &ocSpec{
			Name: name, Protocol: strings.ToLower(firstNonEmpty(vpn.Get("protocol"), "anyconnect")), Host: host, Port: port,
			Username:      nmVal(vpn, sec, "form:main:username", "username", "user"),
			Password:      nmVal(vpn, sec, "form:main:password", "password"),
			Group:         nmVal(vpn, sec, "form:main:group_list", "authgroup", "usergroup"),
			ServerCertPin: nmVal(vpn, sec, "gwcert", "certsigs"),
		}
		if u, err := url.Parse(gw); err == nil && strings.Contains(gw, "://") {
			spec.Path = u.Path
		}
		var c0 *Config
		ca, err := nmFileData(f, fs, nil, vpn.Get("cacert"), true)
		if err != nil {
			return nil, err
		}
		spec.CACert = ca
		c0 = ocConfig(f, fs, spec)
		nmAttach(f, fs, c0, vpn, "cacert", "usercert", "userkey")
		return []*Config{c0}, nil
	case "fortisslvpn":
		host, port := nmSplitHostPort(vpn.Get("gateway"), 443)
		if host == "" {
			return nil, errors.New("fortisslvpn gateway is missing")
		}
		spec := &ocSpec{Name: name, Protocol: "fortinet", Host: host, Port: port, Username: vpn.Get("user"), Password: nmVal(vpn, sec, "password"), Group: vpn.Get("realm"), ServerCertPin: vpn.Get("trusted-cert")}
		c0 := ocConfig(f, fs, spec)
		nmAttach(f, fs, c0, vpn, "ca", "cert", "key")
		return []*Config{c0}, nil
	case "sstp":
		host, port := nmSplitHostPort(vpn.Get("gateway"), 443)
		if host == "" {
			return nil, errors.New("sstp gateway is missing")
		}
		spec := &sstpSpec{Name: name, Host: host, Port: port, Username: vpn.Get("user"), Password: nmVal(vpn, sec, "password"), Domain: vpn.Get("domain")}
		ca, err := nmFileData(f, fs, nil, vpn.Get("ca-cert"), true)
		if err != nil {
			return nil, err
		}
		spec.CACert = ca
		c0 := sstpConfig(f, fs, spec)
		nmAttach(f, fs, c0, vpn, "ca-cert")
		return []*Config{c0}, nil
	case "pptp":
		host, _ := nmSplitHostPort(vpn.Get("gateway"), 1723)
		if host == "" {
			return nil, errors.New("pptp gateway is missing")
		}
		spec := &pptpSpec{Name: name, Host: host, Username: vpn.Get("user"), Password: nmVal(vpn, sec, "password"), Domain: vpn.Get("domain")}
		return []*Config{pptpConfig(f, fs, spec)}, nil
	case "":
		return nil, errors.New("vpn service-type is missing")
	}
	return []*Config{unsupportedConfig(f, "NetworkManager", st, "NetworkManager VPN plugin "+st+" is not supported")}, nil
}

func nmAttach(f *vfile, fs *vfs, c *Config, vpn *iniSection, keys ...string) {
	if c == nil {
		return
	}
	for _, k := range keys {
		if v := vpn.Get(k); v != "" && !strings.Contains(v, "-----BEGIN") {
			if g := fs.Resolve(f, v); g != nil {
				c.AddDep(fs, g, true)
			}
		}
	}
}

func nmOpenVPN(f *vfile, fs *vfs, vpn, sec *iniSection, name string) ([]*Config, error) {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w("client")
	devType := strings.ToLower(firstNonEmpty(vpn.Get("dev-type"), "tun"))
	w("dev " + devType)
	proto := "udp"
	if strings.EqualFold(vpn.Get("proto-tcp"), "yes") {
		proto = "tcp-client"
	}
	w("proto " + proto)
	port := firstNonEmpty(vpn.Get("port"), "1194")
	remotes := nmList(vpn.Get("remote"))
	if len(remotes) == 0 {
		return nil, errors.New("openvpn remote is missing")
	}
	for _, r := range remotes {
		parts := strings.Fields(strings.ReplaceAll(r, ":", " "))
		if strings.Count(r, ":") > 1 && !strings.HasPrefix(r, "[") {
			parts = []string{r}
		}
		host := strings.Trim(parts[0], "[]")
		p := port
		if len(parts) > 1 {
			p = parts[1]
		}
		line := "remote " + host + " " + p
		if len(parts) > 2 {
			line += " " + parts[2]
		}
		w(line)
	}
	if strings.EqualFold(vpn.Get("remote-random"), "yes") {
		w("remote-random")
	}
	for _, kv := range [][2]string{{"ca", "ca"}, {"cert", "cert"}, {"key", "key"}, {"tls-crypt", "tls-crypt"}, {"tls-crypt-v2", "tls-crypt-v2"}} {
		if v := vpn.Get(kv[0]); v != "" {
			w(kv[1] + " \"" + v + "\"")
		}
	}
	if v := vpn.Get("ta"); v != "" {
		line := "tls-auth \"" + v + "\""
		if d := vpn.Get("ta-dir"); d != "" {
			line += " " + d
		}
		w(line)
	}
	for _, kv := range [][2]string{{"cipher", "cipher"}, {"data-ciphers", "data-ciphers"}, {"data-ciphers-fallback", "data-ciphers-fallback"}, {"auth", "auth"}, {"tls-version-min", "tls-version-min"}, {"remote-cert-tls", "remote-cert-tls"}} {
		if v := vpn.Get(kv[0]); v != "" {
			w(kv[1] + " " + v)
		}
	}
	if v := vpn.Get("verify-x509-name"); v != "" {
		typ, val, ok := strings.Cut(v, ":")
		if ok {
			w("verify-x509-name \"" + val + "\" " + typ)
		} else {
			w("verify-x509-name \"" + v + "\"")
		}
	}
	switch strings.ToLower(vpn.Get("comp-lzo")) {
	case "yes", "adaptive":
		w("comp-lzo adaptive")
	case "no-by-default":
		w("comp-lzo no")
	}
	if v := vpn.Get("compress"); v != "" {
		w("compress " + v)
	}
	if v := vpn.Get("proxy-server"); v != "" {
		pt := strings.ToLower(vpn.Get("proxy-type"))
		pp := vpn.Get("proxy-port")
		if pt == "http" {
			w("http-proxy " + v + " " + pp)
		} else if pt == "socks" {
			w("socks-proxy " + v + " " + pp)
		}
	}
	ct := strings.ToLower(vpn.Get("connection-type"))
	if ct == "password" || ct == "password-tls" || vpn.Get("username") != "" {
		user := vpn.Get("username")
		pass := nmVal(vpn, sec, "password")
		if user != "" {
			w("<auth-user-pass>")
			w(user)
			w(pass)
			w("</auth-user-pass>")
		} else {
			w("auth-user-pass")
		}
	}
	if ct == "static-key" {
		return []*Config{unsupportedConfig(f, "NetworkManager", "OpenVPN", "OpenVPN static-key mode is not supported")}, nil
	}
	if devType == "tap" {
		return []*Config{unsupportedConfig(f, "NetworkManager", "OpenVPN", "OpenVPN tap devices are not supported")}, nil
	}
	return parseAs("OpenVPN", f.Child("openvpn", name+".ovpn", []byte(b.String())), fs)
}

func nmStrongSwan(f *vfile, fs *vfs, vpn, sec *iniSection, name string) ([]*Config, error) {
	host, port := nmSplitHostPort(vpn.Get("address"), 500)
	if host == "" {
		return nil, errors.New("strongswan address is missing")
	}
	spec := &ikeSpec{Name: name, Kind: "ikev2", Version: 2, Host: host, Port: port, RemoteID: vpn.Get("remote-identity"), LocalID: vpn.Get("local-identity")}
	if spec.RemoteID == "" {
		spec.RemoteID = vpn.Get("server-id")
	}
	method := strings.ToLower(vpn.Get("method"))
	pw := nmVal(vpn, sec, "password")
	switch method {
	case "eap", "":
		spec.Auth = "eap"
		spec.Username = vpn.Get("user")
		spec.Password = pw
	case "psk":
		spec.Auth = "psk"
		spec.PSK = pw
	case "key", "cert", "eap-tls":
		spec.Auth = "pubkey"
		if method == "eap-tls" {
			spec.Auth = "eap-tls"
		}
		cert, err := nmFileData(f, fs, nil, vpn.Get("usercert"), true)
		if err != nil {
			return nil, err
		}
		key, err := nmFileData(f, fs, nil, vpn.Get("userkey"), false)
		if err != nil {
			return nil, err
		}
		spec.ClientCert, spec.ClientKey = cert, key
	case "agent", "smartcard":
		return []*Config{unsupportedConfig(f, "NetworkManager", "IKEv2", "strongSwan "+method+" authentication is not supported")}, nil
	}
	if v := vpn.Get("certificate"); v != "" {
		ca, err := nmFileData(f, fs, nil, v, true)
		if err != nil {
			return nil, err
		}
		spec.CACerts = append(spec.CACerts, ca)
	}
	if strings.EqualFold(vpn.Get("proposal"), "yes") {
		spec.IKEProposals = nmList(vpn.Get("ike"))
		spec.ESPProposals = nmList(vpn.Get("esp"))
	}
	c := ikeConfig(f, fs, spec)
	nmAttach(f, fs, c, vpn, "certificate", "usercert", "userkey")
	return []*Config{c}, nil
}

func nmLibreswan(f *vfile, fs *vfs, vpn, sec *iniSection, name string) ([]*Config, error) {
	host, port := nmSplitHostPort(vpn.Get("right"), 500)
	if host == "" {
		return nil, errors.New("libreswan right (gateway) is missing")
	}
	v2 := strings.EqualFold(vpn.Get("ikev2"), "yes") || strings.EqualFold(vpn.Get("ikev2"), "insist") || strings.EqualFold(vpn.Get("ikev2"), "propose")
	spec := &ikeSpec{Name: name, Host: host, Port: port, LocalID: vpn.Get("leftid"), RemoteID: vpn.Get("rightid"), PSK: nmVal(vpn, sec, "pskvalue")}
	if p := vpn.Get("ike"); p != "" {
		spec.IKEProposals = nmList(p)
	}
	if v2 {
		spec.Version, spec.Kind, spec.Auth = 2, "ikev2", "psk"
	} else {
		spec.Version, spec.Kind = 1, "ikev1"
		spec.Aggressive = strings.EqualFold(vpn.Get("aggrmode"), "yes")
		spec.Username = firstNonEmpty(vpn.Get("leftxauthusername"), vpn.Get("leftusername"))
		spec.Password = nmVal(vpn, sec, "xauthpassword")
		spec.GroupName = vpn.Get("leftid")
		spec.Auth = "psk"
		if spec.Username != "" {
			spec.Auth = "xauth-psk"
			spec.Kind = "cisco"
		}
	}
	return []*Config{ikeConfig(f, fs, spec)}, nil
}

func init() {
	registerFormat(&fileFormat{Name: "NetworkManager", Detector: NetworkManagerDetector{}, Parser: NetworkManagerParser{}})
}
