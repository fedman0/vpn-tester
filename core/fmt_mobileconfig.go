package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
)

type mcDict = map[string]any

func mcXMLValue(d *xml.Decoder, start xml.StartElement, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("plist nesting too deep")
	}
	switch start.Name.Local {
	case "dict":
		m := mcDict{}
		key := ""
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					var s string
					if err := d.DecodeElement(&s, &t); err != nil {
						return nil, err
					}
					key = strings.TrimSpace(s)
					continue
				}
				v, err := mcXMLValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := mcXMLValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return start.Name.Local == "true", nil
	}
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return nil, err
	}
	switch start.Name.Local {
	case "integer":
		n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return n, nil
	case "real":
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, nil
	case "data":
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, s)
		b, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			b, _ = b64decode(clean)
		}
		return b, nil
	}
	return s, nil
}

func mcParseXML(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	d.CharsetReader = func(label string, input io.Reader) (io.Reader, error) { return input, nil }
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				continue
			}
			return mcXMLValue(d, se, 0)
		}
	}
}

type mcBPlist struct {
	b       []byte
	offs    []uint64
	refSize int
	depth   int
}

func mcParseBinary(b []byte) (any, error) {
	if len(b) < 40 || !bytes.HasPrefix(b, []byte("bplist00")) {
		return nil, errors.New("not a binary plist")
	}
	tr := b[len(b)-32:]
	offSize := int(tr[6])
	refSize := int(tr[7])
	num := binary.BigEndian.Uint64(tr[8:16])
	top := binary.BigEndian.Uint64(tr[16:24])
	tbl := binary.BigEndian.Uint64(tr[24:32])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || num > 1<<20 || tbl >= uint64(len(b)) || tbl+num*uint64(offSize) > uint64(len(b)) {
		return nil, errors.New("bad binary plist trailer")
	}
	p := &mcBPlist{b: b, refSize: refSize}
	for i := uint64(0); i < num; i++ {
		p.offs = append(p.offs, mcBEUint(b[tbl+i*uint64(offSize):tbl+(i+1)*uint64(offSize)]))
	}
	return p.obj(top)
}

func mcBEUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func (p *mcBPlist) count(off uint64, low byte) (uint64, uint64, error) {
	if low != 0x0f {
		return uint64(low), off + 1, nil
	}
	if off+2 > uint64(len(p.b)) {
		return 0, 0, errors.New("truncated")
	}
	m := p.b[off+1]
	if m>>4 != 1 {
		return 0, 0, errors.New("bad count")
	}
	n := uint64(1) << (m & 0x0f)
	if off+2+n > uint64(len(p.b)) {
		return 0, 0, errors.New("truncated")
	}
	return mcBEUint(p.b[off+2 : off+2+n]), off + 2 + n, nil
}

func (p *mcBPlist) obj(ref uint64) (any, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 64 || ref >= uint64(len(p.offs)) {
		return nil, errors.New("bad object reference")
	}
	off := p.offs[ref]
	if off >= uint64(len(p.b)) {
		return nil, errors.New("bad offset")
	}
	m := p.b[off]
	hi, lo := m>>4, m&0x0f
	switch hi {
	case 0:
		switch m {
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		}
		return nil, nil
	case 1:
		n := uint64(1) << lo
		if off+1+n > uint64(len(p.b)) {
			return nil, errors.New("truncated int")
		}
		return int64(mcBEUint(p.b[off+1 : off+1+n])), nil
	case 2:
		n := uint64(1) << lo
		if off+1+n > uint64(len(p.b)) {
			return nil, errors.New("truncated real")
		}
		v := mcBEUint(p.b[off+1 : off+1+n])
		if n == 4 {
			return float64(math.Float32frombits(uint32(v))), nil
		}
		return math.Float64frombits(v), nil
	case 3:
		return "date", nil
	case 4, 5, 6:
		n, st, err := p.count(off, lo)
		if err != nil {
			return nil, err
		}
		size := n
		if hi == 6 {
			size = 2 * n
		}
		if st+size > uint64(len(p.b)) {
			return nil, errors.New("truncated data")
		}
		raw := p.b[st : st+size]
		switch hi {
		case 4:
			return append([]byte(nil), raw...), nil
		case 5:
			return string(raw), nil
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(raw[2*i:])
		}
		return string(utf16.Decode(u)), nil
	case 0xa, 0xd:
		n, st, err := p.count(off, lo)
		if err != nil {
			return nil, err
		}
		rs := uint64(p.refSize)
		total := n
		if hi == 0xd {
			total = 2 * n
		}
		if n > 1<<16 || st+total*rs > uint64(len(p.b)) {
			return nil, errors.New("truncated container")
		}
		refAt := func(i uint64) uint64 { return mcBEUint(p.b[st+i*rs : st+(i+1)*rs]) }
		if hi == 0xa {
			a := make([]any, 0, n)
			for i := uint64(0); i < n; i++ {
				v, err := p.obj(refAt(i))
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			return a, nil
		}
		d := mcDict{}
		for i := uint64(0); i < n; i++ {
			k, err := p.obj(refAt(i))
			if err != nil {
				return nil, err
			}
			v, err := p.obj(refAt(n + i))
			if err != nil {
				return nil, err
			}
			d[fmt.Sprint(k)] = v
		}
		return d, nil
	}
	return nil, nil
}

type mcEncap struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type mcSignedData struct {
	Version     int
	Digests     asn1.RawValue
	Encap       mcEncap
	Certs       asn1.RawValue `asn1:"optional,tag:0"`
	CRLs        asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos asn1.RawValue
}

type mcContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

func mcOctets(rv asn1.RawValue) []byte {
	if !rv.IsCompound {
		return rv.Bytes
	}
	var out []byte
	rest := rv.Bytes
	for len(rest) > 0 {
		var inner asn1.RawValue
		r, err := asn1.Unmarshal(rest, &inner)
		if err != nil {
			break
		}
		out = append(out, mcOctets(inner)...)
		rest = r
	}
	return out
}

func mcUnwrapCMS(b []byte) []byte {
	var ci mcContentInfo
	if _, err := asn1.Unmarshal(b, &ci); err == nil {
		var sd mcSignedData
		if _, err := asn1.Unmarshal(ci.Content.FullBytes, &sd); err == nil && len(sd.Encap.Content.Bytes) > 0 {
			var oct asn1.RawValue
			if _, err := asn1.Unmarshal(sd.Encap.Content.Bytes, &oct); err == nil {
				if c := mcOctets(oct); len(c) > 0 {
					return c
				}
			}
		}
	}
	if i := bytes.Index(b, []byte("<?xml")); i >= 0 {
		if j := bytes.LastIndex(b, []byte("</plist>")); j > i {
			return b[i : j+8]
		}
	}
	if i := bytes.Index(b, []byte("bplist00")); i >= 0 {
		return b[i:]
	}
	return nil
}

func mcLoad(data []byte) (mcDict, bool) {
	t := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
	var v any
	var err error
	switch {
	case bytes.HasPrefix(t, []byte("bplist00")):
		v, err = mcParseBinary(t)
	case bytes.HasPrefix(t, []byte("<")):
		v, err = mcParseXML(t)
	case len(t) > 0 && t[0] == 0x30:
		inner := mcUnwrapCMS(t)
		if inner == nil {
			return nil, false
		}
		return mcLoad(inner)
	default:
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	m, ok := v.(mcDict)
	if !ok {
		return nil, false
	}
	if _, ok := m["PayloadContent"]; !ok {
		if _, ok := m["PayloadType"]; !ok {
			return nil, false
		}
	}
	return m, true
}

type MobileconfigDetector struct{}

func (MobileconfigDetector) Detect(f *vfile) int {
	if len(f.Data) > 8<<20 || len(f.Data) < 16 {
		return 0
	}
	d := f.Data
	if !bytes.Contains(d, []byte("PayloadContent")) && !bytes.Contains(d, []byte("PayloadType")) {
		return 0
	}
	if _, ok := mcLoad(d); ok {
		return 90
	}
	return 0
}

func mcStr(m mcDict, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				if s := strings.TrimSpace(t); s != "" {
					return s
				}
			case []byte:
				if len(t) > 0 {
					return string(t)
				}
			case int64:
				return strconv.FormatInt(t, 10)
			case float64:
				return strconv.FormatInt(int64(t), 10)
			case bool:
				return strconv.FormatBool(t)
			}
		}
	}
	return ""
}

func mcBool(m mcDict, k string) bool {
	switch t := m[k].(type) {
	case bool:
		return t
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t == "1" || strings.EqualFold(t, "true") || strings.EqualFold(t, "yes")
	}
	return false
}

func mcSub(m mcDict, k string) mcDict {
	if d, ok := m[k].(mcDict); ok {
		return d
	}
	return mcDict{}
}

func mcData(m mcDict, k string) []byte {
	switch t := m[k].(type) {
	case []byte:
		return t
	case string:
		if b, err := b64decode(t); err == nil && len(b) > 0 {
			return b
		}
		return []byte(t)
	}
	return nil
}

func mcGroupToken(g int64) string {
	return map[int64]string{1: "modp768", 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 17: "modp6144", 18: "modp8192", 19: "ecp256", 20: "ecp384", 21: "ecp521", 31: "curve25519", 32: "curve448"}[g]
}

func mcProposal(sa mcDict) string {
	if len(sa) == 0 {
		return ""
	}
	enc := map[string]string{"DES": "des", "3DES": "3des", "AES-128": "aes128", "AES-256": "aes256", "AES-128-GCM": "aes128gcm16", "AES-256-GCM": "aes256gcm16", "CHACHA20POLY1305": "chacha20poly1305"}[strings.ToUpper(mcStr(sa, "EncryptionAlgorithm"))]
	if enc == "" {
		enc = "aes256"
	}
	integ := map[string]string{"SHA1-96": "sha1", "SHA1-160": "sha1", "SHA2-256": "sha256", "SHA2-384": "sha384", "SHA2-512": "sha512"}[strings.ToUpper(mcStr(sa, "IntegrityAlgorithm"))]
	if integ == "" {
		integ = "sha256"
	}
	g, _ := strconv.ParseInt(mcStr(sa, "DiffieHellmanGroup"), 10, 64)
	if g == 0 {
		g = 14
	}
	dh := mcGroupToken(g)
	if dh == "" {
		dh = fmt.Sprintf("dh%d", g)
	}
	if strings.Contains(enc, "gcm") || strings.Contains(enc, "chacha") {
		integ = "prf" + integ
	}
	return enc + "-" + integ + "-" + dh
}

type mcProfile struct {
	certs map[string]mcDict
	cas   [][]byte
}

func (pr *mcProfile) identity(uuid string, c *[]string) ([]byte, []byte) {
	p, ok := pr.certs[uuid]
	if !ok || uuid == "" {
		if uuid != "" {
			*c = append(*c, "certificate payload "+uuid+" not found in profile")
		}
		return nil, nil
	}
	data := mcData(p, "PayloadContent")
	if strings.Contains(mcStr(p, "PayloadType"), "pkcs12") {
		cert, key, _, err := decodePKCS12(data, mcStr(p, "Password"))
		if err != nil {
			*c = append(*c, swP12Err(err))
			return nil, nil
		}
		return cert, key
	}
	return swCertPEM(data), nil
}

var mcOCTypes = []struct {
	prefix string
	proto  string
}{
	{"com.cisco.anyconnect", "anyconnect"}, {"com.cisco.secureclient", "anyconnect"}, {"anyconnect", "anyconnect"},
	{"com.paloaltonetworks", "gp"}, {"globalprotect", "gp"},
	{"com.fortinet", "fortinet"}, {"fortinet", "fortinet"},
	{"net.pulsesecure", "pulse"}, {"com.pulsesecure", "pulse"}, {"com.ivanti", "pulse"}, {"com.juniper", "pulse"}, {"junipersssl", "pulse"}, {"juniperssl", "pulse"},
	{"com.f5", "f5"}, {"f5", "f5"},
}

func mcOCProto(sub string) string {
	s := strings.ToLower(sub)
	for _, t := range mcOCTypes {
		if strings.HasPrefix(s, t.prefix) {
			return t.proto
		}
	}
	return ""
}

type MobileconfigParser struct{}

func (MobileconfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	root, ok := mcLoad(f.Data)
	if !ok {
		return nil, errors.New("not a configuration profile")
	}
	var payloads []mcDict
	if arr, ok := root["PayloadContent"].([]any); ok {
		for _, it := range arr {
			if d, ok := it.(mcDict); ok {
				payloads = append(payloads, d)
			}
		}
	} else {
		payloads = append(payloads, root)
	}
	pr := &mcProfile{certs: map[string]mcDict{}}
	for _, p := range payloads {
		t := mcStr(p, "PayloadType")
		if !strings.HasPrefix(t, "com.apple.security.") {
			continue
		}
		pr.certs[mcStr(p, "PayloadUUID")] = p
		if t == "com.apple.security.root" || t == "com.apple.security.pem" || t == "com.apple.security.pkcs1" {
			if pm := swCertPEM(mcData(p, "PayloadContent")); pm != nil {
				pr.cas = append(pr.cas, pm)
			}
		}
	}
	var out []*Config
	for _, p := range payloads {
		t := mcStr(p, "PayloadType")
		if !strings.HasPrefix(t, "com.apple.vpn.managed") {
			continue
		}
		out = append(out, mcVPN(f, fs, p, pr)...)
	}
	if len(out) == 0 {
		c := unsupportedConfig(f, "Apple", "", "profile contains no VPN payload")
		c.Name = mcStr(root, "PayloadDisplayName")
		return []*Config{c}, nil
	}
	return out, nil
}

func mcVPN(f *vfile, fs *vfs, p mcDict, pr *mcProfile) []*Config {
	name := firstNonEmpty(mcStr(p, "UserDefinedName"), mcStr(p, "PayloadDisplayName"))
	vt := mcStr(p, "VPNType")
	var warns []string
	finish := func(c *Config) *Config {
		c.Format = "Apple"
		if c.Name == "" {
			c.Name = name
		}
		c.Warnings = append(c.Warnings, warns...)
		return c
	}
	switch strings.ToLower(vt) {
	case "ikev2":
		return []*Config{finish(mcIKEv2(f, fs, name, mcSub(p, "IKEv2"), pr, &warns))}
	case "alwayson":
		var out []*Config
		ao := mcSub(p, "AlwaysOn")
		if arr, ok := ao["TunnelConfigurations"].([]any); ok {
			for _, it := range arr {
				if d, ok := it.(mcDict); ok {
					out = append(out, finish(mcIKEv2(f, fs, name, d, pr, &warns)))
				}
			}
		}
		if len(out) == 0 {
			out = append(out, finish(invalidConfig(f, "Apple", errors.New("AlwaysOn payload without tunnel configuration"))))
		}
		return out
	case "ipsec":
		ip := mcSub(p, "IPSec")
		spec := &ikeSpec{Name: name, Kind: "cisco", Version: 1, Host: mcStr(ip, "RemoteAddress")}
		spec.GroupName = mcStr(ip, "LocalIdentifier")
		spec.LocalID = spec.GroupName
		spec.PSK = mcStr(ip, "SharedSecret")
		xauth := mcBool(ip, "XAuthEnabled")
		spec.Username = mcStr(ip, "XAuthName")
		spec.Password = mcStr(ip, "XAuthPassword")
		cert := strings.EqualFold(mcStr(ip, "AuthenticationMethod"), "Certificate")
		if cert {
			spec.ClientCert, spec.ClientKey = pr.identity(mcStr(ip, "PayloadCertificateUUID"), &warns)
			spec.Auth = "pubkey"
		} else {
			spec.Auth = "psk"
			spec.Aggressive = spec.GroupName != ""
		}
		if xauth {
			spec.Auth = "xauth-" + spec.Auth
		}
		spec.CACerts = pr.cas
		return []*Config{finish(ikeConfig(f, fs, spec))}
	case "l2tp":
		ppp := mcSub(p, "PPP")
		ip := mcSub(p, "IPSec")
		spec := &ikeSpec{Name: name, Kind: "l2tp", Version: 1, L2TP: true, Host: mcStr(ppp, "CommRemoteAddress")}
		spec.Username = mcStr(ppp, "AuthName")
		spec.Password = mcStr(ppp, "AuthPassword")
		spec.PSK = mcStr(ip, "SharedSecret")
		spec.LocalID = mcStr(ip, "LocalIdentifier")
		spec.Auth = "psk"
		if strings.EqualFold(mcStr(ip, "AuthenticationMethod"), "Certificate") {
			spec.Auth = "pubkey"
			spec.ClientCert, spec.ClientKey = pr.identity(mcStr(ip, "PayloadCertificateUUID"), &warns)
		}
		spec.CACerts = pr.cas
		if spec.Host == "" {
			spec.Host = mcStr(ip, "RemoteAddress")
		}
		return []*Config{finish(ikeConfig(f, fs, spec))}
	case "pptp":
		ppp := mcSub(p, "PPP")
		return []*Config{finish(pptpConfig(f, fs, &pptpSpec{Name: name, Host: mcStr(ppp, "CommRemoteAddress"), Username: mcStr(ppp, "AuthName"), Password: mcStr(ppp, "AuthPassword")}))}
	}
	sub := mcStr(p, "VPNSubType")
	proto := mcOCProto(sub)
	if proto == "" {
		proto = mcOCProto(vt)
	}
	if proto == "" {
		c := unsupportedConfig(f, "Apple", firstNonEmpty(sub, vt), "unsupported VPN type "+firstNonEmpty(sub, vt))
		vpn := mcSub(p, "VPN")
		c.Host = mcStr(vpn, "RemoteAddress")
		return []*Config{finish(c)}
	}
	vpn := mcSub(p, "VPN")
	vc := mcSub(p, "VendorConfig")
	spec := &ocSpec{Name: name, Protocol: proto}
	addr := firstNonEmpty(mcStr(vpn, "RemoteAddress"), mcStr(vc, "RemoteAddress", "Server", "server", "host"))
	if !strings.Contains(addr, "://") {
		addr = "https://" + addr
	}
	if u, err := url.Parse(addr); err == nil {
		spec.Host = u.Hostname()
		spec.Port, _ = strconv.Atoi(u.Port())
		spec.Path = strings.TrimPrefix(u.Path, "/")
	}
	spec.Username = firstNonEmpty(mcStr(vpn, "AuthName"), mcStr(vc, "Username", "username", "user"))
	spec.Password = firstNonEmpty(mcStr(vpn, "AuthPassword"), mcStr(vc, "Password", "password"))
	spec.Group = mcStr(vc, "Group", "GroupName", "group", "LoginGroupOrDomain", "Realm", "realm")
	if strings.EqualFold(mcStr(vpn, "AuthenticationMethod"), "Certificate") {
		cert, key := pr.identity(mcStr(vpn, "PayloadCertificateUUID"), &warns)
		spec.ClientCert, spec.ClientKey = cert, key
	}
	if len(pr.cas) > 0 {
		spec.CACert = pr.cas[0]
	}
	return []*Config{finish(ocConfig(f, fs, spec))}
}

func mcIKEv2(f *vfile, fs *vfs, name string, ik mcDict, pr *mcProfile, warns *[]string) *Config {
	spec := &ikeSpec{Name: name, Kind: "apple", Version: 2, Host: mcStr(ik, "RemoteAddress")}
	spec.RemoteID = mcStr(ik, "RemoteIdentifier")
	spec.LocalID = mcStr(ik, "LocalIdentifier")
	method := strings.ToLower(mcStr(ik, "AuthenticationMethod"))
	eap := mcBool(ik, "ExtendedAuthEnabled")
	spec.Username = mcStr(ik, "AuthName")
	spec.Password = mcStr(ik, "AuthPassword")
	spec.PSK = mcStr(ik, "SharedSecret")
	switch {
	case method == "certificate" && eap:
		spec.Auth = "eap-tls"
	case method == "certificate":
		spec.Auth = "pubkey"
	case method == "sharedsecret" && !eap:
		spec.Auth = "psk"
	default:
		spec.Auth = "eap"
	}
	if method == "certificate" {
		spec.ClientCert, spec.ClientKey = pr.identity(mcStr(ik, "PayloadCertificateUUID"), warns)
	}
	if spec.Auth != "psk" && method != "sharedsecret" {
		spec.PSK = ""
	}
	if p := mcProposal(mcSub(ik, "IKESecurityAssociationParameters")); p != "" {
		spec.IKEProposals = []string{p}
	}
	if p := mcProposal(mcSub(ik, "ChildSecurityAssociationParameters")); p != "" {
		spec.ESPProposals = []string{p}
	}
	spec.CACerts = pr.cas
	if cn := mcStr(ik, "ServerCertificateIssuerCommonName"); cn != "" && len(pr.cas) == 0 {
		*warns = append(*warns, "server CA \""+cn+"\" is expected from the device trust store")
	}
	if spec.Host == "" {
		return invalidConfig(f, "Apple", errors.New("IKEv2 payload without RemoteAddress"))
	}
	return ikeConfig(f, fs, spec)
}

func init() {
	registerFormat(&fileFormat{Name: "Apple", Detector: MobileconfigDetector{}, Parser: MobileconfigParser{}})
}
