package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/curve25519"
)

type wgPeer struct {
	PublicKey  string
	PSK        string
	Endpoint   string
	Host       string
	Port       int
	AllowedIPs []netip.Prefix
	Keepalive  string
	Reserved   []byte
	pub        [32]byte
	psk        [32]byte
	hasPSK     bool
}

type wgParam struct {
	Key   string
	Value string
}

type wgConf struct {
	Name       string
	PrivateKey string
	priv       [32]byte
	ClientPub  string
	Addresses  []netip.Prefix
	DNS        []string
	MTU        int
	ListenPort int
	AWG        []wgParam
	Amnezia    bool
	V3         bool
	Version    string
	Peers      []*wgPeer
}

var wgAwgAliases = map[string]string{
	"jc": "jc", "jmin": "jmin", "jmax": "jmax",
	"s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4",
	"i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
	"j1": "j1", "j2": "j2", "j3": "j3", "itime": "itime",
	"headerprotectionkey":        "header_protection_key",
	"contentpaddingaddition":     "content_padding_addition",
	"rekeyaftertime":             "rekey_after_time",
	"rekeytimeout":               "rekey_timeout",
	"rejectaftertime":            "reject_after_time",
	"keepalivetimeout":           "keepalive_timeout",
	"maxhandshakeattempts":       "max_handshake_attempts",
	"randomtrailers":             "random_trailers",
	"disablecookies":             "disable_cookies",
	"junkpacketcount":            "jc",
	"junkpacketminsize":          "jmin",
	"junkpacketmaxsize":          "jmax",
	"initpacketjunksize":         "s1",
	"responsepacketjunksize":     "s2",
	"cookiereplypacketjunksize":  "s3",
	"transportpacketjunksize":    "s4",
	"initpacketmagicheader":      "h1",
	"responsepacketmagicheader":  "h2",
	"underloadpacketmagicheader": "h3",
	"transportpacketmagicheader": "h4",
}

var wgAwgOrder = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime",
	"header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout",
	"reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies",
}

var wgAwgLabels = map[string]string{
	"jc": "Jc", "jmin": "Jmin", "jmax": "Jmax", "s1": "S1", "s2": "S2", "s3": "S3", "s4": "S4",
	"h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4", "i1": "I1", "i2": "I2", "i3": "I3", "i4": "I4", "i5": "I5",
	"j1": "J1", "j2": "J2", "j3": "J3", "itime": "Itime",
	"header_protection_key": "HeaderProtectionKey", "content_padding_addition": "ContentPaddingAddition",
	"rekey_after_time": "RekeyAfterTime", "rekey_timeout": "RekeyTimeout", "reject_after_time": "RejectAfterTime",
	"keepalive_timeout": "KeepaliveTimeout", "max_handshake_attempts": "MaxHandshakeAttempts",
	"random_trailers": "RandomTrailers", "disable_cookies": "DisableCookies",
}

var wgV3Keys = map[string]bool{
	"header_protection_key": true, "content_padding_addition": true, "rekey_after_time": true,
	"rekey_timeout": true, "reject_after_time": true, "keepalive_timeout": true,
	"max_handshake_attempts": true, "random_trailers": true, "disable_cookies": true,
}

var wgV15Keys = map[string]bool{"j1": true, "j2": true, "j3": true, "itime": true}

var wgHookKeys = map[string]bool{
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

var wgIgnoredKeys = map[string]string{
	"saveconfig": "SaveConfig", "table": "Table", "fwmark": "FwMark",
	"includedapplications": "IncludedApplications", "excludedapplications": "ExcludedApplications",
}

type wgLine struct {
	Section string
	Key     string
	Value   string
	Line    int
}

func wgSplitLines(text string) []wgLine {
	var out []wgLine
	section := ""
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			out = append(out, wgLine{Section: section, Line: i + 1})
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			out = append(out, wgLine{Section: section, Key: "", Value: line, Line: i + 1})
			continue
		}
		out = append(out, wgLine{Section: section, Key: strings.ToLower(strings.Join(strings.Fields(k), "")), Value: strings.TrimSpace(v), Line: i + 1})
	}
	return out
}

type wgSniff struct {
	iface   bool
	privKey bool
	peer    bool
	pubKey  bool
	awg     bool
	other   int
	keys    int
}

func wgText(f *vfile) (string, bool) {
	d := f.Data
	if len(d) >= 2 && (d[0] == 0xFF && d[1] == 0xFE || d[0] == 0xFE && d[1] == 0xFF) {
		be := d[0] == 0xFE
		d = d[2:]
		u := make([]uint16, 0, len(d)/2)
		for i := 0; i+1 < len(d); i += 2 {
			if be {
				u = append(u, uint16(d[i])<<8|uint16(d[i+1]))
			} else {
				u = append(u, uint16(d[i+1])<<8|uint16(d[i]))
			}
		}
		return strings.ReplaceAll(string(utf16.Decode(u)), "\r\n", "\n"), true
	}
	if !f.IsText() {
		return "", false
	}
	return f.Text(), true
}

func wgSniffText(f *vfile) wgSniff {
	var s wgSniff
	if len(f.Data) == 0 || len(f.Data) > 1<<20 {
		return s
	}
	text, ok := wgText(f)
	if !ok {
		return s
	}
	for _, l := range wgSplitLines(text) {
		if l.Key == "" && l.Value == "" {
			switch l.Section {
			case "interface":
				s.iface = true
			case "peer":
				s.peer = true
			default:
				s.other++
			}
			continue
		}
		if l.Key == "" {
			continue
		}
		s.keys++
		switch l.Section {
		case "interface":
			if l.Key == "privatekey" {
				s.privKey = true
			}
			if _, ok := wgAwgAliases[l.Key]; ok {
				s.awg = true
			}
		case "peer":
			if l.Key == "publickey" {
				s.pubKey = true
			}
		}
	}
	return s
}

func (s wgSniff) score() int {
	if !s.iface {
		return 0
	}
	switch {
	case s.privKey && s.peer && s.pubKey:
		return 90
	case s.privKey || (s.peer && s.pubKey):
		return 70
	}
	return 0
}

type wgDetector struct {
	amnezia bool
}

func (d wgDetector) Detect(f *vfile) int {
	s := wgSniffText(f)
	sc := s.score()
	if sc == 0 {
		return 0
	}
	if d.amnezia {
		if s.awg {
			return sc + 2
		}
		return 0
	}
	if s.awg {
		return 0
	}
	return sc
}

func wgDecodeKey(s string) ([32]byte, error) {
	var k [32]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return k, errors.New("empty")
	}
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err = enc.DecodeString(s)
		if err == nil {
			break
		}
	}
	if err != nil {
		if len(s) == 64 {
			if hb, herr := hex.DecodeString(s); herr == nil {
				copy(k[:], hb)
				return k, nil
			}
		}
		return k, errors.New("not valid base64")
	}
	if len(b) != 32 {
		return k, fmt.Errorf("decodes to %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

func wgParseRange(v string, bits int) error {
	lo, hi, isRange := strings.Cut(v, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, bits)
	if err != nil {
		return errors.New("not a number or range")
	}
	if isRange {
		b, err := strconv.ParseUint(strings.TrimSpace(hi), 10, bits)
		if err != nil {
			return errors.New("bad range upper bound")
		}
		if b < a {
			return errors.New("range upper bound below lower bound")
		}
	}
	return nil
}

func wgNormalizeAwg(key, v string) (string, error) {
	switch key {
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime":
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return "", errors.New("must be a non-negative integer")
		}
		return strconv.FormatUint(n, 10), nil
	case "h1", "h2", "h3", "h4", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts":
		v = strings.ReplaceAll(v, " ", "")
		if err := wgParseRange(v, 32); err != nil {
			return "", err
		}
		return v, nil
	case "header_protection_key":
		k, err := wgDecodeKey(v)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(k[:]), nil
	case "random_trailers", "disable_cookies":
		switch strings.ToLower(v) {
		case "on", "true", "yes", "1":
			return "true", nil
		case "off", "false", "no", "0":
			return "false", nil
		}
		return "", errors.New("must be on/off")
	}
	return v, nil
}

func wgParseEndpoint(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, errors.New("must be host:port")
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, errors.New("missing host")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return host, n, nil
}

func wgParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()), nil
}

func wgSplitList(v string) []string {
	var out []string
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func wgParseReserved(v string) ([]byte, error) {
	parts := wgSplitList(strings.Trim(v, "[]"))
	if len(parts) == 3 {
		out := make([]byte, 3)
		for i, p := range parts {
			n, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return nil, errors.New("must be three bytes")
			}
			out[i] = byte(n)
		}
		return out, nil
	}
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err == nil && len(b) == 3 {
		return b, nil
	}
	return nil, errors.New("must be three bytes")
}

type wgParseResult struct {
	conf        *wgConf
	warnings    []string
	unsupported string
}

func wgParseText(text string) (*wgParseResult, error) {
	res := &wgParseResult{}
	w := &wgConf{}
	res.conf = w
	warn := func(format string, args ...any) {
		res.warnings = append(res.warnings, fmt.Sprintf(format, args...))
	}
	ifaceCount := 0
	var cur *wgPeer
	seenHooks := map[string]bool{}
	seenIgnored := map[string]bool{}
	awgVals := map[string]string{}
	awgSeen := false
	inIface := false
	for _, l := range wgSplitLines(text) {
		if l.Key == "" && l.Value == "" {
			inIface = false
			cur = nil
			switch l.Section {
			case "interface":
				ifaceCount++
				inIface = ifaceCount == 1
				if ifaceCount == 2 {
					warn("multiple [Interface] sections; only the first is used")
				}
			case "peer":
				cur = &wgPeer{}
				w.Peers = append(w.Peers, cur)
			default:
				warn("unknown section [%s] ignored", l.Section)
			}
			continue
		}
		if l.Key == "" {
			warn("line %d ignored: not key = value", l.Line)
			continue
		}
		switch {
		case inIface:
			if wgHookKeys[l.Key] {
				if !seenHooks[l.Key] {
					seenHooks[l.Key] = true
					warn("%s hook ignored (never executed)", wgHookName(l.Key))
				}
				continue
			}
			if name, ok := wgIgnoredKeys[l.Key]; ok {
				if !seenIgnored[l.Key] {
					seenIgnored[l.Key] = true
					warn("%s ignored", name)
				}
				continue
			}
			if uk, ok := wgAwgAliases[l.Key]; ok {
				awgSeen = true
				if l.Value == "" {
					continue
				}
				v, err := wgNormalizeAwg(uk, l.Value)
				if err != nil {
					return nil, fmt.Errorf("invalid AmneziaWG %s %q: %v", wgAwgLabels[uk], wgTrunc(l.Value), err)
				}
				awgVals[uk] = v
				continue
			}
			switch l.Key {
			case "privatekey":
				w.PrivateKey = l.Value
			case "address":
				for _, a := range wgSplitList(l.Value) {
					p, err := wgParsePrefix(a)
					if err != nil {
						return nil, fmt.Errorf("invalid [Interface] Address %q", wgTrunc(a))
					}
					w.Addresses = append(w.Addresses, p)
				}
			case "dns":
				w.DNS = append(w.DNS, wgSplitList(l.Value)...)
			case "mtu":
				n, err := strconv.Atoi(l.Value)
				if err != nil || n < 576 || n > 65535 {
					warn("invalid MTU %q ignored", wgTrunc(l.Value))
					continue
				}
				w.MTU = n
			case "listenport":
				n, err := strconv.Atoi(l.Value)
				if err != nil || n < 0 || n > 65535 {
					warn("invalid ListenPort %q ignored", wgTrunc(l.Value))
					continue
				}
				w.ListenPort = n
			default:
				warn("unknown [Interface] key %q ignored", l.Key)
			}
		case cur != nil:
			switch l.Key {
			case "publickey":
				cur.PublicKey = l.Value
			case "presharedkey":
				cur.PSK = l.Value
			case "endpoint":
				cur.Endpoint = l.Value
			case "allowedips":
				for _, a := range wgSplitList(l.Value) {
					p, err := wgParsePrefix(a)
					if err != nil {
						return nil, fmt.Errorf("[Peer] #%d: invalid AllowedIPs entry %q", len(w.Peers), wgTrunc(a))
					}
					cur.AllowedIPs = append(cur.AllowedIPs, p.Masked())
				}
			case "persistentkeepalive":
				cur.Keepalive = l.Value
			case "reserved":
				b, err := wgParseReserved(l.Value)
				if err != nil {
					return nil, fmt.Errorf("[Peer] #%d: invalid Reserved %q: %v", len(w.Peers), wgTrunc(l.Value), err)
				}
				cur.Reserved = b
			case "advancedsecurity":
			default:
				warn("unknown [Peer] key %q ignored", l.Key)
			}
		}
	}
	if ifaceCount == 0 {
		return nil, errors.New("missing [Interface] section")
	}
	if w.PrivateKey == "" {
		if len(w.Peers) > 0 {
			res.unsupported = "no [Interface] PrivateKey (key stored outside the file?)"
			return res, nil
		}
		return nil, errors.New("missing [Interface] PrivateKey")
	}
	k, err := wgDecodeKey(w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid [Interface] PrivateKey: %v", err)
	}
	w.priv = k
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("invalid [Interface] PrivateKey: %v", err)
	}
	w.ClientPub = base64.StdEncoding.EncodeToString(pub)
	if len(w.Peers) == 0 {
		return nil, errors.New("no [Peer] section")
	}
	for i, p := range w.Peers {
		n := i + 1
		if p.PublicKey == "" {
			return nil, fmt.Errorf("[Peer] #%d: missing PublicKey", n)
		}
		pk, err := wgDecodeKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("[Peer] #%d: invalid PublicKey: %v", n, err)
		}
		p.pub = pk
		if base64.StdEncoding.EncodeToString(pk[:]) == w.ClientPub {
			return nil, fmt.Errorf("[Peer] #%d: PublicKey equals the interface's own public key", n)
		}
		if p.PSK != "" {
			sk, err := wgDecodeKey(p.PSK)
			if err != nil {
				return nil, fmt.Errorf("[Peer] #%d: invalid PresharedKey: %v", n, err)
			}
			p.psk = sk
			p.hasPSK = true
		}
		if p.Endpoint != "" {
			h, port, err := wgParseEndpoint(p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("[Peer] #%d: invalid Endpoint %q: %v", n, wgTrunc(p.Endpoint), err)
			}
			p.Host, p.Port = h, port
		}
		if p.Keepalive != "" && !strings.EqualFold(p.Keepalive, "off") {
			if err := wgParseRange(p.Keepalive, 16); err != nil {
				return nil, fmt.Errorf("[Peer] #%d: invalid PersistentKeepalive %q", n, wgTrunc(p.Keepalive))
			}
		}
	}
	if w.primary() == nil {
		res.unsupported = "no [Peer] Endpoint: server-side or listen-only WireGuard config cannot be tested as a client"
		return res, nil
	}
	if awgSeen {
		w.Amnezia = true
		hasV3, hasV15, hasV2, hasI := false, false, false, false
		for _, k := range wgAwgOrder {
			v, ok := awgVals[k]
			if !ok {
				continue
			}
			switch {
			case wgV3Keys[k]:
				hasV3 = true
			case wgV15Keys[k]:
				hasV15 = true
			case k == "s3" || k == "s4":
				hasV2 = true
			case strings.HasPrefix(k, "h") && strings.Contains(v, "-"):
				hasV2 = true
			case strings.HasPrefix(k, "i"):
				hasI = true
			}
			if (k != "random_trailers" && k != "disable_cookies" && v == "0") || v == "false" {
				continue
			}
			w.AWG = append(w.AWG, wgParam{Key: k, Value: v})
		}
		if hasV3 && hasV15 {
			return nil, errors.New("AmneziaWG v1.5 options (J1-J3, Itime) cannot be combined with v3 options")
		}
		switch {
		case hasV3:
			w.V3, w.Version = true, "awg v3"
		case hasV15:
			w.Version = "awg v1.5"
		case hasV2:
			w.Version = "awg v2"
		case hasI:
			w.Version = "awg v1.5"
		default:
			w.Version = "awg v1"
		}
	}
	return res, nil
}

func wgHookName(k string) string {
	switch k {
	case "preup":
		return "PreUp"
	case "postup":
		return "PostUp"
	case "predown":
		return "PreDown"
	}
	return "PostDown"
}

func wgTrunc(s string) string {
	if len(s) > 48 {
		return s[:48] + "…"
	}
	return s
}

func (w *wgConf) primary() *wgPeer {
	for _, p := range w.Peers {
		if p.Host != "" {
			return p
		}
	}
	return nil
}

func (w *wgConf) fingerprintExtra() string {
	parts := []string{w.ClientPub}
	for _, p := range w.AWG {
		parts = append(parts, p.Key+"="+p.Value)
	}
	var eps []string
	for _, p := range w.Peers {
		if p.Host != "" {
			eps = append(eps, strings.ToLower(p.Host)+":"+strconv.Itoa(p.Port)+"/"+p.PublicKey+"/"+p.PSK)
		}
	}
	sort.Strings(eps)
	parts = append(parts, eps...)
	if w.Amnezia {
		parts = append(parts, "awg")
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:12])
}

func wgFileName(f *vfile) string {
	n := f.Name
	if i := strings.LastIndex(n, "."); i > 0 {
		n = n[:i]
	}
	return n
}

func wgBuildConfig(f *vfile, format string, forceAmnezia bool) ([]*Config, error) {
	text, ok := wgText(f)
	if !ok {
		return nil, errors.New("not a text file")
	}
	res, err := wgParseText(text)
	if err != nil {
		return nil, err
	}
	w := res.conf
	if forceAmnezia {
		w.Amnezia = true
		if w.Version == "" {
			w.Version = "awg v1"
		}
	}
	proto := "WireGuard"
	if w.Amnezia {
		proto = "AmneziaWG"
		if format == "WireGuard" {
			format = "AmneziaWG"
		}
	}
	if res.unsupported != "" {
		c := unsupportedConfig(f, format, proto, res.unsupported)
		c.Name = wgFileName(f)
		c.Warnings = res.warnings
		c.RawConfig = f.Data
		return []*Config{c}, nil
	}
	w.Name = wgFileName(f)
	pp := w.primary()
	c := newConfig(f, format, proto)
	c.Name = w.Name
	c.Host, c.Port = pp.Host, pp.Port
	c.Transport = "udp"
	c.UDP = true
	c.Security = w.Version
	c.PublicKey = pp.PublicKey
	c.PrivateKey = w.PrivateKey
	c.PSK = pp.PSK
	c.Extra = w.fingerprintExtra()
	c.RawConfig = f.Data
	c.Warnings = res.warnings
	c.Payload = w
	c.Validator = wgValidator{}
	if w.Amnezia {
		c.Tester = &AmneziaWgConnectivityTester{}
	} else {
		c.Tester = &WireGuardConnectivityTester{}
	}
	if len(w.Addresses) == 0 {
		c.Warn("no [Interface] Address: data-plane probe not possible")
	}
	return []*Config{c}, nil
}

type WireGuardConfigParser struct{}

func (WireGuardConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	return wgBuildConfig(f, "WireGuard", false)
}

type AmneziaWgConfigParser struct{}

func (AmneziaWgConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	return wgBuildConfig(f, "AmneziaWG", true)
}

type wgValidator struct{}

func (wgValidator) Validate(c *Config) error {
	w, ok := c.Payload.(*wgConf)
	if !ok || w == nil {
		return errors.New("missing WireGuard config")
	}
	if !w.Amnezia || len(w.AWG) == 0 {
		return nil
	}
	return wgCheckAwgParams(w)
}

func init() {
	registerFormat(&fileFormat{Name: "WireGuard", Detector: wgDetector{}, Parser: WireGuardConfigParser{}})
	registerFormat(&fileFormat{Name: "AmneziaWG", Detector: wgDetector{amnezia: true}, Parser: AmneziaWgConfigParser{}})
}
