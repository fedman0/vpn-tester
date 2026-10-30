package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

type ovpnDirective struct {
	Name   string
	Args   []string
	Inline bool
	Body   string
	Sub    []ovpnDirective
	Line   int
}

type ovpnProxy struct {
	Kind string
	Host string
	Port int
	User string
	Pass string
}

type ovpnRemote struct {
	Host   string
	Port   int
	Proto  string
	Family string
	Proxy  *ovpnProxy
}

func (r ovpnRemote) String() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) + "/" + r.Proto + r.Family
}

type ovpnModel struct {
	Name              string
	Remotes           []ovpnRemote
	RemoteRandom      bool
	Dev               string
	CA                []byte
	Cert              []byte
	Key               []byte
	TLSAuth           []byte
	KeyDirection      string
	TLSCrypt          []byte
	TLSCryptV2        []byte
	Cipher            string
	DataCiphers       []string
	Fallback          string
	CipherUnsupported string
	Auth              string
	CompLZO           string
	Compress          string
	AuthUserPass      bool
	Username          string
	Password          string
	HasCreds          bool
	CredNote          string
	PeerFingerprints  []string
	VerifyX509        string
	MTU               int
	Sanitized         []byte
}

var ovpnInlineTags = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "auth-user-pass": true, "extra-certs": true, "connection": true, "dh": true,
	"secret": true, "crl-verify": true, "http-proxy-user-pass": true, "peer-fingerprint": true,
}

var ovpnUnsafe = map[string]bool{
	"up": true, "down": true, "route-up": true, "route-pre-down": true, "ipchange": true, "script-security": true,
	"plugin": true, "tls-verify": true, "auth-user-pass-verify": true, "client-connect": true, "client-disconnect": true,
	"learn-address": true, "management": true, "management-client": true, "management-hold": true,
	"management-query-passwords": true, "management-query-proxy": true, "management-query-remote": true,
	"management-forget-disconnect": true, "management-signal": true, "management-external-key": true,
	"management-external-cert": true, "management-client-auth": true, "management-up-down": true,
	"management-client-user": true, "management-client-group": true, "management-log-cache": true,
	"daemon": true, "log": true, "log-append": true, "writepid": true, "status": true, "status-version": true,
	"cd": true, "chroot": true, "up-restart": true, "down-pre": true, "tls-export-cert": true, "iproute": true,
	"config": true, "tmp-dir": true, "syslog": true, "user": true, "group": true, "route-up-delay": true,
	"route-pre-down-delay": true, "dev-node": true, "service": true, "win-sys": true, "up-delay": true,
	"ifconfig-noexec": true, "route-noexec": true, "echo": true, "client-crresponse": true, "auth-gen-token-secret": true,
	"setcon": true, "machine-readable-output": true, "lladdr": true, "ipchange-script": true, "dhcp-renew": true,
	"dhcp-pre-release": true, "dhcp-release": true, "register-dns": true, "block-outside-dns-script": true,
}

var ovpnSafe = map[string]bool{
	"client": true, "tls-client": true, "pull": true, "dev": true, "dev-type": true, "proto": true, "remote": true,
	"remote-random": true, "remote-random-hostname": true, "port": true, "rport": true, "nobind": true,
	"resolv-retry": true, "connect-retry": true, "connect-retry-max": true, "connect-timeout": true,
	"server-poll-timeout": true, "persist-key": true, "persist-tun": true, "persist-remote-ip": true, "float": true,
	"ca": true, "cert": true, "key": true, "pkcs12": true, "extra-certs": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "key-direction": true, "cipher": true, "data-ciphers": true, "ncp-ciphers": true,
	"data-ciphers-fallback": true, "ncp-disable": true, "auth": true, "auth-nocache": true, "auth-user-pass": true,
	"auth-retry": true, "askpass": true, "comp-lzo": true, "compress": true, "allow-compression": true,
	"tls-version-min": true, "tls-version-max": true, "tls-cipher": true, "tls-ciphersuites": true, "tls-groups": true,
	"tls-cert-profile": true, "verify-x509-name": true, "remote-cert-tls": true, "remote-cert-ku": true,
	"remote-cert-eku": true, "ns-cert-type": true, "peer-fingerprint": true, "http-proxy": true,
	"http-proxy-option": true, "http-proxy-user-pass": true, "http-proxy-retry": true, "http-proxy-timeout": true,
	"socks-proxy": true, "socks-proxy-retry": true, "verb": true, "mute": true, "mute-replay-warnings": true,
	"reneg-sec": true, "reneg-bytes": true, "reneg-pkts": true, "hand-window": true, "tran-window": true, "ping": true,
	"ping-restart": true, "ping-exit": true, "ping-timer-rem": true, "keepalive": true, "inactive": true,
	"explicit-exit-notify": true, "tun-mtu": true, "tun-mtu-extra": true, "link-mtu": true, "mssfix": true,
	"fragment": true, "sndbuf": true, "rcvbuf": true, "fast-io": true, "redirect-gateway": true, "redirect-private": true,
	"route": true, "route-ipv6": true, "route-nopull": true, "route-delay": true, "route-method": true,
	"route-metric": true, "dhcp-option": true, "block-outside-dns": true, "block-ipv6": true, "pull-filter": true,
	"ignore-unknown-option": true, "static-challenge": true, "push-peer-info": true, "key-method": true,
	"tls-timeout": true, "single-session": true, "tun-ipv6": true, "ifconfig-nowarn": true, "topology": true,
	"mtu-disc": true, "replay-window": true, "no-replay": true, "auth-token": true, "auth-token-user": true,
	"connection": true, "crl-verify": true, "txqueuelen": true, "max-routes": true, "route-gateway": true,
	"bind": true, "lport": true, "local": true, "mtu-test": true, "tls-exit": true, "opt-verify": true,
	"tun-mtu-max": true, "disable-dco": true, "dns": true, "allow-recursive-routing": true, "providers": true,
	"windows-driver": true, "ip-win32": true, "route-metric-ipv6": true, "ifconfig-ipv6": true, "ifconfig": true,
	"auth-user-pass-optional": true, "session-timeout": true, "x509-username-field": true, "tls-crypt-v2-max-age": true,
	"setenv": true, "setenv-safe": true, "dev-node-win": false,
}

var ovpnServerOnly = map[string]bool{
	"server": true, "server-bridge": true, "tls-server": true, "client-config-dir": true, "ifconfig-pool": true,
	"push": true, "duplicate-cn": true, "client-to-client": true, "max-clients": true, "dh": true,
	"ifconfig-pool-persist": true, "verify-client-cert": true, "username-as-common-name": true, "auth-gen-token": true,
	"server-ipv6": true, "ccd-exclusive": true,
}

var ovpnDetectWords = map[string]int{
	"client": 3, "remote": 3, "dev": 2, "proto": 2, "tls-client": 3, "auth-user-pass": 2, "nobind": 2,
	"persist-key": 2, "persist-tun": 2, "remote-cert-tls": 2, "resolv-retry": 2, "cipher": 1, "auth": 1,
	"verb": 1, "comp-lzo": 2, "key-direction": 2, "tls-auth": 2, "tls-crypt": 2, "tls-crypt-v2": 2, "ca": 1,
	"cert": 1, "key": 1, "pkcs12": 2, "data-ciphers": 2, "ncp-ciphers": 2, "verify-x509-name": 2, "pull": 2,
	"redirect-gateway": 1, "dhcp-option": 1, "mute-replay-warnings": 2, "auth-nocache": 2, "float": 1,
	"tun-mtu": 2, "remote-random": 2, "rport": 1, "mssfix": 1, "reneg-sec": 1, "server": 1, "dh": 1,
	"keepalive": 1, "topology": 1, "ifconfig-pool-persist": 2, "tls-server": 2, "http-proxy": 1, "socks-proxy": 1,
	"route-nopull": 2, "block-outside-dns": 2, "auth-retry": 2, "setenv": 1, "ping": 1, "ping-restart": 1,
	"compress": 1, "data-ciphers-fallback": 2, "peer-fingerprint": 2, "tls-version-min": 2, "secret": 1, "port": 1,
	"ns-cert-type": 2, "script-security": 1, "up": 1, "down": 1, "explicit-exit-notify": 2, "connect-retry": 2,
}

func ovpnTokens(line string) []string {
	var out []string
	var cur strings.Builder
	in := false
	quote := byte(0)
	esc := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if esc {
			cur.WriteByte(c)
			esc = false
			in = true
			continue
		}
		if quote != 0 {
			if c == '\\' && quote == '"' {
				esc = true
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch {
		case c == '\\':
			esc = true
		case c == '"' || c == '\'':
			quote = c
			in = true
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		case (c == '#' || c == ';') && !in:
			return out
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

func ovpnTagLine(line string) (string, bool, bool) {
	t := strings.TrimSpace(line)
	if len(t) < 3 || t[0] != '<' || t[len(t)-1] != '>' {
		return "", false, false
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	closing := strings.HasPrefix(inner, "/")
	inner = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(inner, "/")))
	if inner == "" || strings.ContainsAny(inner, " \t<>") {
		return "", false, false
	}
	return inner, closing, true
}

func ovpnLex(text string, depth int) ([]ovpnDirective, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []ovpnDirective
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if tag, closing, ok := ovpnTagLine(line); ok {
			if closing {
				continue
			}
			var body strings.Builder
			end := -1
			for j := i + 1; j < len(lines); j++ {
				if t, cl, ok := ovpnTagLine(lines[j]); ok && cl && t == tag {
					end = j
					break
				}
				body.WriteString(strings.TrimRight(lines[j], "\r"))
				body.WriteByte('\n')
			}
			if end < 0 {
				return nil, fmt.Errorf("unterminated <%s> block at line %d", tag, i+1)
			}
			d := ovpnDirective{Name: tag, Inline: true, Body: body.String(), Line: i + 1}
			if tag == "connection" {
				if depth > 0 {
					return nil, fmt.Errorf("nested <connection> block at line %d", i+1)
				}
				sub, err := ovpnLex(d.Body, depth+1)
				if err != nil {
					return nil, err
				}
				d.Sub = sub
			}
			out = append(out, d)
			i = end
			continue
		}
		toks := ovpnTokens(line)
		if len(toks) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(toks[0], "--"))
		out = append(out, ovpnDirective{Name: name, Args: toks[1:], Line: i + 1})
	}
	return out, nil
}

func ovpnScore(text string) int {
	if strings.Contains(text, "[Interface]") || strings.Contains(text, "[Peer]") {
		return 0
	}
	ds, err := ovpnLex(text, 0)
	if err != nil {
		ds = nil
		for _, line := range strings.Split(text, "\n") {
			if toks := ovpnTokens(line); len(toks) > 0 {
				ds = append(ds, ovpnDirective{Name: strings.ToLower(toks[0]), Args: toks[1:]})
			}
		}
	}
	known, total, score := 0, 0, 0
	seen := map[string]bool{}
	core := false
	hasRemote := false
	for _, d := range ds {
		total++
		if d.Inline {
			if ovpnInlineTags[d.Name] {
				known++
				if !seen["<"+d.Name] {
					seen["<"+d.Name] = true
					score += 3
				}
				if d.Name == "ca" || d.Name == "connection" || d.Name == "tls-crypt" || d.Name == "tls-auth" {
					core = true
				}
			}
			continue
		}
		if strings.ContainsAny(d.Name, "=:[]{}") {
			continue
		}
		w, ok := ovpnDetectWords[d.Name]
		if !ok {
			if ovpnSafe[d.Name] || ovpnUnsafe[d.Name] || ovpnServerOnly[d.Name] {
				known++
			}
			continue
		}
		if len(d.Args) > 0 && strings.HasPrefix(d.Args[0], "=") {
			continue
		}
		switch d.Name {
		case "remote":
			if len(d.Args) == 0 || len(d.Args) > 3 {
				continue
			}
			hasRemote = true
			core = true
		case "dev":
			if len(d.Args) != 1 || !(strings.HasPrefix(strings.ToLower(d.Args[0]), "tun") || strings.HasPrefix(strings.ToLower(d.Args[0]), "tap")) {
				continue
			}
			core = true
		case "proto":
			if len(d.Args) != 1 || ovpnNormProto(d.Args[0]) == "" {
				continue
			}
			core = true
		case "client", "tls-client", "nobind", "persist-key", "persist-tun", "pull":
			if len(d.Args) != 0 {
				continue
			}
			core = true
		}
		known++
		if !seen[d.Name] {
			seen[d.Name] = true
			score += w
		}
	}
	if !core || total == 0 || len(seen) < 3 {
		return 0
	}
	if known*2 < total {
		return 0
	}
	if hasRemote && score >= 8 {
		return 90
	}
	if score >= 8 {
		return 75
	}
	return 50
}

func ovpnNormProto(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "udp", "udp4", "udp6":
		return "udp"
	case "tcp", "tcp-client", "tcp4", "tcp6", "tcp4-client", "tcp6-client":
		return "tcp"
	case "tcp-server", "tcp4-server", "tcp6-server":
		return "tcp-server"
	}
	return ""
}

func ovpnProtoFamily(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "udp4"), strings.HasPrefix(s, "tcp4"):
		return "4"
	case strings.HasPrefix(s, "udp6"), strings.HasPrefix(s, "tcp6"):
		return "6"
	}
	return ""
}

type OpenVpnConfigDetector struct{}

func (OpenVpnConfigDetector) Detect(f *vfile) int {
	if len(f.Data) == 0 || len(f.Data) > 2<<20 || !f.IsText() {
		return 0
	}
	return ovpnScore(f.Text())
}

type OpenVpnConfigParser struct{}

type ovpnParseState struct {
	f        *vfile
	fs       *vfs
	c        *Config
	m        *ovpnModel
	unsafe   []string
	unknown  []string
	server   bool
	client   bool
	secret   bool
	askpass  string
	hasAsk   bool
	pkcs12   []byte
	extra    [][]byte
	caDirect []byte
	certRaw  []byte
	keyRaw   []byte
}

func (st *ovpnParseState) material(d ovpnDirective, what string, cert bool) ([]byte, error) {
	if d.Inline {
		return []byte(d.Body), nil
	}
	if len(d.Args) == 0 {
		return nil, fmt.Errorf("%s: missing file argument", what)
	}
	ref := d.Args[0]
	if strings.EqualFold(ref, "[inline]") || strings.EqualFold(ref, "[[inline]]") {
		return nil, nil
	}
	g := st.fs.Resolve(st.f, ref)
	if g == nil {
		return nil, fmt.Errorf("%s file %q not found", what, ref)
	}
	st.c.AddDep(st.fs, g, cert)
	return g.Data, nil
}

func ovpnSplitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == ',' }) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (OpenVpnConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	text := f.Text()
	ds, err := ovpnLex(text, 0)
	if err != nil {
		return nil, err
	}
	c := newConfig(f, "OpenVPN", "OpenVPN")
	m := &ovpnModel{}
	st := &ovpnParseState{f: f, fs: fs, c: c, m: m}
	c.Payload = m
	c.Validator = OpenVpnConfigValidator{}
	c.Tester = OpenVpnConnectivityTester{}
	name := f.Name
	if i := strings.LastIndex(name, "."); i > 0 {
		name = name[:i]
	}
	m.Name = name
	if ovpnIsServerConfig(ds) {
		c.Name = name
		c.Status = StateUnsupported
		c.Error = "OpenVPN server configuration, not a client profile"
		c.Payload, c.Tester, c.Validator = nil, nil, nil
		return []*Config{c}, nil
	}

	type remoteSpec struct {
		host, port, proto string
		conn              *ovpnDirective
	}
	var remotes []remoteSpec
	globalPort, globalProto := "", ""
	var globalHTTP, globalSocks []string
	var httpUserPass string
	m.Dev = "tun"
	devType := ""
	cipher, fallback := "", ""
	var dataCiphers []string
	ncpDisable := false
	var sanitized strings.Builder
	var kept []ovpnDirective
	authUserPassArg := ""
	authUserPassInline := ""
	authUserPassSet := false
	keyDirSet := false
	var firstErr error
	setErr := func(e error) {
		if firstErr == nil && e != nil {
			firstErr = e
		}
	}

	for i := range ds {
		d := ds[i]
		if d.Inline {
			switch d.Name {
			case "connection":
				remotes = append(remotes, remoteSpec{conn: &ds[i]})
				kept = append(kept, d)
				continue
			case "auth-user-pass":
				authUserPassSet = true
				authUserPassInline = d.Body
				kept = append(kept, d)
				continue
			case "http-proxy-user-pass":
				httpUserPass = d.Body
				kept = append(kept, d)
				continue
			case "dh":
				st.server = true
				continue
			case "secret":
				st.secret = true
				continue
			}
			if !ovpnInlineTags[d.Name] {
				st.unknown = append(st.unknown, "<"+d.Name+">")
				continue
			}
		}
		if ovpnUnsafe[d.Name] {
			st.unsafe = append(st.unsafe, d.Name)
			continue
		}
		if ovpnServerOnly[d.Name] {
			if d.Name == "server" || d.Name == "server-bridge" || d.Name == "tls-server" || d.Name == "dh" {
				st.server = true
			}
			continue
		}
		keep := true
		switch d.Name {
		case "client":
			st.client = true
		case "tls-client":
			st.client = true
		case "mode":
			if len(d.Args) > 0 && strings.EqualFold(d.Args[0], "server") {
				st.server = true
			}
			keep = len(d.Args) > 0 && strings.EqualFold(d.Args[0], "p2p")
		case "secret":
			st.secret = true
			keep = false
		case "remote":
			if len(d.Args) == 0 {
				setErr(fmt.Errorf("line %d: remote without host", d.Line))
				continue
			}
			rs := remoteSpec{host: d.Args[0]}
			if len(d.Args) > 1 {
				rs.port = d.Args[1]
			}
			if len(d.Args) > 2 {
				rs.proto = d.Args[2]
			}
			remotes = append(remotes, rs)
		case "remote-random":
			m.RemoteRandom = true
		case "port", "rport":
			if len(d.Args) > 0 {
				globalPort = d.Args[0]
			}
		case "proto":
			if len(d.Args) > 0 {
				globalProto = d.Args[0]
			}
		case "dev":
			if len(d.Args) > 0 {
				m.Dev = strings.ToLower(d.Args[0])
			}
		case "dev-type":
			if len(d.Args) > 0 {
				devType = strings.ToLower(d.Args[0])
			}
		case "ca":
			b, err := st.material(d, "ca", true)
			setErr(err)
			if b != nil {
				st.caDirect = b
			}
		case "capath":
			c.Warn("capath directory is not supported; use ca")
			keep = false
		case "cert":
			b, err := st.material(d, "cert", true)
			setErr(err)
			if b != nil {
				st.certRaw = b
			}
		case "key":
			b, err := st.material(d, "key", false)
			setErr(err)
			if b != nil {
				st.keyRaw = b
			}
		case "extra-certs":
			b, err := st.material(d, "extra-certs", true)
			setErr(err)
			if b != nil {
				st.extra = append(st.extra, b)
			}
		case "pkcs12":
			b, err := st.material(d, "pkcs12", true)
			setErr(err)
			if b != nil {
				if d.Inline {
					raw, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b)), ""))
					if derr != nil {
						setErr(fmt.Errorf("inline <pkcs12> is not valid base64"))
					}
					b = raw
				}
				st.pkcs12 = b
			}
		case "tls-auth":
			b, err := st.material(d, "tls-auth", false)
			setErr(err)
			if b != nil {
				m.TLSAuth = b
			}
			if !d.Inline && len(d.Args) > 1 {
				m.KeyDirection = d.Args[1]
				keyDirSet = true
			}
		case "tls-crypt":
			b, err := st.material(d, "tls-crypt", false)
			setErr(err)
			if b != nil {
				m.TLSCrypt = b
			}
		case "tls-crypt-v2":
			b, err := st.material(d, "tls-crypt-v2", false)
			setErr(err)
			if b != nil {
				m.TLSCryptV2 = b
			}
		case "key-direction":
			if len(d.Args) > 0 && !keyDirSet {
				m.KeyDirection = d.Args[0]
			}
		case "cipher":
			if len(d.Args) > 0 {
				cipher = d.Args[0]
			}
		case "data-ciphers", "ncp-ciphers":
			if len(d.Args) > 0 {
				dataCiphers = ovpnSplitList(d.Args[0])
			}
		case "data-ciphers-fallback":
			if len(d.Args) > 0 {
				fallback = d.Args[0]
			}
		case "ncp-disable":
			ncpDisable = true
		case "auth":
			if len(d.Args) > 0 {
				m.Auth = d.Args[0]
			}
		case "comp-lzo":
			m.CompLZO = "yes"
		case "compress":
			if len(d.Args) > 0 {
				m.Compress = strings.ToLower(d.Args[0])
			} else {
				m.Compress = "stub"
			}
		case "auth-user-pass":
			authUserPassSet = true
			if len(d.Args) > 0 {
				authUserPassArg = d.Args[0]
			}
		case "askpass":
			st.hasAsk = true
			if len(d.Args) > 0 {
				g := fs.Resolve(f, d.Args[0])
				if g == nil {
					setErr(fmt.Errorf("askpass file %q not found", d.Args[0]))
				} else {
					c.AddDep(fs, g, false)
					st.askpass = ovpnFirstLine(g.Text())
				}
			}
		case "verify-x509-name":
			if len(d.Args) > 0 {
				m.VerifyX509 = d.Args[0]
			}
		case "peer-fingerprint":
			if d.Inline {
				m.PeerFingerprints = append(m.PeerFingerprints, ovpnSplitFingerprints(d.Body)...)
			} else if len(d.Args) > 0 {
				m.PeerFingerprints = append(m.PeerFingerprints, ovpnSplitFingerprints(d.Args[0])...)
			}
		case "tun-mtu":
			if len(d.Args) > 0 {
				if n, err := strconv.Atoi(d.Args[0]); err == nil && n >= 576 && n <= 65535 {
					m.MTU = n
				}
			}
		case "http-proxy":
			globalHTTP = d.Args
		case "socks-proxy":
			globalSocks = d.Args
		case "setenv", "setenv-safe":
			if len(d.Args) >= 2 && strings.EqualFold(d.Args[0], "FRIENDLY_NAME") {
				m.Name = d.Args[1]
			}
			if len(d.Args) == 0 || !ovpnBenignSetenv(d.Args[0]) {
				st.unsafe = append(st.unsafe, d.Name)
				keep = false
			}
		default:
			if !ovpnSafe[d.Name] {
				st.unknown = append(st.unknown, d.Name)
				keep = false
			}
		}
		if keep {
			kept = append(kept, d)
		}
	}
	for _, d := range kept {
		ovpnWriteDirective(&sanitized, d)
	}
	m.Sanitized = []byte(sanitized.String())
	c.RawConfig = m.Sanitized
	c.Name = m.Name

	if len(st.unsafe) > 0 {
		c.Warn("ignored unsafe directives: %s", strings.Join(ovpnUniq(st.unsafe), ", "))
	}
	if len(st.unknown) > 0 {
		c.Warn("ignored unknown directives: %s", strings.Join(ovpnUniq(st.unknown), ", "))
	}

	defaultPort := 1194
	if globalPort != "" {
		n, err := strconv.Atoi(globalPort)
		if err != nil || n <= 0 || n > 65535 {
			setErr(fmt.Errorf("invalid port %q", globalPort))
		} else {
			defaultPort = n
		}
	}
	if globalProto == "" {
		globalProto = "udp"
	}
	mkProxy := func(kind string, args []string, inlineCreds string, proto string) *ovpnProxy {
		if len(args) < 2 {
			if len(args) > 0 {
				c.Warn("%s without port ignored", kind)
			}
			return nil
		}
		port, err := strconv.Atoi(args[1])
		if err != nil || port <= 0 || port > 65535 {
			c.Warn("%s has invalid port %q; testing direct", kind, args[1])
			return nil
		}
		px := &ovpnProxy{Kind: kind, Host: strings.Trim(args[0], "[]"), Port: port}
		if proto != "tcp" {
			c.Warn("%s with UDP transport is not supported by the tester; testing direct", kind)
			return nil
		}
		if ip, err := netip.ParseAddr(px.Host); err == nil && ip.IsLoopback() || strings.EqualFold(px.Host, "localhost") {
			c.Warn("%s %s points to a local app on the device; testing direct", kind, net.JoinHostPort(px.Host, args[1]))
			return nil
		}
		creds := inlineCreds
		if len(args) > 2 {
			a := args[2]
			switch strings.ToLower(a) {
			case "auto", "auto-nct", "stdin", "none", "basic", "ntlm", "ntlm2", "digest", "[inline]":
			default:
				g := fs.Resolve(f, a)
				if g == nil {
					c.Warn("%s credentials file %q not found; trying without credentials", kind, a)
				} else {
					c.AddDep(fs, g, false)
					creds = g.Text()
				}
			}
		}
		if creds != "" {
			lines := ovpnLines(creds)
			if len(lines) > 0 {
				px.User = lines[0]
			}
			if len(lines) > 1 {
				px.Pass = lines[1]
			}
		}
		return px
	}

	seenRemote := map[string]bool{}
	addRemote := func(host, port, proto string, http, socks []string) {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if host == "" {
			setErr(errors.New("remote without host"))
			return
		}
		if strings.ContainsAny(host, " /\\\"'") {
			setErr(fmt.Errorf("invalid remote host %q", host))
			return
		}
		pn := defaultPort
		if port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n <= 0 || n > 65535 {
				setErr(fmt.Errorf("invalid remote port %q", port))
				return
			}
			pn = n
		}
		if proto == "" {
			proto = globalProto
		}
		np := ovpnNormProto(proto)
		if np == "" {
			setErr(fmt.Errorf("unknown proto %q", proto))
			return
		}
		if np == "tcp-server" {
			st.server = true
			return
		}
		r := ovpnRemote{Host: host, Port: pn, Proto: np, Family: ovpnProtoFamily(proto)}
		if len(http) > 0 {
			r.Proxy = mkProxy("http-proxy", http, httpUserPass, np)
		} else if len(socks) > 0 {
			r.Proxy = mkProxy("socks-proxy", socks, "", np)
		}
		k := r.String()
		if seenRemote[k] {
			return
		}
		seenRemote[k] = true
		m.Remotes = append(m.Remotes, r)
	}
	for _, rs := range remotes {
		if rs.conn == nil {
			addRemote(rs.host, rs.port, rs.proto, globalHTTP, globalSocks)
			continue
		}
		cport, cproto := "", ""
		chttp, csocks := globalHTTP, globalSocks
		var crem []remoteSpec
		for _, sd := range rs.conn.Sub {
			switch sd.Name {
			case "remote":
				if len(sd.Args) == 0 {
					continue
				}
				x := remoteSpec{host: sd.Args[0]}
				if len(sd.Args) > 1 {
					x.port = sd.Args[1]
				}
				if len(sd.Args) > 2 {
					x.proto = sd.Args[2]
				}
				crem = append(crem, x)
			case "port", "rport":
				if len(sd.Args) > 0 {
					cport = sd.Args[0]
				}
			case "proto":
				if len(sd.Args) > 0 {
					cproto = sd.Args[0]
				}
			case "http-proxy":
				chttp = sd.Args
			case "socks-proxy":
				csocks = sd.Args
			default:
				if ovpnUnsafe[sd.Name] {
					c.Warn("ignored unsafe directive in <connection>: %s", sd.Name)
				}
			}
		}
		for _, x := range crem {
			port := x.port
			if port == "" {
				port = cport
			}
			proto := x.proto
			if proto == "" {
				proto = cproto
			}
			addRemote(x.host, port, proto, chttp, csocks)
		}
	}

	if devType != "" {
		m.Dev = devType
	}
	switch {
	case strings.HasPrefix(m.Dev, "tun"):
		m.Dev = "tun"
	case strings.HasPrefix(m.Dev, "tap"):
		m.Dev = "tap"
	case strings.HasPrefix(m.Dev, "null"):
		m.Dev = "null"
	}

	if firstErr != nil {
		c.Status = StateInvalid
		c.Error = shortErr(firstErr)
		ovpnFillView(c, m)
		return []*Config{c}, nil
	}
	if st.server && !st.client {
		c.Status = StateUnsupported
		c.Error = "OpenVPN server configuration, not a client profile"
		ovpnFillView(c, m)
		return []*Config{c}, nil
	}
	if st.secret && !st.client && len(st.caDirect) == 0 {
		c.Status = StateUnsupported
		c.Error = "OpenVPN static-key (p2p) mode is not supported by the userspace client"
		ovpnFillView(c, m)
		return []*Config{c}, nil
	}

	if len(st.pkcs12) > 0 {
		cp, kp, cas, err := decodePKCS12(st.pkcs12, st.askpass)
		if err != nil && !errors.Is(err, pkcs12.ErrIncorrectPassword) {
			if raw, derr := b64decode(strings.Join(strings.Fields(string(st.pkcs12)), "")); derr == nil {
				if cp2, kp2, cas2, err2 := decodePKCS12(raw, st.askpass); err2 == nil || errors.Is(err2, pkcs12.ErrIncorrectPassword) {
					cp, kp, cas, err = cp2, kp2, cas2, err2
				}
			}
		}
		if err != nil {
			switch {
			case errors.Is(err, pkcs12.ErrIncorrectPassword) && st.askpass == "":
				c.Status = StateUnsupported
				c.Error = "pkcs12 bundle is password protected and no askpass file is provided"
			case errors.Is(err, pkcs12.ErrIncorrectPassword):
				c.Status = StateInvalid
				c.Error = "askpass password does not decrypt the pkcs12 bundle"
			default:
				c.Status = StateInvalid
				c.Error = "cannot decode pkcs12 bundle: " + shortErr(err)
			}
			ovpnFillView(c, m)
			return []*Config{c}, nil
		}
		if len(st.certRaw) == 0 {
			st.certRaw = cp
		}
		if len(st.keyRaw) == 0 {
			st.keyRaw = kp
		}
		if len(st.caDirect) == 0 {
			for _, b := range cas {
				st.caDirect = append(st.caDirect, b...)
			}
		}
	}
	m.CA = ovpnCertPEM(st.caDirect)
	if len(st.certRaw) > 0 {
		m.Cert = ovpnCertPEM(st.certRaw)
		for _, e := range st.extra {
			m.Cert = append(m.Cert, ovpnCertPEM(e)...)
		}
	}
	if len(st.keyRaw) > 0 {
		k, err := ovpnKeyPEM(st.keyRaw, st.askpass)
		if err != nil {
			if errors.Is(err, errOvpnKeyPassword) && st.askpass == "" {
				c.Status = StateUnsupported
				c.Error = "private key is encrypted and no askpass file is provided"
			} else {
				c.Status = StateInvalid
				c.Error = "private key: " + shortErr(err)
			}
			ovpnFillView(c, m)
			return []*Config{c}, nil
		}
		m.Key = k
	}

	if authUserPassSet {
		m.AuthUserPass = true
		var creds string
		hasSource := false
		if authUserPassInline != "" {
			creds = authUserPassInline
			hasSource = true
		} else if authUserPassArg != "" && !strings.EqualFold(authUserPassArg, "[inline]") {
			g := fs.Resolve(f, authUserPassArg)
			if g == nil {
				c.Status = StateInvalid
				c.Error = fmt.Sprintf("auth-user-pass file %q not found", authUserPassArg)
				ovpnFillView(c, m)
				return []*Config{c}, nil
			}
			c.AddDep(fs, g, false)
			creds = g.Text()
			hasSource = true
		}
		lines := ovpnLines(creds)
		if len(lines) > 0 {
			m.Username = lines[0]
		}
		if len(lines) > 1 {
			m.Password = lines[1]
		}
		switch {
		case m.Username != "" && len(lines) > 1:
			m.HasCreds = true
		case m.Username != "":
			m.CredNote = "auth not tested: password missing in credentials file"
		case hasSource:
			m.CredNote = "auth not tested: credentials file is empty"
		default:
			m.CredNote = "auth not tested: no credentials in file"
		}
		c.Username = m.Username
		if m.HasCreds {
			c.Password = m.Password
		}
	}

	m.Cipher, m.DataCiphers, m.Fallback, m.CipherUnsupported = ovpnCiphers(cipher, dataCiphers, fallback, ncpDisable)
	if m.CipherUnsupported != "" {
		c.Warn("data cipher %s is not supported by the userspace client; relying on cipher negotiation", m.CipherUnsupported)
	}
	m.Auth = strings.ToUpper(strings.TrimSpace(m.Auth))
	switch m.Auth {
	case "", "NONE":
		m.Auth = "SHA1"
	case "SHA-1":
		m.Auth = "SHA1"
	case "SHA-256":
		m.Auth = "SHA256"
	case "SHA-384":
		m.Auth = "SHA384"
	case "SHA-512":
		m.Auth = "SHA512"
	}
	if m.Compress != "" && m.Compress != "lzo" && m.CompLZO == "" {
		c.Warn("compress %s framing is not supported by the userspace client; data-plane probe may fail", m.Compress)
	}
	if m.Compress == "lzo" {
		m.CompLZO = "yes"
	}
	if m.RemoteRandom && len(m.Remotes) > 1 {
		c.Warn("remote-random: remotes are tested in file order")
	}

	ovpnFillView(c, m)
	if m.Dev == "tap" {
		c.Status = StateUnsupported
		c.Error = "dev tap (layer 2) is not supported by the userspace client; only dev tun"
		return []*Config{c}, nil
	}
	if m.Dev != "tun" {
		c.Status = StateUnsupported
		c.Error = fmt.Sprintf("dev %s is not supported; only dev tun", m.Dev)
		return []*Config{c}, nil
	}
	return []*Config{c}, nil
}

func ovpnIsServerConfig(ds []ovpnDirective) bool {
	server, client := false, false
	for _, d := range ds {
		switch d.Name {
		case "client", "tls-client", "pull":
			if !d.Inline {
				client = true
			}
		case "server", "server-bridge", "tls-server":
			if !d.Inline {
				server = true
			}
		case "mode":
			if len(d.Args) > 0 && strings.EqualFold(d.Args[0], "server") {
				server = true
			}
		case "proto":
			if len(d.Args) > 0 && ovpnNormProto(d.Args[0]) == "tcp-server" {
				server = true
			}
		}
	}
	return server && !client
}

func ovpnBenignSetenv(name string) bool {
	n := strings.ToUpper(name)
	switch n {
	case "FRIENDLY_NAME", "CLIENT_CERT", "PUSH_PEER_INFO", "OPT", "SERVER_POLL_TIMEOUT", "GENERIC_CONFIG", "ALLOW_PASSWORD_SAVE", "USERNAME":
		return true
	}
	return strings.HasPrefix(n, "UV_") || strings.HasPrefix(n, "IV_")
}

func ovpnUniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func ovpnLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" && len(out) == 0 {
			continue
		}
		out = append(out, strings.TrimSpace(l))
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

func ovpnFirstLine(s string) string {
	ls := ovpnLines(s)
	if len(ls) == 0 {
		return ""
	}
	return ls[0]
}

func ovpnSplitFingerprints(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r' }) {
		p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
		if len(p) == 64 {
			if _, err := hex.DecodeString(p); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

func ovpnArgQuote(a string) string {
	if a == "" {
		return `""`
	}
	if strings.ContainsAny(a, " \t\"'#;\\") {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(a, `\`, `\\`), `"`, `\"`) + `"`
	}
	return a
}

func ovpnWriteDirective(b *strings.Builder, d ovpnDirective) {
	if d.Inline {
		b.WriteString("<" + d.Name + ">\n")
		if d.Name == "connection" {
			for _, s := range d.Sub {
				if ovpnUnsafe[s.Name] || (!ovpnSafe[s.Name] && !s.Inline) {
					continue
				}
				ovpnWriteDirective(b, s)
			}
		} else {
			b.WriteString(d.Body)
			if !strings.HasSuffix(d.Body, "\n") {
				b.WriteByte('\n')
			}
		}
		b.WriteString("</" + d.Name + ">\n")
		return
	}
	b.WriteString(d.Name)
	for _, a := range d.Args {
		b.WriteByte(' ')
		b.WriteString(ovpnArgQuote(a))
	}
	b.WriteByte('\n')
}

var ovpnCipherOK = map[string]bool{
	"AES-128-GCM": true, "AES-192-GCM": true, "AES-256-GCM": true, "AES-128-CBC": true, "AES-192-CBC": true,
	"AES-256-CBC": true, "CHACHA20-POLY1305": true,
}

func ovpnNormCipher(s string) string {
	u := strings.ToUpper(strings.TrimSpace(s))
	switch u {
	case "AES-CBC":
		return "AES-128-CBC"
	case "AES128-GCM", "ID-AES128-GCM":
		return "AES-128-GCM"
	case "AES192-GCM", "ID-AES192-GCM":
		return "AES-192-GCM"
	case "AES256-GCM", "ID-AES256-GCM":
		return "AES-256-GCM"
	case "AES128-CBC", "AES128":
		return "AES-128-CBC"
	case "AES192-CBC", "AES192":
		return "AES-192-CBC"
	case "AES256-CBC", "AES256":
		return "AES-256-CBC"
	case "CHACHA20POLY1305":
		return "CHACHA20-POLY1305"
	}
	return u
}

func ovpnCiphers(cipher string, list []string, fallback string, ncpDisable bool) (string, []string, string, string) {
	defaults := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	cipher = ovpnNormCipher(cipher)
	fallback = ovpnNormCipher(fallback)
	var out []string
	add := func(x string) {
		if !ovpnCipherOK[x] {
			return
		}
		for _, y := range out {
			if y == x {
				return
			}
		}
		out = append(out, x)
	}
	switch {
	case len(list) > 0:
		for _, x := range list {
			add(ovpnNormCipher(x))
		}
	case ncpDisable && cipher != "":
		add(cipher)
	default:
		if cipher != "" {
			add(cipher)
		}
		for _, x := range defaults {
			add(x)
		}
	}
	if len(out) == 0 {
		out = append(out, defaults...)
	}
	fb := ""
	if fallback != "" && ovpnCipherOK[fallback] {
		fb = fallback
	}
	primary := out[0]
	switch {
	case fb != "":
		primary = fb
	case cipher != "" && ovpnCipherOK[cipher]:
		primary = cipher
	}
	legacy := fallback
	if legacy == "" {
		legacy = cipher
	}
	unsupported := ""
	if legacy != "" && !ovpnCipherOK[legacy] {
		unsupported = legacy
	}
	return primary, out, fb, unsupported
}

func ovpnFillView(c *Config, m *ovpnModel) {
	if len(m.Remotes) > 0 {
		r := m.Remotes[0]
		c.Host, c.Port, c.Transport = r.Host, r.Port, r.Proto
	}
	sec := "tls"
	switch {
	case len(m.TLSCryptV2) > 0:
		sec = "tls-crypt-v2"
	case len(m.TLSCrypt) > 0:
		sec = "tls-crypt"
	case len(m.TLSAuth) > 0:
		sec = "tls-auth"
	}
	if m.Cipher != "" {
		sec += "+" + m.Cipher
	}
	c.Security = sec
	c.UDP = c.Transport == "udp"
	h := sha256.New()
	for _, b := range pemBlocks(m.CA, "CERTIFICATE") {
		h.Write(b)
	}
	h.Write([]byte{0})
	h.Write(m.Cert)
	h.Write([]byte{0})
	h.Write(m.TLSAuth)
	h.Write(m.TLSCrypt)
	h.Write(m.TLSCryptV2)
	var rs []string
	for _, r := range m.Remotes {
		k := strings.ToLower(r.String())
		if r.Proxy != nil {
			k += fmt.Sprintf("|%s|%s|%d|%s|%s", r.Proxy.Kind, strings.ToLower(r.Proxy.Host), r.Proxy.Port, r.Proxy.User, r.Proxy.Pass)
		}
		rs = append(rs, k)
	}
	sort.Strings(rs)
	h.Write([]byte(strings.Join(rs, ",")))
	fmt.Fprintf(h, "\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%v",
		m.Password, m.Auth, m.Cipher, strings.Join(m.DataCiphers, ":"), m.Fallback, m.KeyDirection,
		m.CompLZO, m.Compress, strings.Join(m.PeerFingerprints, ","), m.AuthUserPass)
	c.Extra = hex.EncodeToString(h.Sum(nil)[:12])
}

func ovpnCertPEM(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	b = toPEMCert(b)
	blocks := pemBlocks(b, "CERTIFICATE")
	if len(blocks) == 0 {
		return b
	}
	var out []byte
	for _, x := range blocks {
		out = append(out, x...)
	}
	return out
}

type OpenVpnConfigValidator struct{}

func (OpenVpnConfigValidator) Validate(c *Config) error {
	m, ok := c.Payload.(*ovpnModel)
	if !ok || m == nil {
		return errors.New("missing OpenVPN model")
	}
	if len(m.Remotes) == 0 {
		return errors.New("no remote server in config")
	}
	if len(m.CA) == 0 {
		if len(m.PeerFingerprints) > 0 {
			return nil
		}
		return errors.New("missing CA certificate (ca / <ca>)")
	}
	if len(pemBlocks(m.CA, "CERTIFICATE")) == 0 {
		return errors.New("CA is not a valid certificate")
	}
	if len(m.Cert) > 0 || len(m.Key) > 0 {
		if len(m.Cert) == 0 {
			return errors.New("key present but client certificate is missing")
		}
		if len(m.Key) == 0 {
			return errors.New("client certificate present but private key is missing")
		}
	} else if !m.AuthUserPass {
		return errors.New("no client certificate and no auth-user-pass")
	}
	cfg, err := ovpnClientConfig(m, m.Remotes[0], m.CA, "", "")
	if err != nil {
		return err
	}
	if err := ovpnCheckKeyPair(cfg.Cert, cfg.Key); err != nil {
		return err
	}
	return nil
}

func init() {
	registerFormat(&fileFormat{Name: "OpenVPN", Detector: OpenVpnConfigDetector{}, Parser: OpenVpnConfigParser{}})
}
