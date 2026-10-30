package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type OpenConnectConnectivityTester struct{}

type ocValidator struct{}

var ocProtoNames = map[string]string{
	"anyconnect": "AnyConnect",
	"gp":         "GlobalProtect",
	"fortinet":   "Fortinet",
	"nc":         "Juniper",
	"pulse":      "Pulse",
	"f5":         "F5",
	"array":      "Array",
}

const ocUserAgent = "AnyConnect-compatible OpenConnect VPN Agent v9.12"

func init() {
	buildOCConfig = ocBuildConfig
}

func ocNormProto(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(s)
	switch s {
	case "", "anyconnect", "cisco", "ciscoanyconnect", "ocserv", "openconnect", "asa", "cstp", "anyconnectssl", "ciscossl":
		return "anyconnect"
	case "gp", "globalprotect", "paloalto", "paloaltonetworks", "pan", "panglobalprotect", "gpst":
		return "gp"
	case "fortinet", "forti", "fortigate", "fortisslvpn", "fortinetssl", "fortivpn", "fortissl":
		return "fortinet"
	case "nc", "juniper", "oncp", "ncsvc", "netconnect", "junipernc", "junipernetworkconnect":
		return "nc"
	case "pulse", "pulsesecure", "ivanti", "pulseconnectsecure", "ift", "ivanticonnectsecure", "pulsevpn":
		return "pulse"
	case "f5", "bigip", "f5bigip", "f5vpn", "f5networks", "f5apm":
		return "f5"
	case "array", "arraynetworks", "arrayag", "arrayvpn":
		return "array"
	}
	return ""
}

func ocSplitServer(raw string) (host string, port int, path string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		h := strings.TrimPrefix(raw, "https://")
		if i := strings.IndexAny(h, "/?#"); i >= 0 {
			h = h[:i]
		}
		return strings.Trim(h, "[]"), 0, ""
	}
	host = u.Hostname()
	port, _ = strconv.Atoi(u.Port())
	path = u.EscapedPath()
	if path == "/" {
		path = ""
	}
	return
}

func ocBuildConfig(f *vfile, fs *vfs, s *ocSpec) *Config {
	proto := ocNormProto(s.Protocol)
	if proto == "" {
		return unsupportedConfig(f, "OpenConnect", s.Protocol, "unsupported OpenConnect protocol "+s.Protocol)
	}
	sp := *s
	sp.Protocol = proto
	host, port, path := ocSplitServer(s.Host)
	if s.Port > 0 {
		port = s.Port
	}
	if port <= 0 || port > 65535 {
		port = 443
	}
	if p := strings.TrimSpace(s.Path); p != "" {
		path = p
	}
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	sp.Host, sp.Port, sp.Path = host, port, path
	c := newConfig(f, "OpenConnect", ocProtoNames[proto])
	c.Name = s.Name
	c.Host = host
	c.Port = port
	c.Transport = "tcp"
	c.Security = "tls"
	if host != "" && net.ParseIP(host) == nil {
		c.SNI = host
	}
	c.Username, c.Password = s.Username, s.Password
	c.Extra = proto + "|" + s.Group + "|" + path
	if s.Password != "" || s.ServerCertPin != "" || len(s.ClientCert) > 0 || len(s.CACert) > 0 {
		h := sha1.Sum([]byte(s.Password + "\x00" + s.ServerCertPin + "\x00" + string(s.ClientCert) + "\x00" + string(s.CACert)))
		c.Extra += "|" + hex.EncodeToString(h[:6])
	}
	if sp.ServerCertPin != "" {
		if _, err := ocParsePins(sp.ServerCertPin); err != nil {
			c.Warn("ignoring server certificate pin: %s", shortErr(err))
			sp.ServerCertPin = ""
		}
	}
	if len(sp.CACert) > 0 {
		if pool := ocCertPool(sp.CACert); pool == nil {
			c.Warn("CA certificate could not be parsed; server certificate will not be verified against it")
			sp.CACert = nil
		}
	}
	if len(sp.ClientCert) > 0 {
		if _, err := ocClientCert(&sp); err != nil {
			c.Warn("client certificate could not be loaded: %s", shortErr(err))
			sp.ClientCert, sp.ClientKey = nil, nil
		}
	}
	c.Payload = &sp
	c.Tester = &OpenConnectConnectivityTester{}
	c.Validator = ocValidator{}
	return c
}

func (ocValidator) Validate(c *Config) error {
	s, ok := c.Payload.(*ocSpec)
	if !ok || s == nil {
		return errors.New("internal: missing OpenConnect parameters")
	}
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("missing server address")
	}
	if strings.ContainsAny(c.Host, " /\\@\t") {
		return fmt.Errorf("invalid server address %q", c.Host)
	}
	if c.Password != "" && c.Username == "" && s.Protocol != "gp" {
		c.Warn("password without username")
	}
	return nil
}

type ocPin struct {
	kind string
	val  string
}

func ocParsePins(s string) ([]ocPin, error) {
	var out []ocPin
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lp := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lp, "pin-sha256:"):
			v := part[11:]
			if b, err := base64.StdEncoding.DecodeString(v); err != nil || len(b) != 32 {
				return nil, fmt.Errorf("invalid pin-sha256 value")
			}
			out = append(out, ocPin{"pin-sha256", v})
		case strings.HasPrefix(lp, "sha256:"), strings.HasPrefix(lp, "sha1:"):
			k, v, _ := strings.Cut(lp, ":")
			v = strings.ReplaceAll(v, ":", "")
			if len(v) < 4 || !ocIsHex(v) {
				return nil, fmt.Errorf("invalid %s fingerprint", k)
			}
			out = append(out, ocPin{k, v})
		default:
			v := strings.ReplaceAll(lp, ":", "")
			if len(v) < 4 || !ocIsHex(v) {
				return nil, fmt.Errorf("unrecognized pin %q", part)
			}
			out = append(out, ocPin{"cert-sha1", v})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty pin")
	}
	return out, nil
}

func ocIsHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func ocPinMatch(pins []ocPin, cert *x509.Certificate) bool {
	spki256 := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spki1 := sha1.Sum(cert.RawSubjectPublicKeyInfo)
	cert1 := sha1.Sum(cert.Raw)
	cert256 := sha256.Sum256(cert.Raw)
	for _, p := range pins {
		switch p.kind {
		case "pin-sha256":
			if p.val == base64.StdEncoding.EncodeToString(spki256[:]) {
				return true
			}
		case "sha256":
			if strings.HasPrefix(hex.EncodeToString(spki256[:]), p.val) || len(p.val) == 64 && p.val == hex.EncodeToString(cert256[:]) {
				return true
			}
		case "sha1":
			if strings.HasPrefix(hex.EncodeToString(spki1[:]), p.val) || len(p.val) == 40 && p.val == hex.EncodeToString(cert1[:]) {
				return true
			}
		case "cert-sha1":
			if strings.HasPrefix(hex.EncodeToString(cert1[:]), p.val) || len(p.val) == 64 && p.val == hex.EncodeToString(cert256[:]) {
				return true
			}
		}
	}
	return false
}

func ocCertPool(data []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	n := 0
	for _, b := range pemBlocks(data, "CERTIFICATE") {
		if pool.AppendCertsFromPEM(b) {
			n++
		}
	}
	if n == 0 {
		if c, err := x509.ParseCertificate(data); err == nil {
			pool.AddCert(c)
			n++
		} else if b := toPEMCert(data); !bytes.Equal(b, data) && pool.AppendCertsFromPEM(b) {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return pool
}

func ocClientCert(s *ocSpec) (tls.Certificate, error) {
	cert, key := s.ClientCert, s.ClientKey
	if len(key) == 0 {
		key = cert
	}
	if !bytes.Contains(cert, []byte("-----BEGIN")) {
		if _, err := x509.ParseCertificate(cert); err == nil {
			cert = toPEMCert(cert)
		}
	}
	return tls.X509KeyPair(cert, key)
}

type ocTLSPolicy struct {
	host      string
	sni       string
	pins      []ocPin
	roots     *x509.CertPool
	client    *tls.Certificate
	untrusted string
	certReq   bool
	mu        sync.Mutex
}

func newOCTLSPolicy(s *ocSpec) *ocTLSPolicy {
	pol := &ocTLSPolicy{host: s.Host}
	if net.ParseIP(s.Host) == nil {
		pol.sni = s.Host
	}
	if s.ServerCertPin != "" {
		pol.pins, _ = ocParsePins(s.ServerCertPin)
	}
	if len(s.CACert) > 0 {
		pol.roots = ocCertPool(s.CACert)
	}
	if len(s.ClientCert) > 0 {
		if c, err := ocClientCert(s); err == nil {
			pol.client = &c
		}
	}
	return pol
}

func (pol *ocTLSPolicy) config(serverName string, primary bool) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       ocCipherSuites(),
	}
	if serverName != "" && net.ParseIP(serverName) == nil {
		cfg.ServerName = serverName
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		pol.mu.Lock()
		pol.certReq = true
		pol.mu.Unlock()
		if pol.client != nil {
			cl := *pol.client
			return &cl, nil
		}
		return &tls.Certificate{}, nil
	}
	if primary {
		cfg.VerifyConnection = pol.verify
	}
	return cfg
}

func ocCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		switch s.ID {
		case tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			ids = append(ids, s.ID)
		}
	}
	return ids
}

func (pol *ocTLSPolicy) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if len(pol.pins) > 0 {
		if !ocPinMatch(pol.pins, leaf) {
			return fmt.Errorf("server certificate does not match pinned fingerprint (server pin-sha256:%s)", ocLeafPin(leaf))
		}
		return nil
	}
	if pol.roots != nil {
		opts := x509.VerifyOptions{Roots: pol.roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("server certificate is not signed by the configured CA: %s", shortErr(err))
		}
		return nil
	}
	opts := x509.VerifyOptions{Intermediates: inter, DNSName: pol.sni}
	if _, err := leaf.Verify(opts); err != nil {
		pol.mu.Lock()
		pol.untrusted = ocTrustReason(err)
		pol.mu.Unlock()
	}
	return nil
}

func ocLeafPin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(h[:])
}

func ocTrustReason(err error) string {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return "unknown or self-signed issuer"
	case errors.As(err, &hn):
		return "hostname mismatch"
	case errors.As(err, &ci):
		if ci.Reason == x509.Expired {
			return "expired or not yet valid"
		}
		return "invalid certificate"
	}
	return shortErr(err)
}

func (pol *ocTLSPolicy) note(p *probe) {
	pol.mu.Lock()
	u := pol.untrusted
	pol.mu.Unlock()
	if u != "" {
		p.Note("server certificate not trusted (%s)", u)
	}
}

type ocSession struct {
	p        *probe
	ctx      context.Context
	spec     *ocSpec
	cfg      *Config
	pol      *ocTLSPolicy
	base     *url.URL
	ua       string
	first    net.Conn
	firstKey string
	mu       sync.Mutex
	conns    []net.Conn
	tr       *http.Transport
	client   *http.Client
	cookies  map[string]string
	order    []string
	latency  time.Duration
	hsDone   bool
}

func (t *OpenConnectConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	s, ok := c.Payload.(*ocSpec)
	if !ok || s == nil {
		p.Fail(StageParse, StateInvalid, errors.New("missing OpenConnect parameters"))
		return
	}
	p.Engine("native")
	sess := newOCSession(ctx, p, c, s)
	defer sess.close()
	if s.Protocol == "pulse" {
		ocPulseTest(sess)
		return
	}
	if !sess.connect() {
		return
	}
	switch s.Protocol {
	case "anyconnect":
		ocAnyConnectTest(sess)
	case "gp":
		ocGPTest(sess)
	case "fortinet":
		ocFortinetTest(sess)
	case "nc":
		ocJuniperTest(sess)
	case "f5":
		ocF5Test(sess)
	case "array":
		ocArrayTest(sess)
	default:
		p.Unsupported("unsupported OpenConnect protocol " + s.Protocol)
		return
	}
	sess.finish()
}

func newOCSession(ctx context.Context, p *probe, c *Config, s *ocSpec) *ocSession {
	sess := &ocSession{p: p, ctx: ctx, spec: s, cfg: c, pol: newOCTLSPolicy(s), ua: ocUserAgent, cookies: map[string]string{}}
	sess.base = &url.URL{Scheme: "https", Host: ocHostPort(s.Host, s.Port), Path: "/"}
	sess.tr = &http.Transport{
		DialTLSContext:        sess.dialTLS,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	sess.client = &http.Client{
		Transport: sess.tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return sess
}

func ocHostPort(host string, port int) string {
	if port == 443 || port == 0 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *ocSession) connect() bool {
	conn := s.p.DialTCP(s.ctx, s.spec.Host, s.spec.Port)
	if conn == nil {
		return false
	}
	tc, err := s.tlsHandshake(conn, s.spec.Host, true)
	if err != nil {
		conn.Close()
		s.p.Fail(StageHandshake, StateHandshakeFailed, ocErr("TLS: %s", ocTLSErr(err)))
		return false
	}
	s.first = tc
	s.firstKey = net.JoinHostPort(s.spec.Host, strconv.Itoa(s.spec.Port))
	s.track(tc)
	return true
}

func (s *ocSession) tlsHandshake(conn net.Conn, serverName string, primary bool) (*tls.Conn, error) {
	hctx, cancel := s.p.StageCtx(s.ctx, StageHandshake)
	defer cancel()
	tc := tls.Client(conn, s.pol.config(serverName, primary))
	if err := tc.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	return tc, nil
}

func ocTLSErr(err error) string {
	msg := shortErr(err)
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return "server does not speak TLS on this port"
	}
	if errors.Is(err, io.EOF) || strings.Contains(msg, "EOF") {
		return "connection closed during TLS handshake"
	}
	return msg
}

func (s *ocSession) track(c net.Conn) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

func (s *ocSession) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.Lock()
	if s.first != nil && strings.EqualFold(addr, s.firstKey) {
		c := s.first
		s.first = nil
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	target := addr
	if strings.EqualFold(host, s.spec.Host) {
		ip := s.p.res.Address
		if net.ParseIP(ip) == nil && len(s.p.addrs) > 0 {
			ip = s.p.addrs[0].String()
		}
		if net.ParseIP(ip) != nil {
			_, port, _ := net.SplitHostPort(addr)
			target = net.JoinHostPort(ip, port)
		}
	}
	var d net.Dialer
	dctx, cancel := s.p.StageCtx(ctx, StageTransport)
	defer cancel()
	raw, err := d.DialContext(dctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	s.track(raw)
	tc, err := s.tlsHandshake(raw, host, false)
	if err != nil {
		raw.Close()
		return nil, err
	}
	s.track(tc)
	return tc, nil
}

func (s *ocSession) close() {
	if s.tr != nil {
		s.tr.CloseIdleConnections()
	}
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.first = nil
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func (s *ocSession) handshakeOK(lat time.Duration) {
	if s.hsDone {
		return
	}
	s.hsDone = true
	s.latency = lat
	s.p.Pass(StageHandshake)
}

type ocTimeoutErr struct{ msg string }

func (e ocTimeoutErr) Error() string { return e.msg }

func (e ocTimeoutErr) Unwrap() error { return context.DeadlineExceeded }

func ocErr(format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	l := strings.ToLower(msg)
	if strings.Contains(l, "deadline exceeded") || strings.Contains(l, "i/o timeout") || strings.Contains(l, "timeout exceeded") {
		return ocTimeoutErr{msg}
	}
	return errors.New(msg)
}

func (s *ocSession) handshakeFail(format string, args ...any) {
	s.p.Fail(StageHandshake, StateHandshakeFailed, ocErr(format, args...))
}

func (s *ocSession) authOK() {
	s.p.Pass(StageAuth)
}

func (s *ocSession) authFail(format string, args ...any) {
	s.p.Fail(StageAuth, StateAuthFailed, ocErr(format, args...))
}

func (s *ocSession) authError(err error) {
	if err == nil {
		err = errors.New("authentication exchange failed")
	}
	s.p.Fail(StageAuth, StateHandshakeFailed, ocErr("%s", err.Error()))
}

func (s *ocSession) certMissing() bool {
	s.pol.mu.Lock()
	defer s.pol.mu.Unlock()
	return s.pol.certReq && s.pol.client == nil
}

func (s *ocSession) failNoResponse(what string, err error) {
	if s.certMissing() && !s.hsDone {
		s.p.Fail(StageAuth, StateAuthFailed, ocErr("server requires a client certificate (none in file); %s: %s", what, shortErr(err)))
		return
	}
	s.handshakeFail("%s: %s", what, shortErr(err))
}

func (s *ocSession) hasCreds() bool {
	return s.spec.Username != "" || s.spec.Password != ""
}

func (s *ocSession) noCreds() {
	s.p.Note("auth not tested: no credentials in file")
}

func (s *ocSession) finish() {
	s.pol.note(s.p)
	if !s.p.Failed() && s.hsDone {
		s.p.Connectable(s.latency)
	}
}

type ocResp struct {
	Status int
	Header http.Header
	Body   []byte
	URL    *url.URL
	Redirs int
}

func (r *ocResp) text() string { return string(r.Body) }

func (r *ocResp) location() string {
	if r.Status >= 300 && r.Status < 400 {
		return r.Header.Get("Location")
	}
	return ""
}

func (s *ocSession) resolve(ref string) *url.URL {
	u, err := s.base.Parse(ref)
	if err != nil {
		return s.base
	}
	return u
}

func (s *ocSession) setCookies(h http.Header) {
	for _, line := range h.Values("Set-Cookie") {
		part, _, _ := strings.Cut(line, ";")
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		val = strings.Trim(strings.TrimSpace(val), "\"")
		if name == "" {
			continue
		}
		expired := false
		ll := strings.ToLower(line)
		if strings.Contains(ll, "max-age=0") || strings.Contains(ll, "max-age=-") || strings.Contains(ll, "expires=thu, 01-jan-1970") || strings.Contains(ll, "expires=thu, 01 jan 1970") {
			expired = true
		}
		if val == "" || expired || strings.EqualFold(val, "deleted") {
			if _, ok := s.cookies[name]; ok {
				delete(s.cookies, name)
			}
			continue
		}
		if _, ok := s.cookies[name]; !ok {
			s.order = append(s.order, name)
		}
		s.cookies[name] = val
	}
}

func (s *ocSession) cookieHeader() string {
	var parts []string
	for _, n := range s.order {
		if v, ok := s.cookies[n]; ok {
			parts = append(parts, n+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

func (s *ocSession) cookie(name string) string {
	return s.cookies[name]
}

func (s *ocSession) cookiePrefix(prefix string) (string, string) {
	for _, n := range s.order {
		if v, ok := s.cookies[n]; ok && strings.HasPrefix(n, prefix) {
			return n, v
		}
	}
	return "", ""
}

type ocReq struct {
	method  string
	url     *url.URL
	ctype   string
	body    []byte
	headers map[string]string
	follow  int
	stage   string
}

func (s *ocSession) do(r ocReq) (*ocResp, error) {
	stage := r.stage
	if stage == "" {
		stage = StageHandshake
	}
	sctx, cancel := s.p.StageCtx(s.ctx, stage)
	defer cancel()
	u := r.url
	method := r.method
	body := r.body
	ctype := r.ctype
	redirs := 0
	for {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(sctx, method, u.String(), rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", s.ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "identity")
		if ctype != "" && body != nil {
			req.Header.Set("Content-Type", ctype)
		}
		for k, v := range r.headers {
			req.Header.Set(k, v)
		}
		if ck := s.cookieHeader(); ck != "" {
			req.Header.Set("Cookie", ck)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, ocNetErr(err)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil && len(b) == 0 {
			return nil, ocNetErr(err)
		}
		s.setCookies(resp.Header)
		out := &ocResp{Status: resp.StatusCode, Header: resp.Header, Body: b, URL: u, Redirs: redirs}
		loc := out.location()
		if loc == "" || redirs >= r.follow {
			return out, nil
		}
		nu, err := u.Parse(loc)
		if err != nil {
			return out, nil
		}
		redirs++
		if resp.StatusCode != 307 && resp.StatusCode != 308 {
			method, body, ctype = "GET", nil, ""
		}
		u = nu
	}
}

func ocNetErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err
}

func (s *ocSession) get(path string, follow int, stage string) (*ocResp, error) {
	return s.do(ocReq{method: "GET", url: s.resolve(path), follow: follow, stage: stage})
}

func (s *ocSession) postForm(u *url.URL, form string, follow int, stage string, headers map[string]string) (*ocResp, error) {
	return s.do(ocReq{method: "POST", url: u, ctype: "application/x-www-form-urlencoded", body: []byte(form), follow: follow, stage: stage, headers: headers})
}

func (s *ocSession) logout(path string, extra func(*ocReq)) {
	if s.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	r := ocReq{method: "GET", url: s.resolve(path)}
	if extra != nil {
		extra(&r)
	}
	var rd io.Reader
	if r.body != nil {
		rd = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, r.url.String(), rd)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", s.ua)
	if r.ctype != "" {
		req.Header.Set("Content-Type", r.ctype)
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	if ck := s.cookieHeader(); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

func ocFormEncode(kv [][2]string) string {
	var b strings.Builder
	for i, p := range kv {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p[0]))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(p[1]))
	}
	return b.String()
}

func ocShort(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func ocHTTPErr(r *ocResp) error {
	t := ocShort(ocStripTags(string(r.Body)), 80)
	if t == "" {
		return fmt.Errorf("HTTP %d", r.Status)
	}
	return fmt.Errorf("HTTP %d: %s", r.Status, t)
}
