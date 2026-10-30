package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type vfile struct {
	Path   string
	Name   string
	Ext    string
	Data   []byte
	Parent *vfile
}

func newVFile(p string, data []byte) *vfile {
	p = strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "/")
	name := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		name = p[i+1:]
	}
	return &vfile{Path: p, Name: name, Ext: extOf(name), Data: data}
}

func extOf(name string) string {
	if i := strings.LastIndex(name, "."); i > 0 {
		return strings.ToLower(name[i+1:])
	}
	return ""
}

func (f *vfile) Child(tag, name string, data []byte) *vfile {
	return &vfile{Path: f.Path + "#" + tag, Name: name, Ext: extOf(name), Data: data, Parent: f}
}

func (f *vfile) Root() *vfile {
	for f.Parent != nil {
		f = f.Parent
	}
	return f
}

func (f *vfile) Dir() string {
	p := f.Root().Path
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

func (f *vfile) Text() string {
	b := bytes.TrimPrefix(f.Data, []byte{0xEF, 0xBB, 0xBF})
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func (f *vfile) IsText() bool {
	b := f.Data
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	if utf8.Valid(b) {
		return true
	}
	bad := 0
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			bad++
		}
		b = b[n:]
	}
	return bad < 8
}

type vfs struct {
	mu     sync.Mutex
	byPath map[string]*vfile
	byName map[string][]*vfile
	files  []*vfile
	used   map[string]bool
}

func newVFS() *vfs {
	return &vfs{byPath: map[string]*vfile{}, byName: map[string][]*vfile{}, used: map[string]bool{}}
}

func (fs *vfs) add(f *vfile) {
	if _, ok := fs.byPath[f.Path]; ok {
		return
	}
	fs.byPath[f.Path] = f
	k := strings.ToLower(f.Name)
	fs.byName[k] = append(fs.byName[k], f)
	fs.files = append(fs.files, f)
}

func (fs *vfs) Resolve(from *vfile, ref string) *vfile {
	ref = strings.TrimSpace(strings.Trim(strings.TrimSpace(ref), "\"'"))
	if ref == "" || fs == nil {
		return nil
	}
	ref = strings.ReplaceAll(ref, "\\", "/")
	ref = strings.TrimPrefix(ref, "file://")
	abs := strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "~") || (len(ref) > 1 && ref[1] == ':')
	dir := from.Dir()
	if !abs {
		p := path.Clean(path.Join(dir, ref))
		if g := fs.byPath[p]; g != nil {
			return g
		}
		lp := strings.ToLower(p)
		for k, g := range fs.byPath {
			if strings.ToLower(k) == lp {
				return g
			}
		}
	}
	cands := fs.byName[strings.ToLower(path.Base(ref))]
	for _, g := range cands {
		if g.Dir() == dir {
			return g
		}
	}
	if len(cands) == 1 {
		return cands[0]
	}
	for _, g := range cands {
		if strings.HasPrefix(g.Dir(), dir) || strings.HasPrefix(dir, g.Dir()) {
			return g
		}
	}
	return nil
}

func (fs *vfs) markUsed(p string) {
	fs.mu.Lock()
	fs.used[p] = true
	fs.mu.Unlock()
}

const (
	StateUnknown           = "Unknown"
	StateParsed            = "Parsed"
	StateInvalid           = "Invalid"
	StateDNSFailed         = "DNSFailed"
	StateHostUnreachable   = "HostUnreachable"
	StatePortUnreachable   = "PortUnreachable"
	StateHandshakeFailed   = "HandshakeFailed"
	StateAuthFailed        = "AuthenticationFailed"
	StateConnectable       = "Connectable"
	StateDataPlaneVerified = "DataPlaneVerified"
	StateUnsupported       = "Unsupported"
)

const (
	StageParse     = "parse"
	StageDNS       = "dns"
	StageTransport = "transport"
	StageHandshake = "handshake"
	StageAuth      = "authentication"
	StageDataPlane = "dataPlane"
)

type Config struct {
	ID           int
	File         string
	Index        int
	Multi        bool
	Format       string
	Protocol     string
	Name         string
	Host         string
	Port         int
	Transport    string
	Security     string
	SNI          string
	Username     string
	Password     string
	UUID         string
	PublicKey    string
	PrivateKey   string
	PSK          string
	Extra        string
	UDP          bool
	Certificates []string
	Dependencies []string
	RawConfig    []byte
	Warnings     []string
	Status       string
	Error        string
	Fingerprint  string
	DuplicateOf  int
	Tester       ConnectivityTester
	Validator    ConfigValidator
	Payload      any
	source       *vfile
}

func (c *Config) AddDep(fs *vfs, f *vfile, cert bool) {
	if f == nil {
		return
	}
	r := f.Root()
	for _, d := range c.Dependencies {
		if d == r.Path {
			return
		}
	}
	if r.Path == c.File {
		return
	}
	c.Dependencies = append(c.Dependencies, r.Path)
	if cert {
		c.Certificates = append(c.Certificates, r.Path)
	}
	if fs != nil {
		fs.markUsed(r.Path)
	}
}

func (c *Config) Warn(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}

func newConfig(f *vfile, format, protocol string) *Config {
	return &Config{File: f.Root().Path, Format: format, Protocol: protocol, Status: StateParsed, source: f}
}

func invalidConfig(f *vfile, format string, err error) *Config {
	c := newConfig(f, format, "")
	c.Status = StateInvalid
	if err != nil {
		c.Error = shortErr(err)
	}
	return c
}

func unsupportedConfig(f *vfile, format, protocol, reason string) *Config {
	c := newConfig(f, format, protocol)
	c.Status = StateUnsupported
	c.Error = reason
	return c
}

type ConfigDetector interface {
	Detect(f *vfile) int
}

type ConfigParser interface {
	Parse(f *vfile, fs *vfs) ([]*Config, error)
}

type ConfigValidator interface {
	Validate(c *Config) error
}

type ConnectivityTester interface {
	Test(ctx context.Context, c *Config, p *probe)
}

type ConfigFilter interface {
	Filter(f *vfile, indices []int) ([]byte, error)
}

type fileFormat struct {
	Name     string
	Detector ConfigDetector
	Parser   ConfigParser
	Filter   ConfigFilter
}

var (
	formatsMu sync.Mutex
	formats   = map[string]*fileFormat{}
	formatSeq []string
)

func registerFormat(ff *fileFormat) {
	formatsMu.Lock()
	defer formatsMu.Unlock()
	if _, ok := formats[ff.Name]; !ok {
		formatSeq = append(formatSeq, ff.Name)
	}
	formats[ff.Name] = ff
}

func lookupFormat(name string) *fileFormat {
	formatsMu.Lock()
	defer formatsMu.Unlock()
	return formats[name]
}

func parseAs(name string, f *vfile, fs *vfs) ([]*Config, error) {
	ff := lookupFormat(name)
	if ff == nil || ff.Parser == nil {
		return []*Config{unsupportedConfig(f, name, "", name+" support is not available")}, nil
	}
	cs, err := ff.Parser.Parse(f, fs)
	if err != nil {
		return []*Config{invalidConfig(f, name, err)}, nil
	}
	return cs, nil
}

func detectFormat(f *vfile) *fileFormat {
	formatsMu.Lock()
	names := append([]string(nil), formatSeq...)
	formatsMu.Unlock()
	var best *fileFormat
	bestScore := 0
	for _, n := range names {
		ff := lookupFormat(n)
		if ff == nil || ff.Detector == nil {
			continue
		}
		s := safeDetect(ff.Detector, f)
		if s > bestScore {
			best, bestScore = ff, s
		}
	}
	return best
}

func safeDetect(d ConfigDetector, f *vfile) (s int) {
	defer func() {
		if recover() != nil {
			s = 0
		}
	}()
	return d.Detect(f)
}

type ikeSpec struct {
	Name         string
	Kind         string
	Version      int
	Host         string
	Port         int
	RemoteID     string
	LocalID      string
	Auth         string
	PSK          string
	Username     string
	Password     string
	GroupName    string
	Aggressive   bool
	ClientCert   []byte
	ClientKey    []byte
	CACerts      [][]byte
	IKEProposals []string
	ESPProposals []string
	L2TP         bool
}

type ocSpec struct {
	Name          string
	Protocol      string
	Host          string
	Port          int
	Path          string
	Username      string
	Password      string
	Group         string
	ServerCertPin string
	CACert        []byte
	ClientCert    []byte
	ClientKey     []byte
}

type sstpSpec struct {
	Name     string
	Host     string
	Port     int
	Username string
	Password string
	Domain   string
	CACert   []byte
}

type pptpSpec struct {
	Name     string
	Host     string
	Username string
	Password string
	Domain   string
}

var (
	buildIKEConfig   func(f *vfile, fs *vfs, s *ikeSpec) *Config
	buildIKEv1Config func(f *vfile, fs *vfs, s *ikeSpec) *Config
	buildOCConfig    func(f *vfile, fs *vfs, s *ocSpec) *Config
	buildSSTPConfig  func(f *vfile, fs *vfs, s *sstpSpec) *Config
	buildPPTPConfig  func(f *vfile, fs *vfs, s *pptpSpec) *Config
)

func ikeConfig(f *vfile, fs *vfs, s *ikeSpec) *Config {
	if s.Version == 1 {
		if buildIKEv1Config == nil {
			return unsupportedConfig(f, "IPsec", "IKEv1", "IKEv1 support is not available")
		}
		return buildIKEv1Config(f, fs, s)
	}
	if buildIKEConfig == nil {
		return unsupportedConfig(f, "IPsec", "IKEv2", "IKE support is not available")
	}
	return buildIKEConfig(f, fs, s)
}

func ocConfig(f *vfile, fs *vfs, s *ocSpec) *Config {
	if buildOCConfig == nil {
		return unsupportedConfig(f, "OpenConnect", s.Protocol, "OpenConnect support is not available")
	}
	return buildOCConfig(f, fs, s)
}

func sstpConfig(f *vfile, fs *vfs, s *sstpSpec) *Config {
	if buildSSTPConfig == nil {
		return unsupportedConfig(f, "SSTP", "SSTP", "SSTP support is not available")
	}
	return buildSSTPConfig(f, fs, s)
}

func pptpConfig(f *vfile, fs *vfs, s *pptpSpec) *Config {
	if buildPPTPConfig == nil {
		return unsupportedConfig(f, "PPTP", "PPTP", "PPTP support is not available")
	}
	return buildPPTPConfig(f, fs, s)
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return "••••••"
}

func maskID(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= 8 {
		return "••••"
	}
	return string(r[:4]) + "…" + string(r[len(r)-4:])
}

func shortKey(s string) string {
	r := []rune(s)
	if len(r) <= 12 {
		return s
	}
	return string(r[:6]) + "…" + string(r[len(r)-4:])
}

func (c *Config) computeFingerprint() {
	if c.Status != StateParsed || c.Host == "" {
		return
	}
	user := c.UUID
	if user == "" {
		user = c.Username
	}
	if user == "" {
		user = c.Password
	}
	parts := []string{
		strings.ToLower(c.Protocol),
		strings.ToLower(strings.Trim(c.Host, "[]")),
		fmt.Sprint(c.Port),
		user,
		c.PublicKey,
		strings.ToLower(c.SNI),
		strings.ToLower(c.Transport),
		c.Extra,
	}
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	c.Fingerprint = hex.EncodeToString(h[:8])
}

type configView struct {
	Ev           string   `json:"ev"`
	ID           int      `json:"id"`
	File         string   `json:"file"`
	Index        int      `json:"index"`
	Multi        bool     `json:"multi,omitempty"`
	Filterable   bool     `json:"filterable,omitempty"`
	Format       string   `json:"format"`
	Protocol     string   `json:"protocol,omitempty"`
	Name         string   `json:"name,omitempty"`
	Host         string   `json:"host,omitempty"`
	Port         int      `json:"port,omitempty"`
	Transport    string   `json:"transport,omitempty"`
	Security     string   `json:"security,omitempty"`
	SNI          string   `json:"sni,omitempty"`
	Username     string   `json:"username,omitempty"`
	Password     string   `json:"password,omitempty"`
	UUID         string   `json:"uuid,omitempty"`
	PublicKey    string   `json:"publicKey,omitempty"`
	PrivateKey   string   `json:"privateKey,omitempty"`
	PSK          string   `json:"psk,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	DuplicateOf  int      `json:"duplicateOf,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
}

func (c *Config) view() configView {
	filterable := false
	if c.Multi {
		if ff := lookupFormat(c.Format); ff != nil && ff.Filter != nil {
			filterable = true
		}
	}
	return configView{
		Ev: "config", ID: c.ID, File: c.File, Index: c.Index, Multi: c.Multi, Filterable: filterable,
		Format: c.Format, Protocol: c.Protocol, Name: c.Name, Host: c.Host, Port: c.Port,
		Transport: c.Transport, Security: c.Security, SNI: c.SNI, Username: c.Username,
		Password: maskSecret(c.Password), UUID: maskID(c.UUID), PublicKey: shortKey(c.PublicKey),
		PrivateKey: maskSecret(c.PrivateKey), PSK: maskSecret(c.PSK),
		Certificates: c.Certificates, Dependencies: c.Dependencies, Fingerprint: c.Fingerprint,
		DuplicateOf: c.DuplicateOf, Warnings: c.Warnings, Status: c.Status, Error: c.Error,
	}
}

type scanTimeouts struct {
	DNS       int `json:"dns"`
	Connect   int `json:"connect"`
	Handshake int `json:"handshake"`
	Auth      int `json:"auth"`
	Overall   int `json:"overall"`
}

type scanOptions struct {
	URLs        []string     `json:"urls"`
	DNS         []string     `json:"dns"`
	Concurrency int          `json:"concurrency"`
	Timeouts    scanTimeouts `json:"timeouts"`
	DataProbe   *bool        `json:"dataProbe"`
}

func (o *scanOptions) normalize() {
	if len(o.URLs) == 0 {
		o.URLs = defaultURLs
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 10
	}
	if o.Concurrency > 256 {
		o.Concurrency = 256
	}
	t := &o.Timeouts
	if t.Overall <= 0 {
		t.Overall = 15000
	}
	if t.DNS <= 0 {
		t.DNS = 4000
	}
	if t.Connect <= 0 {
		t.Connect = 5000
	}
	if t.Handshake <= 0 {
		t.Handshake = 8000
	}
	if t.Auth <= 0 {
		t.Auth = 10000
	}
	if o.DataProbe == nil {
		v := true
		o.DataProbe = &v
	}
}

type fileMsg struct {
	Path string `json:"path"`
	Data string `json:"data"`
	End  bool   `json:"end"`
}

type summaryView struct {
	Ev           string `json:"ev"`
	Files        int    `json:"files"`
	Configs      int    `json:"configs"`
	Dependencies int    `json:"dependencies"`
	Ignored      int    `json:"ignored"`
}

type jsonEmitter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func (e *jsonEmitter) emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.w.Write(b)
	e.w.WriteByte('\n')
	e.w.Flush()
	e.mu.Unlock()
}

var encryptedFormats = map[string]string{
	"npvt": "NapsternetV", "npvtsub": "NapsternetV", "hc": "HTTP Custom", "ehi": "HTTP Injector",
	"dark": "DarkTunnel", "tnl": "TLS Tunnel", "nm": "NetMod", "sks": "SocksHttp", "ziv": "ZIVPN",
	"hat": "HA Tunnel", "acl": "AnyConnect ACL", "vpnlite": "VPN Lite", "jez": "Jez Tunnel",
}

var configLikeExt = map[string]bool{
	"ovpn": true, "conf": true, "vpn": true, "sswan": true, "mobileconfig": true, "nmconnection": true,
	"pcf": true, "wg": true, "awg": true, "secrets": true, "swanctl": true,
}

var depExt = map[string]bool{
	"crt": true, "cer": true, "pem": true, "key": true, "der": true, "p12": true, "pfx": true,
	"pkcs12": true, "pkcs8": true, "p8": true, "csr": false,
}

func isDependencyFile(f *vfile) bool {
	if depExt[f.Ext] {
		return true
	}
	t := f.Data
	if len(t) > 4096 {
		t = t[:4096]
	}
	return bytes.Contains(t, []byte("-----BEGIN ")) && !bytes.Contains(t, []byte("\nremote ")) && !bytes.Contains(t, []byte("[Interface]"))
}

func parseFile(f *vfile, fs *vfs) ([]*Config, bool) {
	ff := detectFormat(f)
	if ff == nil {
		if app, ok := encryptedFormats[f.Ext]; ok {
			return []*Config{unsupportedConfig(f, app, app, "encrypted "+app+" config cannot be read")}, true
		}
		if isDependencyFile(f) {
			return nil, false
		}
		if configLikeExt[f.Ext] {
			return []*Config{unsupportedConfig(f, "Unknown", "", "unrecognized config format")}, true
		}
		return nil, false
	}
	var cs []*Config
	func() {
		defer func() {
			if p := recover(); p != nil {
				cs = []*Config{invalidConfig(f, ff.Name, fmt.Errorf("parser crashed: %v", p))}
			}
		}()
		var err error
		cs, err = ff.Parser.Parse(f, fs)
		if err != nil {
			cs = []*Config{invalidConfig(f, ff.Name, err)}
		}
	}()
	if len(cs) == 0 {
		cs = []*Config{invalidConfig(f, ff.Name, errors.New("no usable config found"))}
	}
	return cs, true
}

func validateConfig(c *Config) {
	if c.Status != StateParsed {
		return
	}
	if c.Validator != nil {
		if err := c.Validator.Validate(c); err != nil {
			c.Status = StateInvalid
			c.Error = shortErr(err)
			return
		}
	}
	if c.Tester == nil {
		c.Status = StateUnsupported
		if c.Error == "" {
			c.Error = "no connectivity tester for " + c.Protocol
		}
	}
}

type scanResult struct {
	configs []*Config
	files   int
	deps    int
	ignored int
}

func discover(fs *vfs) *scanResult {
	res := &scanResult{files: len(fs.files)}
	type item struct {
		f  *vfile
		cs []*Config
		ok bool
	}
	items := make([]item, len(fs.files))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, f := range fs.files {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, f *vfile) {
			defer wg.Done()
			defer func() { <-sem }()
			cs, ok := parseFile(f, fs)
			items[i] = item{f, cs, ok}
		}(i, f)
	}
	wg.Wait()
	id := 0
	for _, it := range items {
		if !it.ok {
			continue
		}
		multi := len(it.cs) > 1
		for idx, c := range it.cs {
			id++
			c.ID = id
			if c.File == "" {
				c.File = it.f.Path
			}
			if c.Format == "" {
				c.Format = "Unknown"
			}
			c.Index = idx
			c.Multi = c.Multi || multi
			validateConfig(c)
			c.computeFingerprint()
			res.configs = append(res.configs, c)
		}
	}
	first := map[string]int{}
	for _, c := range res.configs {
		if c.Fingerprint == "" {
			continue
		}
		if p, ok := first[c.Fingerprint]; ok {
			c.DuplicateOf = p
		} else {
			first[c.Fingerprint] = c.ID
		}
	}
	for _, f := range fs.files {
		if fs.used[f.Path] {
			res.deps++
			continue
		}
	}
	configFiles := map[string]bool{}
	for _, c := range res.configs {
		configFiles[c.File] = true
	}
	for _, f := range fs.files {
		if !configFiles[f.Path] && !fs.used[f.Path] {
			res.ignored++
		}
	}
	return res
}

func runScan(opt *scanOptions, fs *vfs, emit func(any)) {
	res := discover(fs)
	for _, c := range res.configs {
		emit(c.view())
	}
	emit(summaryView{Ev: "summary", Files: res.files, Configs: len(res.configs), Dependencies: res.deps, Ignored: res.ignored})

	byID := map[int]*Config{}
	dups := map[int][]*Config{}
	var queue []*Config
	for _, c := range res.configs {
		byID[c.ID] = c
		if c.Status != StateParsed {
			continue
		}
		if c.DuplicateOf != 0 {
			dups[c.DuplicateOf] = append(dups[c.DuplicateOf], c)
			continue
		}
		queue = append(queue, c)
	}
	jobs := make(chan *Config)
	var wg sync.WaitGroup
	for i := 0; i < opt.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				emit(map[string]any{"ev": "testing", "id": c.ID})
				for _, d := range dups[c.ID] {
					emit(map[string]any{"ev": "testing", "id": d.ID})
				}
				r := testConfig(opt, c)
				emit(r)
				for _, d := range dups[c.ID] {
					cp := *r
					cp.ID = d.ID
					cp.Note = strings.TrimSpace("duplicate of #" + fmt.Sprint(c.ID) + ". " + cp.Note)
					emit(&cp)
				}
			}
		}()
	}
	for _, c := range queue {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	emit(map[string]any{"ev": "done"})
}

func testConfig(opt *scanOptions, c *Config) (r *TestResult) {
	p := newProbe(opt, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opt.Timeouts.Overall)*time.Millisecond)
	defer cancel()
	p.ctx = ctx
	defer func() {
		if rec := recover(); rec != nil {
			p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("internal error: %v", rec))
		}
		r = p.finish(ctx)
	}()
	p.Pass(StageParse)
	c.Tester.Test(ctx, c, p)
	return
}

func scanMain() {
	out := protocolOutput()
	em := &jsonEmitter{w: bufio.NewWriterSize(out, 64<<10)}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	if !sc.Scan() {
		em.emit(map[string]any{"ev": "done", "error": "missing options"})
		return
	}
	opt := &scanOptions{}
	if err := json.Unmarshal(sc.Bytes(), opt); err != nil {
		em.emit(map[string]any{"ev": "done", "error": "bad options: " + err.Error()})
		return
	}
	opt.normalize()
	initRuntime(opt.DNS)
	fs := newVFS()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m fileMsg
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if m.End {
			break
		}
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil || m.Path == "" {
			continue
		}
		fs.add(newVFile(m.Path, data))
	}
	runScan(opt, fs, em.emit)
	os.Exit(0)
}

type exportMsg struct {
	Path    string `json:"path"`
	Format  string `json:"format"`
	Data    string `json:"data"`
	Indices []int  `json:"indices"`
}

func exportMain() {
	out := protocolOutput()
	em := &jsonEmitter{w: bufio.NewWriterSize(out, 64<<10)}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m exportMsg
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			em.emit(map[string]any{"path": m.Path, "ok": false, "error": "bad data"})
			continue
		}
		b, err := filterFile(m.Format, newVFile(m.Path, data), m.Indices)
		if err != nil {
			em.emit(map[string]any{"path": m.Path, "ok": false, "error": shortErr(err)})
			continue
		}
		em.emit(map[string]any{"path": m.Path, "ok": true, "data": base64.StdEncoding.EncodeToString(b)})
	}
	em.emit(map[string]any{"done": true})
	os.Exit(0)
}

func filterFile(format string, f *vfile, indices []int) (b []byte, err error) {
	ff := lookupFormat(format)
	if ff == nil || ff.Filter == nil {
		return f.Data, nil
	}
	defer func() {
		if p := recover(); p != nil {
			b, err = f.Data, nil
		}
	}()
	sort.Ints(indices)
	return ff.Filter.Filter(f, indices)
}
