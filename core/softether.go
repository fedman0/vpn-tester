package main

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	seItemInt    = 1
	seItemInt64  = 2
	seItemByte   = 3
	seItemString = 4
	seItemBool   = 5
)

type seItem struct {
	Name string
	Type int
	Str  string
	Num  uint64
	Data []byte
}

type seFolder struct {
	Name    string
	Folders []*seFolder
	Items   []*seItem
}

func (f *seFolder) folder(name string) *seFolder {
	if f == nil {
		return nil
	}
	for _, s := range f.Folders {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

func (f *seFolder) item(name string) *seItem {
	if f == nil {
		return nil
	}
	for i := len(f.Items) - 1; i >= 0; i-- {
		if strings.EqualFold(f.Items[i].Name, name) {
			return f.Items[i]
		}
	}
	return nil
}

func (f *seFolder) str(name string) string {
	it := f.item(name)
	if it == nil {
		return ""
	}
	switch it.Type {
	case seItemString:
		return it.Str
	case seItemInt, seItemInt64, seItemBool:
		return strconv.FormatUint(it.Num, 10)
	}
	return ""
}

func (f *seFolder) num(name string) uint64 {
	it := f.item(name)
	if it == nil {
		return 0
	}
	if it.Type == seItemString {
		n, _ := strconv.ParseUint(strings.TrimSpace(it.Str), 10, 64)
		return n
	}
	return it.Num
}

func (f *seFolder) flag(name string) bool {
	return f.num(name) != 0
}

func (f *seFolder) data(name string) []byte {
	it := f.item(name)
	if it == nil || it.Type != seItemByte {
		return nil
	}
	return it.Data
}

func seUnescape(s string) string {
	if s == "$" {
		return ""
	}
	if !strings.Contains(s, "$") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		i += 2
	}
	return b.String()
}

func seEscape(s string) string {
	if s == "" {
		return "$"
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 31 || c == ' ' || c == '\t' || c == '$' {
			fmt.Fprintf(&b, "$%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func seParseText(text string) *seFolder {
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")
	tmp := &seFolder{Name: "tmp"}
	stack := []*seFolder{tmp}
	for _, raw := range strings.Split(text, "\n") {
		toks := strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' })
		if len(toks) == 0 || strings.HasPrefix(toks[0], "#") || strings.HasPrefix(toks[0], "//") {
			continue
		}
		cur := stack[len(stack)-1]
		kw := strings.ToLower(toks[0])
		switch kw {
		case "declare":
			if len(toks) >= 2 && len(stack) < 64 {
				nf := &seFolder{Name: seUnescape(toks[1])}
				cur.Folders = append(cur.Folders, nf)
				stack = append(stack, nf)
			}
			continue
		case "}":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if len(toks) < 3 {
			continue
		}
		name := seUnescape(toks[1])
		data := toks[2]
		switch kw {
		case "string":
			cur.Items = append(cur.Items, &seItem{Name: name, Type: seItemString, Str: seUnescape(data)})
		case "uint":
			n, _ := strconv.ParseUint(data, 10, 32)
			cur.Items = append(cur.Items, &seItem{Name: name, Type: seItemInt, Num: n})
		case "uint64":
			n, _ := strconv.ParseUint(data, 10, 64)
			cur.Items = append(cur.Items, &seItem{Name: name, Type: seItemInt64, Num: n})
		case "bool":
			v := uint64(0)
			if strings.EqualFold(data, "true") {
				v = 1
			} else if n, err := strconv.ParseUint(data, 10, 64); err == nil && n != 0 {
				v = 1
			}
			cur.Items = append(cur.Items, &seItem{Name: name, Type: seItemBool, Num: v})
		case "byte":
			s := seUnescape(data)
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
			}
			if err == nil {
				cur.Items = append(cur.Items, &seItem{Name: name, Type: seItemByte, Data: b})
			}
		}
	}
	return tmp.folder("root")
}

type seBinReader struct {
	b   []byte
	err error
}

func (r *seBinReader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 4 {
		r.err = errors.New("truncated")
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *seBinReader) u64() uint64 {
	if r.err != nil {
		return 0
	}
	if len(r.b) < 8 {
		r.err = errors.New("truncated")
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *seBinReader) bytesN(n uint32) []byte {
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.b)) {
		r.err = errors.New("truncated")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *seBinReader) name() string {
	n := r.u32()
	if r.err != nil {
		return ""
	}
	if n == 0 {
		r.err = errors.New("bad name")
		return ""
	}
	return string(r.bytesN(n - 1))
}

func seReadFolderBin(r *seBinReader, parent *seFolder, depth int) {
	if depth > 64 {
		r.err = errors.New("too deep")
		return
	}
	f := &seFolder{Name: r.name()}
	parent.Folders = append(parent.Folders, f)
	n := r.u32()
	if n > 1<<20 {
		r.err = errors.New("bad folder count")
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		seReadFolderBin(r, f, depth+1)
	}
	n = r.u32()
	if n > 1<<20 {
		r.err = errors.New("bad item count")
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		it := &seItem{Name: r.name(), Type: int(r.u32())}
		switch it.Type {
		case seItemInt, seItemBool:
			it.Num = uint64(r.u32())
			if it.Type == seItemBool && it.Num != 0 {
				it.Num = 1
			}
		case seItemInt64:
			it.Num = r.u64()
		case seItemByte:
			it.Data = append([]byte(nil), r.bytesN(r.u32())...)
		case seItemString:
			it.Str = string(bytes.TrimRight(r.bytesN(r.u32()), "\x00"))
		default:
			r.err = fmt.Errorf("unknown item type %d", it.Type)
		}
		f.Items = append(f.Items, it)
	}
}

func seParseBin(d []byte) (*seFolder, bool, error) {
	if len(d) < 28 || !bytes.HasPrefix(d, []byte("SEVPN_DB")) {
		return nil, false, errors.New("not a SoftEther binary config")
	}
	sum := seSHA0(d[28:])
	hashOK := bytes.Equal(sum[:], d[8:28])
	r := &seBinReader{b: d[28:]}
	tmp := &seFolder{Name: "tmp"}
	seReadFolderBin(r, tmp, 0)
	root := tmp.folder("root")
	if root == nil {
		if r.err != nil {
			return nil, hashOK, r.err
		}
		return nil, hashOK, errors.New("root folder not found")
	}
	return root, hashOK, nil
}

func seWriteFolder(b *bytes.Buffer, f *seFolder, depth int) {
	ind := strings.Repeat("\t", depth)
	fmt.Fprintf(b, "%sdeclare %s\r\n%s{\r\n", ind, seEscape(f.Name), ind)
	in := ind + "\t"
	for _, it := range f.Items {
		var typ, val string
		switch it.Type {
		case seItemInt:
			typ, val = "uint", strconv.FormatUint(it.Num, 10)
		case seItemInt64:
			typ, val = "uint64", strconv.FormatUint(it.Num, 10)
		case seItemBool:
			typ, val = "bool", "false"
			if it.Num != 0 {
				val = "true"
			}
		case seItemByte:
			typ, val = "byte", base64.StdEncoding.EncodeToString(it.Data)
		case seItemString:
			typ, val = "string", it.Str
		default:
			continue
		}
		fmt.Fprintf(b, "%s%s %s %s\r\n", in, typ, seEscape(it.Name), seEscape(val))
	}
	if len(f.Folders) > 0 && len(f.Items) > 0 {
		b.WriteString("\r\n")
	}
	for _, s := range f.Folders {
		seWriteFolder(b, s, depth+1)
	}
	fmt.Fprintf(b, "%s}\r\n", ind)
}

const seBanner = "\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n# \r\n# You may edit this file when the VPN Server / Client / Bridge program is not running.\r\n# \r\n# In prior to edit this file manually by your text editor,\r\n# shutdown the VPN Server / Client / Bridge background service.\r\n# Otherwise, all changes will be lost.\r\n# \r\n"

const seExportBanner = "# VPN Client VPN Connection Setting File\r\n# \r\n# This file is exported using the VPN Client Manager.\r\n# The contents of this file can be edited using a text editor.\r\n# \r\n# When this file is imported to the Client Connection Manager\r\n#  it can be used immediately.\r\n\r\n"

func seSerialize(root *seFolder, banner string) []byte {
	var b bytes.Buffer
	b.WriteString(banner)
	seWriteFolder(&b, root, 0)
	return b.Bytes()
}

func seLoad(f *vfile) (*seFolder, error) {
	d := f.Data
	if len(d) > 16<<20 {
		return nil, errors.New("file too large")
	}
	if bytes.HasPrefix(d, []byte("SEVPN_DB")) {
		root, hashOK, err := seParseBin(d)
		if err != nil {
			return nil, err
		}
		if !hashOK {
			return root, seErrHashMismatch
		}
		return root, nil
	}
	if !f.IsText() {
		return nil, errors.New("not a SoftEther config")
	}
	t := f.Text()
	lt := strings.ToLower(t)
	if !strings.Contains(lt, "declare") || !strings.Contains(lt, "root") {
		return nil, errors.New("not a SoftEther config")
	}
	root := seParseText(t)
	if root == nil {
		return nil, errors.New("root folder not found")
	}
	return root, nil
}

var seErrHashMismatch = errors.New("binary config checksum mismatch")

func seAccountFolders(root *seFolder) []*seFolder {
	if root == nil {
		return nil
	}
	if root.folder("ClientOption") != nil {
		return []*seFolder{root}
	}
	db := root.folder("AccountDatabase")
	var out []*seFolder
	for _, a := range db.foldersOrNil() {
		if a.folder("ClientOption") != nil {
			out = append(out, a)
		}
	}
	return out
}

func (f *seFolder) foldersOrNil() []*seFolder {
	if f == nil {
		return nil
	}
	return f.Folders
}

func seEncryptedHeader(f *vfile) bool {
	d := f.Data
	if len(d) > 256 {
		d = d[:256]
	}
	return bytes.Contains(d, []byte("VPN Client Config")) && !bytes.Contains(d, []byte("declare"))
}

type SoftEtherDetector struct{}

func (SoftEtherDetector) Detect(f *vfile) int {
	if len(f.Data) == 0 {
		return 0
	}
	if seEncryptedHeader(f) && (!f.IsText() || f.Ext == "vpn" || f.Ext == "config") {
		return 60
	}
	root, err := seLoad(f)
	if root == nil || (err != nil && !errors.Is(err, seErrHashMismatch)) {
		return 0
	}
	if len(seAccountFolders(root)) == 0 {
		return 0
	}
	return 95
}

type seAccount struct {
	Name            string
	Host            string
	Hint            string
	Port            int
	Hub             string
	AuthType        int
	Username        string
	Hashed          []byte
	Plain           string
	HasPlain        bool
	ClientCert      []byte
	ClientKey       []byte
	ProxyType       int
	ProxyHost       string
	ProxyPort       int
	ProxyUser       string
	ProxyPass       string
	ProxyHeader     string
	CheckServerCert bool
	ServerCert      []byte
	UseEncrypt      bool
	UseCompress     bool
	HalfConnection  bool
	DisableQoS      bool
	BridgeMode      bool
	MonitorMode     bool
	MaxConnection   int
}

var seAuthNames = map[int]string{0: "anonymous", 1: "password", 2: "plain-password", 3: "certificate", 4: "smart-card", 5: "openssl-engine"}

func seDecryptPassword(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", true
	}
	var first string
	for i, key := range []string{"EncryptP", "Encr"} {
		c, err := rc4.NewCipher([]byte(key))
		if err != nil {
			continue
		}
		out := make([]byte, len(b))
		c.XORKeyStream(out, b)
		out = bytes.TrimRight(out, "\x00")
		s := string(out)
		if i == 0 {
			first = s
		}
		if sePrintable(s) {
			return s, true
		}
	}
	return first, false
}

func sePrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func seAccountFrom(af *seFolder, c *Config) *seAccount {
	opt := af.folder("ClientOption")
	auth := af.folder("ClientAuth")
	a := &seAccount{
		Name:            opt.str("AccountName"),
		Hub:             opt.str("HubName"),
		Port:            int(opt.num("Port")),
		ProxyType:       int(opt.num("ProxyType")),
		ProxyHost:       strings.TrimSpace(opt.str("ProxyName")),
		ProxyPort:       int(opt.num("ProxyPort")),
		ProxyUser:       opt.str("ProxyUsername"),
		ProxyHeader:     opt.str("CustomHttpHeader"),
		UseEncrypt:      opt.item("UseEncrypt") == nil || opt.flag("UseEncrypt"),
		UseCompress:     opt.flag("UseCompress"),
		HalfConnection:  opt.flag("HalfConnection"),
		DisableQoS:      opt.flag("DisableQoS"),
		BridgeMode:      opt.flag("RequireBridgeRoutingMode"),
		MonitorMode:     opt.flag("RequireMonitorMode"),
		MaxConnection:   int(opt.num("MaxConnection")),
		CheckServerCert: af.flag("CheckServerCert"),
		ServerCert:      af.data("ServerCert"),
		AuthType:        int(auth.num("AuthType")),
		Username:        auth.str("Username"),
	}
	host := strings.TrimSpace(opt.str("Hostname"))
	if i := strings.Index(host, "/"); i >= 0 {
		a.Hint = strings.TrimSpace(host[i+1:])
		host = host[:i]
	}
	if i := strings.Index(host, ","); i >= 0 {
		host = host[:i]
	}
	a.Host = strings.Trim(strings.TrimSpace(host), "[]")
	if _, err := netip.ParseAddr(a.Hint); err != nil {
		a.Hint = ""
	}
	if pw := opt.data("ProxyPassword"); len(pw) > 0 {
		s, ok := seDecryptPassword(pw)
		a.ProxyPass = s
		if !ok {
			c.Warn("proxy password could not be decoded")
		}
	}
	switch a.AuthType {
	case 1:
		h := auth.data("HashedPassword")
		if len(h) == 20 && !bytes.Equal(h, make([]byte, 20)) {
			a.Hashed = h
		}
	case 2:
		if b := auth.data("EncryptedPassword"); b != nil {
			s, ok := seDecryptPassword(b)
			a.Plain, a.HasPlain = s, true
			if !ok {
				c.Warn("stored password could not be decoded")
			}
		} else if auth.item("PlainPassword") != nil {
			a.Plain, a.HasPlain = auth.str("PlainPassword"), true
		}
	case 3:
		a.ClientCert = auth.data("ClientCert")
		a.ClientKey = auth.data("ClientKey")
	}
	return a
}

type SoftEtherParser struct{}

func (SoftEtherParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	if seEncryptedHeader(f) {
		root, err := seLoad(f)
		if root == nil || err != nil {
			return []*Config{unsupportedConfig(f, "SoftEther", "SoftEther", "encrypted SoftEther VPN Client config cannot be read")}, nil
		}
	}
	root, err := seLoad(f)
	if root == nil {
		if err == nil {
			err = errors.New("root folder not found")
		}
		return nil, err
	}
	hashBad := errors.Is(err, seErrHashMismatch)
	accs := seAccountFolders(root)
	if len(accs) == 0 {
		return nil, errors.New("no VPN connection settings found")
	}
	single := root.folder("ClientOption") != nil
	out := make([]*Config, 0, len(accs))
	for _, af := range accs {
		c := newConfig(f, "SoftEther", "SoftEther")
		if hashBad {
			c.Warn("binary config checksum mismatch")
		}
		a := seAccountFrom(af, c)
		c.Name = a.Name
		if c.Name == "" && !single {
			c.Name = af.Name
		}
		if c.Name == "" {
			c.Name = strings.TrimSuffix(f.Name, "."+f.Ext)
		}
		c.Host = a.Host
		if a.Port <= 0 {
			a.Port = 443
			c.Warn("port not set, using 443")
		}
		c.Port = a.Port
		c.Transport = "tcp"
		c.Security = "tls"
		c.Username = a.Username
		if a.HasPlain {
			c.Password = a.Plain
		}
		c.Extra = seExtra(a)
		switch a.AuthType {
		case 0, 1, 2:
		case 3:
			if len(a.ClientCert) == 0 || len(a.ClientKey) == 0 {
				c.Warn("certificate authentication without an embedded certificate/key")
			}
		default:
			c.Warn("%s authentication cannot be tested", seAuthTypeName(a.AuthType))
		}
		if a.ProxyType != 0 {
			c.Warn("connects through %s proxy %s:%d", seProxyName(a.ProxyType), a.ProxyHost, a.ProxyPort)
		}
		acc := &seFolder{Name: "root", Folders: af.Folders, Items: af.Items}
		c.RawConfig = seSerialize(acc, seExportBanner)
		c.Payload = a
		c.Validator = seValidator{}
		c.Tester = SoftEtherConnectivityTester{}
		out = append(out, c)
	}
	if !single {
		for _, c := range out {
			c.Multi = true
		}
	}
	return out, nil
}

func seExtra(a *seAccount) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%x\x00%s\x00%x\x00%x\x00%t\x00%x", a.AuthType, a.Hashed, a.Plain, a.ClientCert, a.ClientKey, a.CheckServerCert, a.ServerCert)
	fmt.Fprintf(h, "\x00%d\x00%s\x00%d\x00%s\x00%s", a.ProxyType, a.ProxyHost, a.ProxyPort, a.ProxyUser, a.ProxyPass)
	return a.Hub + "|" + hex.EncodeToString(h.Sum(nil)[:6])
}

func seAuthTypeName(t int) string {
	if n, ok := seAuthNames[t]; ok {
		return n
	}
	return "auth type " + strconv.Itoa(t)
}

func seProxyName(t int) string {
	switch t {
	case 1:
		return "HTTP"
	case 2:
		return "SOCKS4"
	case 3:
		return "SOCKS5"
	}
	return "unknown"
}

type seValidator struct{}

func (seValidator) Validate(c *Config) error {
	a, _ := c.Payload.(*seAccount)
	if a == nil {
		return errors.New("internal: missing account")
	}
	if a.Host == "" {
		return errors.New("missing server hostname")
	}
	if a.Port <= 0 || a.Port > 65535 {
		return fmt.Errorf("invalid port %d", a.Port)
	}
	if a.Hub == "" {
		return errors.New("missing virtual hub name")
	}
	if a.ProxyType < 0 || a.ProxyType > 3 {
		return fmt.Errorf("unknown proxy type %d", a.ProxyType)
	}
	if a.ProxyType != 0 {
		if a.ProxyHost == "" {
			return errors.New("proxy enabled but proxy host is empty")
		}
		if a.ProxyPort <= 0 || a.ProxyPort > 65535 {
			return fmt.Errorf("invalid proxy port %d", a.ProxyPort)
		}
	}
	return nil
}

type SoftEtherFilter struct{}

func (SoftEtherFilter) Filter(f *vfile, indices []int) ([]byte, error) {
	root, err := seLoad(f)
	if root == nil {
		return f.Data, err
	}
	if root.folder("ClientOption") != nil {
		return f.Data, nil
	}
	accs := seAccountFolders(root)
	keep := map[*seFolder]bool{}
	for _, i := range indices {
		if i >= 0 && i < len(accs) {
			keep[accs[i]] = true
		}
	}
	db := root.folder("AccountDatabase")
	var nf []*seFolder
	for _, a := range db.Folders {
		if a.folder("ClientOption") == nil || keep[a] {
			nf = append(nf, a)
		}
	}
	db.Folders = nf
	return seSerialize(root, seBanner), nil
}

func init() {
	registerFormat(&fileFormat{Name: "SoftEther", Detector: SoftEtherDetector{}, Parser: SoftEtherParser{}, Filter: SoftEtherFilter{}})
}
