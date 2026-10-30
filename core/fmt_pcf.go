package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func init() {
	registerFormat(&fileFormat{Name: "CiscoPCF", Detector: CiscoPcfDetector{}, Parser: CiscoPcfConfigParser{}})
}

type CiscoPcfDetector struct{}

type CiscoPcfConfigParser struct{}

func pcfMain(f *vfile) *iniSection {
	return iniFind(parseINI(f.Text()), "main")
}

func pcfGet(s *iniSection, key string) string {
	if s == nil {
		return ""
	}
	for i := len(s.Keys) - 1; i >= 0; i-- {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(s.Keys[i].Key), "!"), key) {
			return strings.TrimSpace(s.Keys[i].Value)
		}
	}
	return ""
}

func pcfHas(s *iniSection, key string) bool {
	if s == nil {
		return false
	}
	for _, kv := range s.Keys {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(kv.Key), "!"), key) {
			return true
		}
	}
	return false
}

func (CiscoPcfDetector) Detect(f *vfile) int {
	if len(f.Data) == 0 || len(f.Data) > 1<<20 || !f.IsText() {
		return 0
	}
	if !strings.Contains(strings.ToLower(f.Text()), "[main]") {
		return 0
	}
	m := pcfMain(f)
	if m == nil {
		return 0
	}
	score := 0
	if pcfHas(m, "Host") {
		score += 40
	}
	if pcfHas(m, "GroupName") || pcfHas(m, "enc_GroupPwd") || pcfHas(m, "GroupPwd") {
		score += 40
	}
	if pcfHas(m, "AuthType") {
		score += 10
	}
	for _, k := range []string{"enc_UserPassword", "TunnelingMode", "TcpTunnelingPort", "EnableNat", "CertStore", "EnableISPConnect", "SaveUserPassword"} {
		if pcfHas(m, k) {
			score += 2
		}
	}
	if f.Ext == "pcf" {
		score += 15
	}
	if score < 55 || !pcfHas(m, "Host") {
		return 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (CiscoPcfConfigParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	m := pcfMain(f)
	if m == nil {
		return nil, errors.New("missing [main] section")
	}
	host := strings.TrimSpace(pcfGet(m, "Host"))
	if host == "" {
		return nil, errors.New("missing Host")
	}
	var warns []string
	group := pcfGet(m, "GroupName")
	gpw := pcfGet(m, "GroupPwd")
	if enc := pcfGet(m, "enc_GroupPwd"); enc != "" && gpw == "" {
		pw, err := pcfDecrypt(enc)
		if err != nil {
			warns = append(warns, "enc_GroupPwd: "+err.Error())
		} else {
			gpw = pw
		}
	}
	user := pcfGet(m, "Username")
	upw := pcfGet(m, "UserPassword")
	if enc := pcfGet(m, "enc_UserPassword"); enc != "" && upw == "" {
		pw, err := pcfDecrypt(enc)
		if err != nil {
			warns = append(warns, "enc_UserPassword: "+err.Error())
		} else {
			upw = pw
		}
	}
	name := pcfGet(m, "Description")
	if name == "" {
		name = strings.TrimSuffix(f.Name, "."+f.Ext)
	}
	authType := 1
	if v := pcfGet(m, "AuthType"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			authType = n
		}
	}
	spec := &ikeSpec{
		Name: name, Kind: "cisco", Version: 1, Host: host, Port: 500,
		GroupName: group, LocalID: group, PSK: gpw, Username: user, Password: upw,
		Aggressive: true, Auth: "xauth-psk",
	}
	var certFile *vfile
	unsupported := ""
	switch authType {
	case 0, 1:
		if group == "" {
			return []*Config{invalidPCF(f, "group authentication without GroupName")}, nil
		}
	case 3:
		spec.Auth, spec.Aggressive, spec.LocalID = "xauth-rsa", false, ""
		certFile = pcfFindCert(f, fs, m, spec)
		if certFile == nil {
			warns = append(warns, fmt.Sprintf("client certificate %q is kept in the Cisco/Windows certificate store, not in this folder", pcfGet(m, "CertName")))
		}
	case 5:
		spec.Auth = "hybrid"
		if group == "" {
			return []*Config{invalidPCF(f, "mutual group authentication without GroupName")}, nil
		}
	default:
		unsupported = fmt.Sprintf("Cisco AuthType %d is not supported", authType)
	}
	if g := pcfGet(m, "DHGroup"); g != "" {
		if n, err := strconv.Atoi(g); err == nil && ike1GroupSupported(uint16(n)) {
			spec.IKEProposals = []string{"aes256-aes128-3des-sha1-md5-sha256-" + ike1GroupName(uint16(n))}
		}
	}
	c := ikeConfig(f, fs, spec)
	c.Format = "CiscoPCF"
	c.RawConfig = f.Data
	if certFile != nil {
		c.AddDep(fs, certFile, true)
	}
	for _, w := range warns {
		c.Warn("%s", w)
	}
	if pcfGet(m, "EnableBackup") == "1" {
		if b := pcfGet(m, "BackupServer"); b != "" {
			c.Warn("backup servers not tested: %s", b)
		}
	}
	if pcfGet(m, "TunnelingMode") == "1" {
		port := pcfGet(m, "TcpTunnelingPort")
		if port == "" {
			port = "10000"
		}
		unsupported = "IPsec over TCP (Cisco cTCP, port " + port + ") is not supported"
	}
	if unsupported != "" && c.Status == StateParsed {
		c.Status = StateUnsupported
		c.Error = unsupported
		c.Tester = nil
	}
	return []*Config{c}, nil
}

func invalidPCF(f *vfile, msg string) *Config {
	c := invalidConfig(f, "CiscoPCF", errors.New(msg))
	c.Protocol = "Cisco IPsec"
	return c
}

func pcfFindCert(f *vfile, fs *vfs, m *iniSection, spec *ikeSpec) *vfile {
	name := pcfGet(m, "CertName")
	if name == "" || fs == nil {
		return nil
	}
	var cands []string
	for _, base := range []string{name, pcfGet(m, "CertPath") + "/" + name} {
		cands = append(cands, base, base+".p12", base+".pfx", base+".pem", base+".crt")
	}
	for _, ref := range cands {
		g := fs.Resolve(f, ref)
		if g == nil || g.Root() == f.Root() {
			continue
		}
		data := g.Data
		if g.Ext == "p12" || g.Ext == "pfx" || !bytes.Contains(data, []byte("-----BEGIN")) {
			cert, key, cas, err := decodePKCS12(data, "")
			if err != nil {
				continue
			}
			spec.ClientCert, spec.ClientKey, spec.CACerts = cert, key, cas
			return g
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) && bytes.Contains(data, []byte("CERTIFICATE")) {
			spec.ClientCert, spec.ClientKey = data, data
			return g
		}
	}
	return nil
}

func pcfDeriveKey(h1 []byte) []byte {
	ht := append([]byte(nil), h1[:20]...)
	ht[19]++
	h2 := sha1.Sum(ht)
	ht[19] += 2
	h3 := sha1.Sum(ht)
	return append(h2[:], h3[:4]...)
}

func pcfDecrypt(s string) (string, error) {
	ct, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", errors.New("not a hex string")
	}
	if len(ct) < 48 || (len(ct)-40)%8 != 0 {
		return "", errors.New("invalid length")
	}
	h1, h4, enc := ct[:20], ct[20:40], ct[40:]
	if sum := sha1.Sum(enc); !bytes.Equal(sum[:], h4) {
		return "", errors.New("checksum mismatch (corrupted value)")
	}
	block, err := des.NewTripleDESCipher(pcfDeriveKey(h1))
	if err != nil {
		return "", err
	}
	out := make([]byte, len(enc))
	cipher.NewCBCDecrypter(block, h1[:8]).CryptBlocks(out, enc)
	if pad := int(out[len(out)-1]); pad >= 1 && pad <= 8 && pad <= len(out) {
		out = out[:len(out)-pad]
	}
	if i := bytes.IndexByte(out, 0); i >= 0 {
		out = out[:i]
	}
	return string(out), nil
}
