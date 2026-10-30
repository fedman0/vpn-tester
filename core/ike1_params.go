package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type ike1Params struct {
	spec       ikeSpec
	aggressive bool
	auth       uint16
	xauth      bool
	sign       bool
	hybrid     bool
	cisco      bool
	l2tp       bool
	idType     byte
	idData     []byte
	custom     []ike1Transform
	certDER    []byte
	signer     *rsa.PrivateKey
	caPool     *x509.CertPool
	caDNs      [][]byte
	credNote   string
}

type ike1Suite struct {
	enc, kl, hash, group uint16
}

var ike1MMSuites = [][]ike1Suite{
	{
		{ike1EncAES, 256, ike1HashSHA2, 14}, {ike1EncAES, 128, ike1HashSHA2, 14}, {ike1EncAES, 256, ike1HashSHA1, 14}, {ike1EncAES, 128, ike1HashSHA1, 14},
		{ike1EncAES, 256, ike1HashSHA1, 2}, {ike1EncAES, 128, ike1HashSHA1, 2}, {ike1Enc3DES, 0, ike1HashSHA1, 2}, {ike1Enc3DES, 0, ike1HashMD5, 2},
		{ike1EncAES, 256, ike1HashSHA2, 2}, {ike1EncAES, 128, ike1HashSHA2, 2},
		{ike1EncAES, 256, ike1HashSHA1, 5}, {ike1EncAES, 128, ike1HashSHA1, 5}, {ike1Enc3DES, 0, ike1HashSHA1, 5},
		{ike1EncAES, 256, ike1HashSHA2, 19}, {ike1EncAES, 128, ike1HashSHA2, 19}, {ike1EncAES, 256, ike1HashSHA3, 20},
		{ike1Enc3DES, 0, ike1HashSHA1, 14}, {ike1EncAES, 256, ike1HashSHA5, 14}, {ike1EncAES, 128, ike1HashMD5, 2}, {ike1EncAES, 256, ike1HashSHA2, 5},
	},
	{
		{ike1EncAES, 256, ike1HashSHA2, 15}, {ike1EncAES, 256, ike1HashSHA2, 16}, {ike1EncAES, 256, ike1HashSHA5, 16}, {ike1EncAES, 256, ike1HashSHA3, 14},
		{ike1EncAES, 256, ike1HashSHA3, 19}, {ike1EncAES, 128, ike1HashSHA1, 19}, {ike1EncAES, 256, ike1HashSHA1, 19}, {ike1EncAES, 256, ike1HashSHA1, 20},
		{ike1EncAES, 256, ike1HashSHA5, 20}, {ike1EncAES, 256, ike1HashSHA5, 21}, {ike1EncAES, 128, ike1HashSHA2, 20}, {ike1EncAES, 256, ike1HashSHA1, 15},
		{ike1EncAES, 256, ike1HashSHA1, 16}, {ike1EncAES, 128, ike1HashSHA1, 15}, {ike1EncAES, 192, ike1HashSHA1, 2}, {ike1EncAES, 192, ike1HashSHA2, 14},
		{ike1Enc3DES, 0, ike1HashMD5, 5}, {ike1Enc3DES, 0, ike1HashSHA1, 1}, {ike1Enc3DES, 0, ike1HashMD5, 1}, {ike1EncAES, 128, ike1HashMD5, 5},
	},
	{
		{ike1Enc3DES, 0, ike1HashSHA2, 14}, {ike1Enc3DES, 0, ike1HashSHA2, 2}, {ike1EncAES, 256, ike1HashMD5, 2}, {ike1EncAES, 256, ike1HashMD5, 14},
		{ike1Enc3DES, 0, ike1HashSHA1, 15}, {ike1Enc3DES, 0, ike1HashSHA1, 16}, {ike1EncAES, 128, ike1HashSHA1, 1}, {ike1EncAES, 256, ike1HashSHA1, 1},
		{ike1EncAES, 256, ike1HashSHA5, 15}, {ike1EncAES, 256, ike1HashSHA3, 15}, {ike1Enc3DES, 0, ike1HashMD5, 14}, {ike1EncAES, 128, ike1HashMD5, 14},
		{ike1EncAES, 128, ike1HashSHA5, 14}, {ike1EncAES, 128, ike1HashSHA3, 14}, {ike1EncAES, 256, ike1HashSHA2, 21}, {ike1EncAES, 128, ike1HashSHA2, 15},
		{ike1EncAES, 192, ike1HashSHA1, 5}, {ike1EncAES, 192, ike1HashSHA1, 14}, {ike1EncAES, 256, ike1HashSHA2, 31}, {ike1EncAES, 128, ike1HashSHA2, 31},
	},
}

var ike1AMPairs = []ike1Suite{
	{ike1EncAES, 256, ike1HashSHA1, 0}, {ike1EncAES, 128, ike1HashSHA1, 0}, {ike1Enc3DES, 0, ike1HashSHA1, 0}, {ike1Enc3DES, 0, ike1HashMD5, 0},
	{ike1EncAES, 256, ike1HashSHA2, 0}, {ike1EncAES, 128, ike1HashSHA2, 0}, {ike1EncAES, 256, ike1HashMD5, 0}, {ike1EncAES, 128, ike1HashMD5, 0},
	{ike1EncAES, 256, ike1HashSHA3, 0}, {ike1EncAES, 256, ike1HashSHA5, 0}, {ike1EncAES, 192, ike1HashSHA1, 0}, {ike1Enc3DES, 0, ike1HashSHA2, 0},
}

var ike1AMGroups = []uint16{2, 14, 5, 19, 20, 1, 15, 16}

const ike1ChunkMax = 20

func (prm *ike1Params) mmProposals() [][]ike1Transform {
	var out [][]ike1Transform
	seen := map[ike1Transform]bool{}
	norm := func(t ike1Transform) ike1Transform {
		t.Auth = prm.auth
		t.Life = 0
		if t.Enc == ike1EncAES && t.KeyLen == 0 {
			t.KeyLen = 128
		}
		if t.Enc != ike1EncAES {
			t.KeyLen = 0
		}
		return t
	}
	var cur []ike1Transform
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
	}
	add := func(t ike1Transform) {
		t = norm(t)
		if seen[t] || !ike1GroupSupported(t.Group) || ike1HashFn(t.Hash) == nil || ike1EncKeyBytes(t.Enc, t.KeyLen) == 0 {
			return
		}
		seen[t] = true
		cur = append(cur, t)
		if len(cur) >= ike1ChunkMax {
			flush()
		}
	}
	for _, t := range prm.custom {
		add(t)
	}
	flush()
	for _, chunk := range ike1MMSuites {
		for _, su := range chunk {
			add(ike1Transform{Enc: su.enc, KeyLen: su.kl, Hash: su.hash, Group: su.group})
		}
		flush()
	}
	return out
}

func (prm *ike1Params) amGroups() []uint16 {
	var out []uint16
	seen := map[uint16]bool{}
	for _, t := range prm.custom {
		if !seen[t.Group] && ike1GroupSupported(t.Group) {
			seen[t.Group] = true
			out = append(out, t.Group)
		}
	}
	for _, g := range ike1AMGroups {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

func (prm *ike1Params) amTransforms(group uint16) []ike1Transform {
	var out []ike1Transform
	seen := map[ike1Transform]bool{}
	add := func(t ike1Transform) {
		t.Auth, t.Group, t.Life = prm.auth, group, 0
		if t.Enc == ike1EncAES && t.KeyLen == 0 {
			t.KeyLen = 128
		}
		if seen[t] || len(out) >= ike1ChunkMax || ike1HashFn(t.Hash) == nil || ike1EncKeyBytes(t.Enc, t.KeyLen) == 0 {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range prm.custom {
		if t.Group == group {
			add(t)
		}
	}
	for _, su := range ike1AMPairs {
		add(ike1Transform{Enc: su.enc, KeyLen: su.kl, Hash: su.hash})
	}
	return out
}

func (prm *ike1Params) label() string {
	mode := "main"
	if prm.aggressive {
		mode = "aggressive"
	}
	a := "PSK"
	switch {
	case prm.hybrid:
		a = "hybrid RSA"
	case prm.sign:
		a = "RSA"
	}
	if prm.xauth {
		a += "+XAUTH"
	}
	return "IKEv1 " + mode + " " + a
}

func ike1Prepare(s *ikeSpec) (*ike1Params, []string, error) {
	prm := &ike1Params{spec: *s}
	var warns []string
	prm.cisco = strings.EqualFold(strings.TrimSpace(s.Kind), "cisco")
	prm.l2tp = s.L2TP
	a := strings.ToLower(strings.TrimSpace(s.Auth))
	a = strings.NewReplacer("_", "-", " ", "-", "+", "-").Replace(a)
	switch a {
	case "", "psk", "secret", "pre-shared", "preshared", "pre-shared-key", "presharedkey", "shared-secret", "sharedsecret":
		if a == "" && s.PSK == "" && len(s.ClientCert) > 0 {
			prm.sign = true
		}
		if prm.cisco && !prm.l2tp {
			prm.xauth = true
		}
	case "xauth-psk", "xauthpsk", "psk-xauth", "xauth", "xauthinitpsk", "xauthinitpreshared", "xauth-preshared", "secret-xauth":
		prm.xauth = true
	case "rsa", "pubkey", "cert", "certificate", "rsasig", "rsa-sig", "x509", "rsa-signature", "signature":
		prm.sign = true
	case "xauth-rsa", "xauthrsa", "xauth-rsasig", "rsa-xauth", "xauth-cert", "xauthinitrsa", "cert-xauth", "xauthrsasig", "pubkey-xauth", "xauth-pubkey":
		prm.sign, prm.xauth = true, true
	case "hybrid", "hybrid-rsa", "xauth-hybrid", "hybrid-xauth", "hybridinitrsa", "hybrid-rsa-xauth", "xauthhybrid":
		prm.hybrid, prm.xauth = true, true
	default:
		return nil, nil, fmt.Errorf("IKEv1 authentication %q is not supported", s.Auth)
	}
	switch {
	case prm.hybrid:
		prm.auth = ike1AuthHyb
	case prm.sign && prm.xauth:
		prm.auth = ike1AuthXRSA
	case prm.sign:
		prm.auth = ike1AuthRSA
	case prm.xauth:
		prm.auth = ike1AuthXPSK
	default:
		prm.auth = ike1AuthPSK
	}
	prm.aggressive = s.Aggressive || (prm.cisco && !prm.sign && !prm.l2tp && strings.TrimSpace(s.GroupName) != "")
	if prm.sign {
		if err := prm.loadSigner(); err != nil {
			prm.credNote = err.Error()
		}
	}
	for _, ca := range s.CACerts {
		for _, c := range ike1ParseCerts(ca) {
			if prm.caPool == nil {
				prm.caPool = x509.NewCertPool()
			}
			prm.caPool.AddCert(c)
			prm.caDNs = append(prm.caDNs, c.RawSubject)
		}
	}
	local := strings.TrimSpace(s.LocalID)
	keyID := false
	if local == "" && prm.cisco {
		local = strings.TrimSpace(s.GroupName)
	}
	if prm.cisco && local != "" && local == strings.TrimSpace(s.GroupName) {
		keyID = true
	}
	prm.idType, prm.idData = ike1ParseID(local, keyID)
	if prm.idType == ike1IDDN || (prm.idType == 0 && prm.sign) {
		prm.idType, prm.idData = 0, nil
		if len(prm.certDER) > 0 {
			if c, err := x509.ParseCertificate(prm.certDER); err == nil {
				prm.idType, prm.idData = ike1IDDN, c.RawSubject
			}
		}
	}
	for _, p := range s.IKEProposals {
		trs, err := ike1ParseProposals(p)
		if err != nil {
			warns = append(warns, err.Error())
			continue
		}
		prm.custom = append(prm.custom, trs...)
	}
	return prm, warns, nil
}

func ike1ParseCerts(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	if bytes.Contains(b, []byte("-----BEGIN")) {
		rest := b
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" || blk.Type == "X509 CERTIFICATE" || blk.Type == "TRUSTED CERTIFICATE" {
				if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
					out = append(out, c)
				}
			}
		}
		return out
	}
	if cs, err := x509.ParseCertificates(b); err == nil {
		return cs
	}
	if d, err := b64decode(string(b)); err == nil {
		if cs, err := x509.ParseCertificates(d); err == nil {
			return cs
		}
	}
	return nil
}

func (prm *ike1Params) loadSigner() error {
	s := &prm.spec
	certSrc, keySrc := s.ClientCert, s.ClientKey
	if len(keySrc) == 0 && bytes.Contains(certSrc, []byte("PRIVATE KEY")) {
		keySrc = certSrc
	}
	if len(certSrc) == 0 && len(keySrc) == 0 {
		return errors.New("no client certificate/key in file")
	}
	certs := ike1ParseCerts(certSrc)
	if len(certs) == 0 {
		return errors.New("client certificate not found or unreadable")
	}
	if len(keySrc) == 0 {
		return errors.New("client private key not found")
	}
	key, err := ike1ParseRSAKey(keySrc)
	if err != nil {
		return err
	}
	pub, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("client certificate is not RSA (IKEv1 ECDSA auth not supported)")
	}
	if pub.N.Cmp(key.N) != 0 {
		return errors.New("client private key does not match certificate")
	}
	prm.certDER = certs[0].Raw
	prm.signer = key
	return nil
}

func ike1ParseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	conv := func(k any) (*rsa.PrivateKey, error) {
		if r, ok := k.(*rsa.PrivateKey); ok {
			return r, nil
		}
		return nil, errors.New("client key is not RSA (IKEv1 ECDSA auth not supported)")
	}
	if bytes.Contains(b, []byte("-----BEGIN")) {
		rest := b
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if !strings.Contains(blk.Type, "PRIVATE KEY") {
				continue
			}
			if blk.Type == "ENCRYPTED PRIVATE KEY" || blk.Headers["Proc-Type"] != "" {
				return nil, errors.New("client private key is password-protected")
			}
			if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				return conv(k)
			}
			if _, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return nil, errors.New("client key is not RSA (IKEv1 ECDSA auth not supported)")
			}
		}
		return nil, errors.New("client private key unreadable")
	}
	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		return conv(k)
	}
	return nil, errors.New("client private key unreadable")
}

func ike1ParseID(id string, keyID bool) (byte, []byte) {
	id = strings.TrimSpace(unquote(id))
	if id == "" || strings.HasPrefix(id, "%") {
		return 0, nil
	}
	if keyID {
		return ike1IDKeyID, []byte(id)
	}
	low := strings.ToLower(id)
	for _, p := range []struct {
		pre string
		typ byte
	}{{"keyid:", ike1IDKeyID}, {"fqdn:", ike1IDFQDN}, {"email:", ike1IDUFQDN}, {"rfc822:", ike1IDUFQDN}, {"userfqdn:", ike1IDUFQDN}, {"ipv4:", ike1IDIPv4}, {"dns:", ike1IDFQDN}} {
		if strings.HasPrefix(low, p.pre) {
			v := id[len(p.pre):]
			if p.typ == ike1IDIPv4 {
				if ip, err := netip.ParseAddr(v); err == nil {
					return ike1IDIPv4, ip.Unmap().AsSlice()
				}
			}
			if p.typ == ike1IDKeyID && strings.HasPrefix(v, "#") {
				if b, err := hex.DecodeString(v[1:]); err == nil {
					return ike1IDKeyID, b
				}
			}
			return p.typ, []byte(v)
		}
	}
	if ip, err := netip.ParseAddr(id); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return ike1IDIPv4, ip.AsSlice()
		}
		return ike1IDIPv6, ip.AsSlice()
	}
	if strings.HasPrefix(id, "@#") {
		if b, err := hex.DecodeString(id[2:]); err == nil {
			return ike1IDKeyID, b
		}
	}
	if strings.HasPrefix(id, "@@") {
		return ike1IDUFQDN, []byte(id[2:])
	}
	if strings.HasPrefix(id, "@") {
		return ike1IDFQDN, []byte(id[1:])
	}
	if strings.Contains(id, "=") && (strings.Contains(id, ",") || strings.Contains(id, "/") || strings.HasPrefix(strings.ToUpper(id), "CN=")) {
		return ike1IDDN, nil
	}
	if strings.Contains(id, "@") {
		return ike1IDUFQDN, []byte(id)
	}
	if strings.Contains(id, ".") {
		return ike1IDFQDN, []byte(id)
	}
	return ike1IDKeyID, []byte(id)
}

var ike1EncTok = map[string][2]uint16{
	"aes": {ike1EncAES, 128}, "aes128": {ike1EncAES, 128}, "aes192": {ike1EncAES, 192}, "aes256": {ike1EncAES, 256},
	"aescbc": {ike1EncAES, 128}, "aes_cbc": {ike1EncAES, 128}, "aes_cbc_128": {ike1EncAES, 128}, "aes_cbc_192": {ike1EncAES, 192},
	"aes_cbc_256": {ike1EncAES, 256}, "aes-128": {ike1EncAES, 128}, "aes-192": {ike1EncAES, 192}, "aes-256": {ike1EncAES, 256},
	"3des": {ike1Enc3DES, 0}, "3des_cbc": {ike1Enc3DES, 0}, "des3": {ike1Enc3DES, 0}, "tripledes": {ike1Enc3DES, 0}, "des-ede3": {ike1Enc3DES, 0},
	"des": {ike1EncDES, 0}, "des_cbc": {ike1EncDES, 0},
}

var ike1HashTok = map[string]uint16{
	"md5": ike1HashMD5, "hmac_md5": ike1HashMD5, "sha": ike1HashSHA1, "sha1": ike1HashSHA1, "hmac_sha1": ike1HashSHA1, "sha1_96": ike1HashSHA1,
	"sha2": ike1HashSHA2, "sha256": ike1HashSHA2, "sha2_256": ike1HashSHA2, "sha256_128": ike1HashSHA2, "hmac_sha2_256": ike1HashSHA2,
	"sha384": ike1HashSHA3, "sha2_384": ike1HashSHA3, "sha384_192": ike1HashSHA3, "sha512": ike1HashSHA5, "sha2_512": ike1HashSHA5, "sha512_256": ike1HashSHA5,
}

var ike1GroupTok = map[string]uint16{
	"modp768": 1, "modp1024": 2, "modp1536": 5, "modp2048": 14, "modp3072": 15, "modp4096": 16, "modp6144": 17, "modp8192": 18,
	"ecp256": 19, "ecp384": 20, "ecp521": 21, "curve25519": 31, "x25519": 31, "dh19": 19, "dh20": 20, "dh21": 21, "dh31": 31,
}

func ike1ParseProposals(s string) ([]ike1Transform, error) {
	var out []ike1Transform
	for _, prop := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		prop = strings.TrimSuffix(strings.TrimSpace(prop), "!")
		if prop == "" {
			continue
		}
		var encs [][2]uint16
		var hashes, groups []uint16
		toks := strings.FieldsFunc(strings.ToLower(prop), func(r rune) bool { return r == '-' || r == ';' || r == '/' })
		for i := 0; i < len(toks); i++ {
			t := toks[i]
			if e, ok := ike1EncTok[t]; ok {
				if t == "aes" && i+1 < len(toks) {
					if n, err := strconv.Atoi(toks[i+1]); err == nil && (n == 128 || n == 192 || n == 256) {
						e[1] = uint16(n)
						i++
					}
				}
				encs = append(encs, e)
				continue
			}
			if h, ok := ike1HashTok[t]; ok {
				hashes = append(hashes, h)
				continue
			}
			if g, ok := ike1GroupTok[t]; ok {
				groups = append(groups, g)
				continue
			}
			if strings.HasPrefix(t, "prf") {
				continue
			}
			num := strings.TrimLeft(t, "abcdefghijklmnopqrstuvwxyz_")
			pre := strings.TrimSuffix(t, num)
			if n, err := strconv.Atoi(num); err == nil && (pre == "dh" || pre == "group" || pre == "dhgroup" || pre == "dh_group") {
				groups = append(groups, uint16(n))
			}
		}
		if len(encs) == 0 && len(hashes) == 0 && len(groups) == 0 {
			return out, fmt.Errorf("unrecognized IKE proposal %q", prop)
		}
		if len(encs) == 0 {
			encs = [][2]uint16{{ike1EncAES, 256}, {ike1EncAES, 128}, {ike1Enc3DES, 0}}
		}
		if len(hashes) == 0 {
			hashes = []uint16{ike1HashSHA2, ike1HashSHA1}
		}
		if len(groups) == 0 {
			groups = []uint16{14, 2}
		}
		for _, g := range groups {
			for _, e := range encs {
				for _, h := range hashes {
					out = append(out, ike1Transform{Enc: e[0], KeyLen: e[1], Hash: h, Group: g})
				}
			}
		}
	}
	return out, nil
}
