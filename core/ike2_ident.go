package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"path"
	"strings"
	"time"
)

const (
	ike2IDIPv4  = 1
	ike2IDFQDN  = 2
	ike2IDEmail = 3
	ike2IDIPv6  = 5
	ike2IDDN    = 9
	ike2IDKeyID = 11
)

type ike2ID struct {
	typ  byte
	data []byte
	text string
}

func (id ike2ID) body() []byte {
	return append([]byte{id.typ, 0, 0, 0}, id.data...)
}

func (id ike2ID) String() string {
	switch id.typ {
	case ike2IDIPv4, ike2IDIPv6:
		if a, ok := netip.AddrFromSlice(id.data); ok {
			return a.String()
		}
	case ike2IDFQDN, ike2IDEmail:
		return string(id.data)
	case ike2IDDN:
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(id.data, &rdn); err == nil {
			return ike2DNString(rdn)
		}
	case ike2IDKeyID:
		return "@#" + hex.EncodeToString(id.data)
	}
	return fmt.Sprintf("id(%d):%x", id.typ, id.data)
}

func ike2IDFromBody(b []byte) ike2ID {
	if len(b) < 4 {
		return ike2ID{}
	}
	id := ike2ID{typ: b[0], data: b[4:]}
	id.text = id.String()
	return id
}

var ike2DNOIDs = map[string]asn1.ObjectIdentifier{
	"C": {2, 5, 4, 6}, "ST": {2, 5, 4, 8}, "S": {2, 5, 4, 8}, "L": {2, 5, 4, 7}, "O": {2, 5, 4, 10},
	"OU": {2, 5, 4, 11}, "CN": {2, 5, 4, 3}, "SN": {2, 5, 4, 4}, "SERIALNUMBER": {2, 5, 4, 5},
	"T": {2, 5, 4, 12}, "TITLE": {2, 5, 4, 12}, "G": {2, 5, 4, 42}, "GN": {2, 5, 4, 42},
	"E": {1, 2, 840, 113549, 1, 9, 1}, "EMAIL": {1, 2, 840, 113549, 1, 9, 1}, "EMAILADDRESS": {1, 2, 840, 113549, 1, 9, 1},
	"DC": {0, 9, 2342, 19200300, 100, 1, 25}, "UID": {0, 9, 2342, 19200300, 100, 1, 1},
	"STREET": {2, 5, 4, 9}, "POSTALCODE": {2, 5, 4, 17}, "D": {2, 5, 4, 13}, "N": {2, 5, 4, 41}, "I": {2, 5, 4, 43},
}

func ike2OIDName(o asn1.ObjectIdentifier) string {
	best := ""
	for k, v := range ike2DNOIDs {
		if v.Equal(o) && (best == "" || len(k) < len(best) || len(k) == len(best) && k < best) {
			best = k
		}
	}
	if best == "" {
		return o.String()
	}
	return best
}

func ike2DNString(rdn pkix.RDNSequence) string {
	var parts []string
	for _, set := range rdn {
		for _, a := range set {
			parts = append(parts, ike2OIDName(a.Type)+"="+fmt.Sprint(a.Value))
		}
	}
	return strings.Join(parts, ", ")
}

func ike2SplitDN(s string) []string {
	s = strings.TrimSpace(s)
	sep := byte(',')
	if strings.HasPrefix(s, "/") {
		sep = '/'
		s = s[1:]
	}
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == sep || (sep == ',' && c == ';') {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}

func ike2ParseDN(s string) ([]byte, bool) {
	var rdn pkix.RDNSequence
	for _, part := range ike2SplitDN(s) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, false
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), "\"")
		oid, ok := ike2DNOIDs[k]
		if !ok {
			return nil, false
		}
		rdn = append(rdn, pkix.RelativeDistinguishedNameSET{{Type: oid, Value: v}})
	}
	if len(rdn) == 0 {
		return nil, false
	}
	b, err := asn1.Marshal(rdn)
	if err != nil {
		return nil, false
	}
	return b, true
}

func ike2ParseID(s string) (ike2ID, bool) {
	s = strings.TrimSpace(unquote(s))
	if s == "" || strings.HasPrefix(s, "%") || s == "*" {
		return ike2ID{}, false
	}
	lower := strings.ToLower(s)
	mk := func(t byte, d []byte) (ike2ID, bool) {
		id := ike2ID{typ: t, data: d}
		id.text = id.String()
		return id, true
	}
	for _, pf := range []string{"fqdn:", "email:", "rfc822:", "userfqdn:", "keyid:", "asn1dn:", "ipv4:", "ipv6:", "dns:"} {
		if strings.HasPrefix(lower, pf) {
			v := s[len(pf):]
			switch pf {
			case "fqdn:", "dns:":
				return mk(ike2IDFQDN, []byte(v))
			case "email:", "rfc822:", "userfqdn:":
				return mk(ike2IDEmail, []byte(v))
			case "keyid:":
				v = strings.TrimPrefix(strings.TrimPrefix(v, "#"), "0x")
				if b, err := hex.DecodeString(v); err == nil {
					return mk(ike2IDKeyID, b)
				}
				return mk(ike2IDKeyID, []byte(v))
			case "asn1dn:":
				if b, ok := ike2ParseDN(v); ok {
					return mk(ike2IDDN, b)
				}
				return ike2ID{}, false
			case "ipv4:", "ipv6:":
				if a, err := netip.ParseAddr(v); err == nil {
					if a.Is4() {
						return mk(ike2IDIPv4, a.AsSlice())
					}
					return mk(ike2IDIPv6, a.AsSlice())
				}
			}
		}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		if a.Is4() {
			return mk(ike2IDIPv4, a.AsSlice())
		}
		return mk(ike2IDIPv6, a.AsSlice())
	}
	if strings.HasPrefix(s, "@#") {
		if b, err := hex.DecodeString(strings.ReplaceAll(s[2:], ":", "")); err == nil {
			return mk(ike2IDKeyID, b)
		}
	}
	if strings.HasPrefix(s, "@@") {
		return mk(ike2IDEmail, []byte(s[2:]))
	}
	if strings.HasPrefix(s, "@") {
		return mk(ike2IDFQDN, []byte(s[1:]))
	}
	if strings.Contains(s, "=") {
		if b, ok := ike2ParseDN(s); ok {
			return mk(ike2IDDN, b)
		}
	}
	if strings.Contains(s, "@") {
		return mk(ike2IDEmail, []byte(s))
	}
	return mk(ike2IDFQDN, []byte(s))
}

type ike2Attr struct {
	oid string
	val string
}

func ike2DNAttrs(der []byte) ([]ike2Attr, bool) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdn); err != nil {
		return nil, false
	}
	var out []ike2Attr
	for _, set := range rdn {
		for _, a := range set {
			out = append(out, ike2Attr{a.Type.String(), strings.ToLower(strings.TrimSpace(fmt.Sprint(a.Value)))})
		}
	}
	return out, true
}

func ike2DNMatch(want, got []byte) bool {
	if bytes.Equal(want, got) {
		return true
	}
	a, ok1 := ike2DNAttrs(want)
	b, ok2 := ike2DNAttrs(got)
	if !ok1 || !ok2 || len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, x := range a {
		found := false
		for j, y := range b {
			if used[j] || x.oid != y.oid {
				continue
			}
			if x.val == y.val || x.val == "*" {
				used[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ike2IDMatch(want, got ike2ID) bool {
	if want.typ == ike2IDDN && got.typ == ike2IDDN {
		return ike2DNMatch(want.data, got.data)
	}
	if want.typ != got.typ {
		return false
	}
	switch want.typ {
	case ike2IDFQDN, ike2IDEmail:
		w := strings.ToLower(string(want.data))
		g := strings.ToLower(string(got.data))
		if strings.Contains(w, "*") {
			ok, _ := path.Match(w, g)
			return ok
		}
		return w == g
	}
	return bytes.Equal(want.data, got.data)
}

func ike2CertHasID(c *x509.Certificate, id ike2ID) bool {
	switch id.typ {
	case ike2IDFQDN:
		n := strings.ToLower(string(id.data))
		for _, d := range c.DNSNames {
			if strings.EqualFold(d, n) {
				return true
			}
			if strings.HasPrefix(d, "*.") && strings.HasSuffix(n, strings.ToLower(d[1:])) && strings.Count(n, ".") == strings.Count(d, ".") {
				return true
			}
		}
		return false
	case ike2IDEmail:
		for _, e := range c.EmailAddresses {
			if strings.EqualFold(e, string(id.data)) {
				return true
			}
		}
		return false
	case ike2IDIPv4, ike2IDIPv6:
		a, _ := netip.AddrFromSlice(id.data)
		for _, ip := range c.IPAddresses {
			if b, ok := netip.AddrFromSlice(ip); ok && b.Unmap() == a.Unmap() {
				return true
			}
		}
		return false
	case ike2IDDN:
		return ike2DNMatch(id.data, c.RawSubject)
	case ike2IDKeyID:
		h := sha1.Sum(c.RawSubjectPublicKeyInfo)
		return bytes.Equal(h[:], id.data) || bytes.Equal(c.SubjectKeyId, id.data)
	}
	return false
}

func ike2ParseCerts(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	if bytes.Contains(data, []byte("-----BEGIN")) {
		rest := data
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if strings.Contains(b.Type, "CERTIFICATE") {
				if c, err := x509.ParseCertificate(b.Bytes); err == nil {
					out = append(out, c)
				}
			}
		}
		return out
	}
	if cs, err := x509.ParseCertificates(data); err == nil {
		return cs
	}
	if b, err := b64decode(strings.TrimSpace(string(data))); err == nil {
		if bytes.Contains(b, []byte("-----BEGIN")) {
			return ike2ParseCerts(b)
		}
		if cs, err := x509.ParseCertificates(b); err == nil {
			return cs
		}
	}
	return nil
}

func ike2ParseKey(data []byte) (crypto.Signer, error) {
	var ders [][]byte
	if bytes.Contains(data, []byte("-----BEGIN")) {
		rest := data
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if strings.Contains(b.Type, "ENCRYPTED") || b.Headers["Proc-Type"] != "" {
				return nil, errors.New("private key is encrypted")
			}
			if strings.Contains(b.Type, "PRIVATE KEY") {
				ders = append(ders, b.Bytes)
			}
		}
	} else {
		ders = append(ders, data)
	}
	for _, d := range ders {
		if k, err := x509.ParsePKCS8PrivateKey(d); err == nil {
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
		}
		if k, err := x509.ParsePKCS1PrivateKey(d); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(d); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("no usable private key")
}

func ike2SamePub(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}

var (
	ike2OIDSHA1RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	ike2OIDSHA256RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	ike2OIDSHA384RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	ike2OIDSHA512RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	ike2OIDRSAPSS    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	ike2OIDECSHA1    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	ike2OIDECSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	ike2OIDECSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	ike2OIDECSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	ike2OIDEd25519   = asn1.ObjectIdentifier{1, 3, 101, 112}
	ike2OIDHSHA1     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	ike2OIDHSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	ike2OIDHSHA384   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	ike2OIDHSHA512   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

func ike2Digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA1:
		d := sha1.Sum(data)
		return d[:]
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:]
	}
	return nil
}

func ike2HashFromOID(o asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case o.Equal(ike2OIDHSHA1):
		return crypto.SHA1
	case o.Equal(ike2OIDHSHA256):
		return crypto.SHA256
	case o.Equal(ike2OIDHSHA384):
		return crypto.SHA384
	case o.Equal(ike2OIDHSHA512):
		return crypto.SHA512
	}
	return 0
}

type ike2PSSParams struct {
	Hash    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional"`
	MGF     pkix.AlgorithmIdentifier `asn1:"explicit,tag:1,optional"`
	Salt    int                      `asn1:"explicit,tag:2,optional,default:20"`
	Trailer int                      `asn1:"explicit,tag:3,optional,default:1"`
}

type ike2ECSig struct {
	R, S *big.Int
}

func ike2HashListHas(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func ike2AlgID(oid asn1.ObjectIdentifier, nullParams bool) []byte {
	ai := pkix.AlgorithmIdentifier{Algorithm: oid}
	if nullParams {
		ai.Parameters = asn1.NullRawValue
	}
	b, _ := asn1.Marshal(ai)
	return b
}

func ike2Sign(key crypto.Signer, octets []byte, hashes []uint16) (byte, []byte, error) {
	pick := crypto.SHA256
	if len(hashes) > 0 && !ike2HashListHas(hashes, 2) {
		switch {
		case ike2HashListHas(hashes, 3):
			pick = crypto.SHA384
		case ike2HashListHas(hashes, 4):
			pick = crypto.SHA512
		case ike2HashListHas(hashes, 1):
			pick = crypto.SHA1
		}
	}
	rfc7427 := len(hashes) > 0
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if !rfc7427 {
			sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA1, ike2Digest(crypto.SHA1, octets))
			return 1, sig, err
		}
		oid := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA1: ike2OIDSHA1RSA, crypto.SHA256: ike2OIDSHA256RSA, crypto.SHA384: ike2OIDSHA384RSA, crypto.SHA512: ike2OIDSHA512RSA}[pick]
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, pick, ike2Digest(pick, octets))
		if err != nil {
			return 0, nil, err
		}
		ai := ike2AlgID(oid, true)
		return 14, append(append([]byte{byte(len(ai))}, ai...), sig...), nil
	case *ecdsa.PrivateKey:
		h := crypto.SHA256
		method := byte(9)
		switch k.Curve {
		case elliptic.P384():
			h, method = crypto.SHA384, 10
		case elliptic.P521():
			h, method = crypto.SHA512, 11
		}
		if !rfc7427 {
			r, sv, err := ecdsa.Sign(rand.Reader, k, ike2Digest(h, octets))
			if err != nil {
				return 0, nil, err
			}
			n := (k.Curve.Params().BitSize + 7) / 8
			out := make([]byte, 2*n)
			r.FillBytes(out[:n])
			sv.FillBytes(out[n:])
			return method, out, nil
		}
		oid := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA1: ike2OIDECSHA1, crypto.SHA256: ike2OIDECSHA256, crypto.SHA384: ike2OIDECSHA384, crypto.SHA512: ike2OIDECSHA512}[pick]
		sig, err := ecdsa.SignASN1(rand.Reader, k, ike2Digest(pick, octets))
		if err != nil {
			return 0, nil, err
		}
		ai := ike2AlgID(oid, false)
		return 14, append(append([]byte{byte(len(ai))}, ai...), sig...), nil
	case ed25519.PrivateKey:
		if !ike2HashListHas(hashes, 5) {
			return 0, nil, errors.New("responder does not accept Ed25519 signatures")
		}
		sig := ed25519.Sign(k, octets)
		ai := ike2AlgID(ike2OIDEd25519, false)
		return 14, append(append([]byte{byte(len(ai))}, ai...), sig...), nil
	}
	return 0, nil, fmt.Errorf("unsupported private key type %T", key)
}

func ike2VerifySig(pub crypto.PublicKey, method byte, data, octets []byte) error {
	bad := errors.New("signature verification failed")
	switch method {
	case 1:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA AUTH with non-RSA certificate")
		}
		if rsa.VerifyPKCS1v15(k, crypto.SHA1, ike2Digest(crypto.SHA1, octets), data) != nil {
			return bad
		}
		return nil
	case 9, 10, 11:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ECDSA AUTH with non-ECDSA certificate")
		}
		h := map[byte]crypto.Hash{9: crypto.SHA256, 10: crypto.SHA384, 11: crypto.SHA512}[method]
		n := len(data) / 2
		if n == 0 || len(data)%2 != 0 {
			return bad
		}
		r := new(big.Int).SetBytes(data[:n])
		s := new(big.Int).SetBytes(data[n:])
		if !ecdsa.Verify(k, ike2Digest(h, octets), r, s) {
			return bad
		}
		return nil
	case 14:
		if len(data) < 1 || int(data[0])+1 > len(data) {
			return errors.New("malformed RFC 7427 signature")
		}
		var ai pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(data[1:1+int(data[0])], &ai); err != nil {
			return errors.New("malformed RFC 7427 algorithm identifier")
		}
		sig := data[1+int(data[0]):]
		o := ai.Algorithm
		rsaH := map[string]crypto.Hash{ike2OIDSHA1RSA.String(): crypto.SHA1, ike2OIDSHA256RSA.String(): crypto.SHA256, ike2OIDSHA384RSA.String(): crypto.SHA384, ike2OIDSHA512RSA.String(): crypto.SHA512}
		ecH := map[string]crypto.Hash{ike2OIDECSHA1.String(): crypto.SHA1, ike2OIDECSHA256.String(): crypto.SHA256, ike2OIDECSHA384.String(): crypto.SHA384, ike2OIDECSHA512.String(): crypto.SHA512}
		if h, ok := rsaH[o.String()]; ok {
			k, ok := pub.(*rsa.PublicKey)
			if !ok {
				return errors.New("RSA signature with non-RSA certificate")
			}
			if rsa.VerifyPKCS1v15(k, h, ike2Digest(h, octets), sig) != nil {
				return bad
			}
			return nil
		}
		if h, ok := ecH[o.String()]; ok {
			k, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("ECDSA signature with non-ECDSA certificate")
			}
			if !ecdsa.VerifyASN1(k, ike2Digest(h, octets), sig) {
				var es ike2ECSig
				n := len(sig) / 2
				if _, err := asn1.Unmarshal(sig, &es); err != nil && n > 0 && len(sig)%2 == 0 {
					if ecdsa.Verify(k, ike2Digest(h, octets), new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
						return nil
					}
				}
				return bad
			}
			return nil
		}
		if o.Equal(ike2OIDRSAPSS) {
			k, ok := pub.(*rsa.PublicKey)
			if !ok {
				return errors.New("RSA-PSS signature with non-RSA certificate")
			}
			var pp ike2PSSParams
			pp.Salt = 20
			h := crypto.SHA1
			if len(ai.Parameters.FullBytes) > 0 {
				if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &pp); err == nil {
					if x := ike2HashFromOID(pp.Hash.Algorithm); x != 0 {
						h = x
					}
				}
			}
			if rsa.VerifyPSS(k, h, ike2Digest(h, octets), sig, &rsa.PSSOptions{SaltLength: pp.Salt, Hash: h}) != nil {
				if rsa.VerifyPSS(k, h, ike2Digest(h, octets), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h}) != nil {
					return bad
				}
			}
			return nil
		}
		if o.Equal(ike2OIDEd25519) {
			k, ok := pub.(ed25519.PublicKey)
			if !ok {
				return errors.New("Ed25519 signature with non-Ed25519 certificate")
			}
			if !ed25519.Verify(k, octets, sig) {
				return bad
			}
			return nil
		}
		return fmt.Errorf("unsupported signature algorithm %s", o)
	}
	return fmt.Errorf("unsupported AUTH method %d", method)
}

func ike2CheckSigFrom(child, parent *x509.Certificate) error {
	err := child.CheckSignatureFrom(parent)
	if err == nil {
		return nil
	}
	var ia x509.InsecureAlgorithmError
	if !errors.As(err, &ia) {
		return err
	}
	k, ok := parent.PublicKey.(*rsa.PublicKey)
	if !ok {
		return err
	}
	switch child.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		return rsa.VerifyPKCS1v15(k, crypto.SHA1, ike2Digest(crypto.SHA1, child.RawTBSCertificate), child.Signature)
	}
	return err
}

func ike2ManualChain(leaf *x509.Certificate, inter, roots []*x509.Certificate) error {
	now := time.Now()
	cur := leaf
	pool := append(append([]*x509.Certificate{}, inter...), roots...)
	for depth := 0; depth < 8; depth++ {
		if now.Before(cur.NotBefore) || now.After(cur.NotAfter) {
			return fmt.Errorf("certificate %q expired or not yet valid", cur.Subject.CommonName)
		}
		for _, r := range roots {
			if bytes.Equal(r.Raw, cur.Raw) {
				return nil
			}
		}
		var next *x509.Certificate
		for _, c := range pool {
			if bytes.Equal(c.RawSubject, cur.RawIssuer) && ike2CheckSigFrom(cur, c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			return errors.New("certificate signed by unknown authority")
		}
		for _, r := range roots {
			if next == r {
				return nil
			}
		}
		cur = next
	}
	return errors.New("certificate chain too long")
}

func ike2VerifyChain(leaf *x509.Certificate, inter, roots []*x509.Certificate) error {
	for _, r := range roots {
		if bytes.Equal(r.Raw, leaf.Raw) {
			if time.Now().After(leaf.NotAfter) {
				return errors.New("pinned server certificate expired")
			}
			return nil
		}
	}
	rp := x509.NewCertPool()
	for _, r := range roots {
		rp.AddCert(r)
	}
	ip := x509.NewCertPool()
	for _, c := range inter {
		ip.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: rp, Intermediates: ip, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err == nil {
		return nil
	}
	if merr := ike2ManualChain(leaf, inter, roots); merr == nil {
		return nil
	}
	return err
}

func ike2ErrText(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, "x509: ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
