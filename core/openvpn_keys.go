package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"sync"
	"time"

	"crypto/pbkdf2"

	ovpn "github.com/metacubex/mihomo/transport/openvpn"
)

var errOvpnKeyPassword = errors.New("private key is encrypted")

var (
	ovpnOIDPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	ovpnOIDPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	ovpnOIDHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	ovpnOIDHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	ovpnOIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	ovpnOIDHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	ovpnOIDHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	ovpnOIDAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	ovpnOIDAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	ovpnOIDAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	ovpnOIDDES3CBC    = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

type ovpnEncPKCS8 struct {
	Algo pkix.AlgorithmIdentifier
	Data []byte
}

type ovpnPBES2Params struct {
	KDF pkix.AlgorithmIdentifier
	Enc pkix.AlgorithmIdentifier
}

type ovpnPBKDF2Params struct {
	Salt   []byte
	Iter   int
	KeyLen int                      `asn1:"optional"`
	PRF    pkix.AlgorithmIdentifier `asn1:"optional"`
}

func ovpnPBES2(der []byte, pass string) ([]byte, error) {
	var ep ovpnEncPKCS8
	if _, err := asn1.Unmarshal(der, &ep); err != nil {
		return nil, err
	}
	if !ep.Algo.Algorithm.Equal(ovpnOIDPBES2) {
		return nil, fmt.Errorf("unsupported key encryption %v", ep.Algo.Algorithm)
	}
	var params ovpnPBES2Params
	if _, err := asn1.Unmarshal(ep.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	if !params.KDF.Algorithm.Equal(ovpnOIDPBKDF2) {
		return nil, errors.New("unsupported key derivation")
	}
	var kdf ovpnPBKDF2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, err
	}
	var h func() hash.Hash
	switch {
	case len(kdf.PRF.Algorithm) == 0 || kdf.PRF.Algorithm.Equal(ovpnOIDHMACSHA1):
		h = sha1.New
	case kdf.PRF.Algorithm.Equal(ovpnOIDHMACSHA224):
		h = sha256.New224
	case kdf.PRF.Algorithm.Equal(ovpnOIDHMACSHA256):
		h = sha256.New
	case kdf.PRF.Algorithm.Equal(ovpnOIDHMACSHA384):
		h = sha512.New384
	case kdf.PRF.Algorithm.Equal(ovpnOIDHMACSHA512):
		h = sha512.New
	default:
		return nil, errors.New("unsupported PBKDF2 PRF")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.Enc.Parameters.FullBytes, &iv); err != nil {
		return nil, err
	}
	keyLen := 0
	var mk func([]byte) (cipher.Block, error)
	switch {
	case params.Enc.Algorithm.Equal(ovpnOIDAES128CBC):
		keyLen, mk = 16, aes.NewCipher
	case params.Enc.Algorithm.Equal(ovpnOIDAES192CBC):
		keyLen, mk = 24, aes.NewCipher
	case params.Enc.Algorithm.Equal(ovpnOIDAES256CBC):
		keyLen, mk = 32, aes.NewCipher
	case params.Enc.Algorithm.Equal(ovpnOIDDES3CBC):
		keyLen, mk = 24, des.NewTripleDESCipher
	default:
		return nil, errors.New("unsupported key cipher")
	}
	key, err := pbkdf2.Key(h, pass, kdf.Salt, kdf.Iter, keyLen)
	if err != nil {
		return nil, err
	}
	blk, err := mk(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != blk.BlockSize() || len(ep.Data) == 0 || len(ep.Data)%blk.BlockSize() != 0 {
		return nil, errors.New("malformed encrypted key")
	}
	out := make([]byte, len(ep.Data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ep.Data)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > blk.BlockSize() || pad > len(out) {
		return nil, errors.New("wrong key password")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("wrong key password")
		}
	}
	out = out[:len(out)-pad]
	if _, err := x509.ParsePKCS8PrivateKey(out); err != nil {
		return nil, errors.New("wrong key password")
	}
	return out, nil
}

func ovpnParseKeyDER(der []byte) ([]byte, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	}
	return nil, errors.New("unrecognized private key format")
}

func ovpnKeyPEM(raw []byte, pass string) ([]byte, error) {
	if !bytes.Contains(raw, []byte("-----BEGIN")) {
		if k, err := ovpnParseKeyDER(raw); err == nil {
			return k, nil
		}
		if b, err := b64decode(strings.Join(strings.Fields(string(raw)), "")); err == nil {
			return ovpnParseKeyDER(b)
		}
		return nil, errors.New("unrecognized private key format")
	}
	rest := raw
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if !strings.Contains(b.Type, "PRIVATE KEY") {
			continue
		}
		if b.Type == "ENCRYPTED PRIVATE KEY" {
			if pass == "" {
				return nil, errOvpnKeyPassword
			}
			der, err := ovpnPBES2(b.Bytes, pass)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
		}
		if x509.IsEncryptedPEMBlock(b) {
			if pass == "" {
				return nil, errOvpnKeyPassword
			}
			der, err := x509.DecryptPEMBlock(b, []byte(pass))
			if err != nil {
				return nil, errors.New("wrong key password")
			}
			return pem.EncodeToMemory(&pem.Block{Type: b.Type, Bytes: der}), nil
		}
		return pem.EncodeToMemory(&pem.Block{Type: b.Type, Bytes: b.Bytes}), nil
	}
	return nil, errors.New("no private key found")
}

func ovpnCheckKeyPair(cert, key []byte) error {
	if len(cert) == 0 && len(key) == 0 {
		return nil
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return fmt.Errorf("client certificate/key: %v", err)
	}
	return nil
}

var (
	ovpnDummyCAOnce sync.Once
	ovpnDummyCAPEM  []byte
)

func ovpnDummyCA() []byte {
	ovpnDummyCAOnce.Do(func() {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return
		}
		tpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "vpntester placeholder"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			return
		}
		ovpnDummyCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	})
	return ovpnDummyCAPEM
}

func ovpnClientConfig(m *ovpnModel, r ovpnRemote, ca []byte, user, pass string) (*ovpn.ClientConfig, error) {
	if len(ca) == 0 {
		ca = ovpnDummyCA()
	}
	if user == "" && m.AuthUserPass {
		user, pass = "vpntester", "placeholder"
	}
	info := map[string]string{"IV_PLAT": "android"}
	for _, c := range m.DataCiphers {
		if strings.HasSuffix(c, "-GCM") {
			info["IV_NCP"] = "2"
			break
		}
	}
	cfg := &ovpn.ClientConfig{
		RemoteHost:     r.Host,
		RemotePort:     uint16(r.Port),
		Proto:          r.Proto,
		Dev:            "tun",
		Cipher:         m.Cipher,
		DataCiphers:    append([]string(nil), m.DataCiphers...),
		FallbackCipher: m.Fallback,
		Auth:           m.Auth,
		CompLZO:        m.CompLZO,
		CA:             ca,
		Cert:           m.Cert,
		Key:            m.Key,
		TLSAuth:        m.TLSAuth,
		KeyDirection:   strings.TrimSpace(m.KeyDirection),
		TLSCrypt:       m.TLSCrypt,
		TLSCryptV2:     m.TLSCryptV2,
		Username:       user,
		Password:       pass,
		PeerInfo:       info,
	}
	if err := cfg.Prepare(); err != nil {
		return nil, err
	}
	return cfg, nil
}
