package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

type iniKV struct {
	Key   string
	Value string
}

type iniSection struct {
	Name string
	Keys []iniKV
}

func (s *iniSection) Get(key string) string {
	if s == nil {
		return ""
	}
	for i := len(s.Keys) - 1; i >= 0; i-- {
		if strings.EqualFold(s.Keys[i].Key, key) {
			return s.Keys[i].Value
		}
	}
	return ""
}

func (s *iniSection) All(key string) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, kv := range s.Keys {
		if strings.EqualFold(kv.Key, key) {
			out = append(out, kv.Value)
		}
	}
	return out
}

func (s *iniSection) Has(key string) bool {
	if s == nil {
		return false
	}
	for _, kv := range s.Keys {
		if strings.EqualFold(kv.Key, key) {
			return true
		}
	}
	return false
}

func parseINI(text string) []*iniSection {
	var out []*iniSection
	cur := &iniSection{}
	out = append(out, cur)
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = &iniSection{Name: strings.TrimSpace(line[1 : len(line)-1])}
			out = append(out, cur)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur.Keys = append(cur.Keys, iniKV{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v)})
	}
	return out
}

func iniFind(secs []*iniSection, name string) *iniSection {
	for _, s := range secs {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

func iniFindAll(secs []*iniSection, name string) []*iniSection {
	var out []*iniSection
	for _, s := range secs {
		if strings.EqualFold(s.Name, name) {
			out = append(out, s)
		}
	}
	return out
}

func pemBlocks(data []byte, typ string) [][]byte {
	var out [][]byte
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if typ == "" || strings.Contains(b.Type, typ) {
			out = append(out, pem.EncodeToMemory(b))
		}
	}
	return out
}

func toPEMCert(data []byte) []byte {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return data
	}
	if _, err := x509.ParseCertificate(data); err == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	}
	if b, err := b64decode(string(data)); err == nil {
		if _, err := x509.ParseCertificate(b); err == nil {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		}
	}
	return data
}

func decodePKCS12(data []byte, password string) (certPEM, keyPEM []byte, caPEMs [][]byte, err error) {
	pwds := []string{password}
	if password != "" {
		pwds = append(pwds, "")
	}
	var lastErr error
	for _, pw := range pwds {
		key, cert, cas, err := pkcs12.DecodeChain(data, pw)
		if err != nil {
			lastErr = err
			continue
		}
		kb, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		for _, c := range cas {
			caPEMs = append(caPEMs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		return certPEM, keyPEM, caPEMs, nil
	}
	if lastErr == nil {
		lastErr = errors.New("invalid pkcs12")
	}
	return nil, nil, nil, lastErr
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
