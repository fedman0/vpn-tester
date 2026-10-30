package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ike2Params struct {
	spec     ikeSpec
	auth     string
	eapType  string
	cert     *x509.Certificate
	chain    [][]byte
	key      crypto.Signer
	cas      []*x509.Certificate
	ike      []ike2Proposal
	esp      []ike2Proposal
	propNote string
}

func (p *ike2Params) rounds() []string {
	switch p.auth {
	case "psk":
		return []string{"psk"}
	case "pubkey":
		return []string{"pubkey"}
	case "pubkey+eap":
		return []string{"pubkey", "eap"}
	}
	return []string{"eap"}
}

func (p *ike2Params) remoteID() (ike2ID, bool) {
	return ike2ParseID(p.spec.RemoteID)
}

func (p *ike2Params) eapIdentity() string {
	if p.spec.Username != "" {
		return p.spec.Username
	}
	if p.spec.LocalID != "" {
		return unquote(p.spec.LocalID)
	}
	if p.cert != nil && p.eapType == "tls" {
		return ike2ID{typ: ike2IDDN, data: p.cert.RawSubject}.String()
	}
	return ""
}

func (p *ike2Params) localID(round string, s *ike2Session) ike2ID {
	if id, ok := ike2ParseID(p.spec.LocalID); ok {
		return id
	}
	if round == "pubkey" && p.cert != nil {
		id := ike2ID{typ: ike2IDDN, data: p.cert.RawSubject}
		id.text = id.String()
		return id
	}
	if round == "eap" {
		if id, ok := ike2ParseID(p.spec.Username); ok {
			return id
		}
		if p.eapType == "tls" && p.cert != nil {
			id := ike2ID{typ: ike2IDDN, data: p.cert.RawSubject}
			id.text = id.String()
			return id
		}
	}
	a := s.localAP().Addr()
	t := byte(ike2IDIPv4)
	if a.Is6() {
		t = ike2IDIPv6
	}
	id := ike2ID{typ: t, data: a.AsSlice()}
	id.text = id.String()
	return id
}

func (p *ike2Params) eapIdentityID(s *ike2Session) ike2ID {
	if id, ok := ike2ParseID(p.spec.Username); ok {
		return id
	}
	return p.localID("eap", s)
}

func (p *ike2Params) hasEAPCreds() bool {
	if p.eapType == "tls" {
		return p.cert != nil && p.key != nil
	}
	if p.eapType == "ttls" || p.eapType == "peap" {
		return false
	}
	return p.spec.Password != "" || (p.eapType == "" && p.cert != nil && p.key != nil)
}

func (p *ike2Params) newEAP() *ike2EAP {
	e := &ike2EAP{identity: p.eapIdentity(), password: p.spec.Password, method: ike2EAPMethodByName(p.eapType)}
	if e.identity == "" && p.spec.LocalID != "" {
		e.identity = p.spec.LocalID
	}
	if p.cert != nil && p.key != nil && (p.eapType == "tls" || p.eapType == "") {
		e.tls = &ike2EAPTLSState{cert: ike2TLSCert(p.cert.Raw, p.chain, p.key), cas: p.cas}
	}
	return e
}

func (p *ike2Params) missingCreds() string {
	switch p.auth {
	case "psk":
		if p.spec.PSK == "" {
			return "no pre-shared key in file"
		}
	case "pubkey", "pubkey+eap":
		if p.cert == nil || p.key == nil {
			return "no usable client certificate/key in file"
		}
	}
	return ""
}

func (p *ike2Params) proposalSets() [][]ike2Proposal {
	if len(p.ike) > 0 {
		return [][]ike2Proposal{p.ike}
	}
	return [][]ike2Proposal{ike2DefaultIKE(), ike2LegacyIKE()}
}

func ike2Prop(proto byte, encr []ike2Transform, integ, prf, dh []uint16, esn bool) ike2Proposal {
	p := ike2Proposal{proto: proto}
	for _, e := range encr {
		e.typ = ike2TEncr
		p.ts = append(p.ts, e)
	}
	for _, i := range integ {
		p.ts = append(p.ts, ike2Transform{typ: ike2TInteg, id: i})
	}
	for _, i := range prf {
		p.ts = append(p.ts, ike2Transform{typ: ike2TPRF, id: i})
	}
	for _, i := range dh {
		p.ts = append(p.ts, ike2Transform{typ: ike2TDH, id: i})
	}
	if esn {
		p.ts = append(p.ts, ike2Transform{typ: ike2TESN, id: 0}, ike2Transform{typ: ike2TESN, id: 1})
	}
	return p
}

var ike2ModernGroups = []uint16{19, 14, 31, 20, 21, 15, 16}

func ike2DefaultIKE() []ike2Proposal {
	prf := []uint16{ike2PRFSHA256, ike2PRFSHA384, ike2PRFSHA512, ike2PRFSHA1}
	return []ike2Proposal{
		ike2Prop(1, []ike2Transform{{id: ike2EncrAESCBC, keyLen: 256}, {id: ike2EncrAESCBC, keyLen: 128}, {id: ike2EncrAESCBC, keyLen: 192}},
			[]uint16{ike2IntegSHA256, ike2IntegSHA384, ike2IntegSHA512, ike2IntegSHA1}, prf, ike2ModernGroups, false),
		ike2Prop(1, []ike2Transform{{id: ike2EncrAESGCM16, keyLen: 256}, {id: ike2EncrAESGCM16, keyLen: 128}, {id: ike2EncrChaCha}},
			nil, prf, ike2ModernGroups, false),
	}
}

func ike2LegacyIKE() []ike2Proposal {
	return []ike2Proposal{
		ike2Prop(1, []ike2Transform{{id: ike2EncrAESCBC, keyLen: 256}, {id: ike2EncrAESCBC, keyLen: 128}, {id: ike2EncrDES3}},
			[]uint16{ike2IntegSHA1, ike2IntegSHA256, ike2IntegMD5}, []uint16{ike2PRFSHA1, ike2PRFSHA256, ike2PRFMD5}, []uint16{2, 5, 14, 19}, false),
		ike2Prop(1, []ike2Transform{{id: ike2EncrAESGCM16, keyLen: 256}, {id: ike2EncrAESGCM16, keyLen: 128}, {id: ike2EncrAESGCM12, keyLen: 256}, {id: ike2EncrAESGCM12, keyLen: 128}},
			nil, []uint16{ike2PRFSHA1, ike2PRFSHA256, ike2PRFSHA384, ike2PRFSHA512}, []uint16{2, 5, 14, 19}, false),
	}
}

func ike2DefaultESP() []ike2Proposal {
	return []ike2Proposal{
		ike2Prop(3, []ike2Transform{{id: ike2EncrAESGCM16, keyLen: 256}, {id: ike2EncrAESGCM16, keyLen: 128}}, nil, nil, nil, true),
		ike2Prop(3, []ike2Transform{{id: ike2EncrAESCBC, keyLen: 256}, {id: ike2EncrAESCBC, keyLen: 128}, {id: ike2EncrDES3}},
			[]uint16{ike2IntegSHA256, ike2IntegSHA1, ike2IntegSHA384, ike2IntegSHA512}, nil, nil, true),
	}
}

var ike2EncrTokens = map[string]ike2Transform{
	"aes": {id: ike2EncrAESCBC, keyLen: 128}, "aes128": {id: ike2EncrAESCBC, keyLen: 128}, "aes192": {id: ike2EncrAESCBC, keyLen: 192},
	"aes256": {id: ike2EncrAESCBC, keyLen: 256}, "aes128cbc": {id: ike2EncrAESCBC, keyLen: 128}, "aes256cbc": {id: ike2EncrAESCBC, keyLen: 256},
	"3des": {id: ike2EncrDES3}, "chacha20poly1305": {id: ike2EncrChaCha},
	"aes128gcm16": {id: ike2EncrAESGCM16, keyLen: 128}, "aes128gcm128": {id: ike2EncrAESGCM16, keyLen: 128}, "aes128gcm": {id: ike2EncrAESGCM16, keyLen: 128},
	"aes192gcm16": {id: ike2EncrAESGCM16, keyLen: 192}, "aes192gcm128": {id: ike2EncrAESGCM16, keyLen: 192},
	"aes256gcm16": {id: ike2EncrAESGCM16, keyLen: 256}, "aes256gcm128": {id: ike2EncrAESGCM16, keyLen: 256}, "aes256gcm": {id: ike2EncrAESGCM16, keyLen: 256},
	"aes128gcm12": {id: ike2EncrAESGCM12, keyLen: 128}, "aes128gcm96": {id: ike2EncrAESGCM12, keyLen: 128},
	"aes192gcm12": {id: ike2EncrAESGCM12, keyLen: 192}, "aes192gcm96": {id: ike2EncrAESGCM12, keyLen: 192},
	"aes256gcm12": {id: ike2EncrAESGCM12, keyLen: 256}, "aes256gcm96": {id: ike2EncrAESGCM12, keyLen: 256},
}

var ike2IntegTokens = map[string][2]uint16{
	"sha": {ike2IntegSHA1, ike2PRFSHA1}, "sha1": {ike2IntegSHA1, ike2PRFSHA1}, "sha256": {ike2IntegSHA256, ike2PRFSHA256},
	"sha2_256": {ike2IntegSHA256, ike2PRFSHA256}, "sha384": {ike2IntegSHA384, ike2PRFSHA384}, "sha2_384": {ike2IntegSHA384, ike2PRFSHA384},
	"sha512": {ike2IntegSHA512, ike2PRFSHA512}, "sha2_512": {ike2IntegSHA512, ike2PRFSHA512}, "md5": {ike2IntegMD5, ike2PRFMD5},
}

var ike2PRFTokens = map[string]uint16{
	"prfsha1": ike2PRFSHA1, "prfsha256": ike2PRFSHA256, "prfsha384": ike2PRFSHA384, "prfsha512": ike2PRFSHA512, "prfmd5": ike2PRFMD5,
}

var ike2DHTokens = map[string]uint16{
	"modp768": 1, "modp1024": 2, "modp1536": 5, "modp2048": 14, "modp3072": 15, "modp4096": 16, "modp6144": 17, "modp8192": 18,
	"ecp256": 19, "ecp384": 20, "ecp521": 21, "modp1024s160": 22, "modp2048s224": 23, "modp2048s256": 24, "ecp192": 25, "ecp224": 26,
	"ecp224bp": 27, "ecp256bp": 28, "ecp384bp": 29, "ecp512bp": 30, "curve25519": 31, "x25519": 31, "curve448": 32, "x448": 32,
}

func ike2ParseProposals(list []string, esp bool) ([]ike2Proposal, []string) {
	var out []ike2Proposal
	var bad []string
	seenBad := map[string]bool{}
	addBad := func(t string) {
		if !seenBad[t] {
			seenBad[t] = true
			bad = append(bad, t)
		}
	}
	proto := byte(1)
	if esp {
		proto = 3
	}
	for _, item := range list {
		for _, ps := range strings.Split(item, ",") {
			ps = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(ps), "!")))
			if ps == "" {
				continue
			}
			if ps == "default" {
				if esp {
					out = append(out, ike2DefaultESP()...)
				} else {
					out = append(out, ike2DefaultIKE()...)
				}
				continue
			}
			var encA, encN []ike2Transform
			var integ, prf, dh []uint16
			for _, tok := range strings.FieldsFunc(ps, func(r rune) bool { return r == '-' || r == ';' || r == '+' }) {
				tok = ike2LibreswanToken(strings.TrimSpace(tok))
				if tok == "" {
					continue
				}
				if e, ok := ike2EncrTokens[tok]; ok {
					if e.id == ike2EncrAESCBC || e.id == ike2EncrDES3 {
						encN = append(encN, e)
					} else {
						encA = append(encA, e)
					}
					continue
				}
				if v, ok := ike2IntegTokens[tok]; ok {
					integ = append(integ, v[0])
					if !esp {
						prf = append(prf, v[1])
					}
					continue
				}
				if v, ok := ike2PRFTokens[tok]; ok {
					prf = append(prf, v)
					continue
				}
				if v, ok := ike2DHTokens[tok]; ok {
					if esp {
						continue
					}
					if ike2KESupported(v) {
						dh = append(dh, v)
					} else {
						addBad(tok)
					}
					continue
				}
				if tok == "esn" || tok == "noesn" {
					continue
				}
				if strings.HasPrefix(tok, "ke") && strings.Contains(tok, "_") {
					addBad(tok)
					continue
				}
				addBad(tok)
			}
			if !esp && len(dh) == 0 {
				continue
			}
			if len(encN) > 0 {
				ig := integ
				if len(ig) == 0 {
					ig = []uint16{ike2IntegSHA256, ike2IntegSHA1}
				}
				pr := prf
				if !esp && len(pr) == 0 {
					pr = []uint16{ike2PRFSHA256, ike2PRFSHA1}
				}
				out = append(out, ike2Prop(proto, encN, ig, pr, dh, esp))
			}
			if len(encA) > 0 {
				pr := prf
				if !esp && len(pr) == 0 {
					pr = []uint16{ike2PRFSHA256, ike2PRFSHA384, ike2PRFSHA512, ike2PRFSHA1}
				}
				out = append(out, ike2Prop(proto, encA, nil, pr, dh, esp))
			}
		}
	}
	return out, bad
}

func ike2NormAuth(s *ikeSpec) (string, string) {
	a := strings.ToLower(strings.TrimSpace(s.Auth))
	eap := ""
	switch {
	case a == "psk" || a == "secret" || a == "sharedsecret" || a == "shared" || a == "preshared":
		return "psk", ""
	case a == "pubkey" || a == "rsa" || a == "ecdsa" || a == "cert" || a == "certificate" || a == "rsasig" || a == "ecdsasig" || a == "rsa-sig":
		return "pubkey", ""
	case strings.HasPrefix(a, "pubkey+") || strings.HasPrefix(a, "cert+") || strings.HasPrefix(a, "cert-"):
		_, rest, _ := strings.Cut(strings.ReplaceAll(a, "cert-", "cert+"), "+")
		return "pubkey+eap", strings.TrimPrefix(rest, "eap-")
	case a == "eap-tls" || a == "tls":
		return "eap", "tls"
	case a == "byod" || a == "eap-ttls" || a == "ttls":
		return "eap", "ttls"
	case a == "eap-peap" || a == "peap":
		return "eap", "peap"
	case strings.HasPrefix(a, "eap"):
		eap = strings.TrimPrefix(strings.TrimPrefix(a, "eap"), "-")
		if eap == "radius" || eap == "dynamic" {
			eap = ""
		}
		return "eap", eap
	case a == "xauth" || a == "mschapv2":
		return "eap", "mschapv2"
	}
	switch {
	case s.PSK != "":
		return "psk", ""
	case s.Username != "" || s.Password != "":
		return "eap", ""
	case len(s.ClientCert) > 0:
		return "pubkey", ""
	}
	return "eap", ""
}

type ike2Validator struct{}

func (ike2Validator) Validate(c *Config) error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("missing server address")
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}
	return nil
}

func ike2BuildConfig(f *vfile, fs *vfs, s *ikeSpec) *Config {
	c := newConfig(f, "IPsec", "IKEv2")
	c.Name = s.Name
	c.Host = strings.Trim(strings.TrimSpace(s.Host), "[]")
	c.Port = s.Port
	if c.Port == 0 {
		c.Port = 500
	}
	c.Transport = "udp"
	c.UDP = true
	prm := &ike2Params{spec: *s}
	prm.spec.Host = c.Host
	prm.auth, prm.eapType = ike2NormAuth(s)
	if len(s.ClientCert) > 0 {
		certs := ike2ParseCerts(s.ClientCert)
		var key crypto.Signer
		if len(s.ClientKey) > 0 {
			k, err := ike2ParseKey(s.ClientKey)
			if err != nil {
				c.Warn("client key: %s", shortErr(err))
			} else {
				key = k
			}
		}
		for _, ct := range certs {
			if key != nil && ike2SamePub(ct.PublicKey, key.Public()) {
				prm.cert = ct
				break
			}
		}
		if prm.cert == nil && len(certs) > 0 {
			prm.cert = certs[0]
			if key != nil {
				c.Warn("client key does not match client certificate")
				key = nil
			}
		}
		prm.key = key
		for _, ct := range certs {
			if ct != prm.cert && !bytes.Equal(ct.RawIssuer, ct.RawSubject) {
				prm.chain = append(prm.chain, ct.Raw)
			}
		}
		if prm.cert == nil {
			c.Warn("client certificate could not be parsed")
		}
	}
	for _, ca := range s.CACerts {
		for _, ct := range ike2ParseCerts(ca) {
			dup := false
			for _, x := range prm.cas {
				if bytes.Equal(x.Raw, ct.Raw) {
					dup = true
				}
			}
			if !dup {
				prm.cas = append(prm.cas, ct)
			}
		}
	}
	if len(s.IKEProposals) > 0 {
		props, bad := ike2ParseProposals(s.IKEProposals, false)
		prm.ike = props
		if len(bad) > 0 {
			c.Warn("IKE algorithms not supported by tester: %s", strings.Join(bad, ", "))
		}
		if len(props) == 0 {
			prm.propNote = "configured IKE proposals unusable, using defaults"
		}
	}
	if len(s.ESPProposals) > 0 {
		props, _ := ike2ParseProposals(s.ESPProposals, true)
		prm.esp = props
	}
	c.Security = "IKEv2 " + ike2AuthLabel(prm)
	c.Username = s.Username
	c.Password = s.Password
	c.PSK = s.PSK
	if prm.key != nil {
		c.PrivateKey = "client key"
	}
	c.Extra = s.RemoteID + "|" + s.LocalID + "|" + prm.auth + "|" + ike2Digest16(s, prm)
	c.SNI = s.RemoteID
	c.Tester = Ikev2ConnectivityTester{}
	c.Validator = ike2Validator{}
	c.Payload = prm
	return c
}

func init() {
	buildIKEConfig = ike2BuildConfig
}

type Ikev2ConnectivityTester struct{}

func (Ikev2ConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	p.Engine("ikev2")
	prm, ok := c.Payload.(*ike2Params)
	if !ok {
		p.Unsupported("missing IKEv2 parameters")
		return
	}
	addrs := p.Resolve(ctx, c.Host)
	if addrs == nil {
		return
	}
	if prm.propNote != "" {
		p.Note("%s", prm.propNote)
	}
	addr := addrs[0]
	key := ike2CacheKey(addr.String(), c.Port, prm)
	if snap := ike2CacheGet("trust|" + key); snap != nil {
		snap.apply(p)
		return
	}
	if prm.noCreds() {
		mu := ike2KeyLock("nocreds|" + key)
		mu.Lock()
		defer mu.Unlock()
		if snap := ike2CacheGet("nocreds|" + key); snap != nil {
			snap.apply(p)
			return
		}
	}
	release, ok := ike2Acquire(ctx, addr.String())
	if !ok {
		p.Fail(StageHandshake, StateHandshakeFailed, context.DeadlineExceeded)
		return
	}
	kind := ike2Run(ctx, c, p, prm, addr)
	release()
	switch kind {
	case "nocreds":
		ike2CachePut("nocreds|"+key, p)
	case "trust":
		ike2CachePut("trust|"+key, p)
	}
}

func ike2Run(ctx context.Context, c *Config, p *probe, prm *ike2Params, addr netip.Addr) string {
	port := c.Port
	var s *ike2Session
	defer func() {
		if s != nil {
			s.close()
		}
	}()
	var redirFrom []byte
	hctx, hcancel := p.StageCtx(ctx, StageHandshake)
	defer hcancel()
	for redirects := 0; ; redirects++ {
		s = newIke2Session(addr, port)
		s.redirFrom = redirFrom
		if err := s.dial(); err != nil {
			p.Fail(StageTransport, classifyErr(StageTransport, err), err)
			return ""
		}
		err := s.saInit(hctx, prm.proposalSets())
		var rd *ike2Redirect
		if errors.As(err, &rd) && redirects < 2 {
			na, rerr := ike2ResolveRedirect(hctx, rd.target)
			if rerr != nil {
				p.Pass(StageTransport)
				p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("redirect to %s failed: %v", rd.target, rerr))
				return ""
			}
			p.Note("redirected to %s", rd.target)
			redirFrom = ike2GWIdent(addr)
			s.close()
			addr = na
			p.res.Address = na.String()
			continue
		}
		if err != nil {
			ike2Report(p, s, err, StageHandshake)
			ike2FlushNotes(p, s)
			return ""
		}
		break
	}
	hcancel()
	p.Pass(StageTransport, StageHandshake)
	p.Note("IKE %s", s.keys.suite)
	if s.natSwitched {
		p.Note("NAT-T: switched to UDP 4500")
	}
	if miss := prm.missingCreds(); miss != "" {
		s.deleteSA(500 * time.Millisecond)
		p.Connectable(s.rtt)
		p.Note("auth not tested: %s", miss)
		ike2FlushNotes(p, s)
		return "nocreds"
	}
	actx, acancel := p.StageCtx(ctx, StageAuth)
	err := s.authenticate(actx, prm)
	acancel()
	if s.fragSent || s.fragRecv {
		p.Note("IKE fragmentation used")
	}
	kind := ""
	var cannot *ike2CannotErr
	var fail *ike2Failure
	switch {
	case err == nil:
		p.Pass(StageAuth)
		p.Connectable(s.rtt)
		p.Note("data plane not tested (ESP not available in userspace)")
		s.deleteSA(1500 * time.Millisecond)
	case errors.Is(err, ike2ErrNoCreds):
		p.Connectable(s.rtt)
		p.Note("auth not tested: no credentials in file")
		s.deleteSA(500 * time.Millisecond)
		kind = "nocreds"
	case errors.As(err, &cannot):
		p.Connectable(s.rtt)
		p.Note("auth not tested: %s (not supported by tester)", cannot.msg)
		s.deleteSA(500 * time.Millisecond)
		kind = "nocreds"
	default:
		ike2Report(p, s, err, StageAuth)
		s.deleteSA(500 * time.Millisecond)
		if errors.As(err, &fail) && fail.trust {
			kind = "trust"
		}
	}
	ike2FlushNotes(p, s)
	return kind
}

func (p *ike2Params) noCreds() bool {
	if p.missingCreds() != "" {
		return true
	}
	for _, r := range p.rounds() {
		if r == "eap" && !p.hasEAPCreds() {
			return true
		}
	}
	return false
}

type ike2Snap struct {
	res     TestResult
	latency time.Duration
	failed  bool
	at      time.Time
}

func (s *ike2Snap) apply(p *probe) {
	r := s.res
	r.ID = p.res.ID
	*p.res = r
	p.latency = s.latency
	p.failed = s.failed
	p.Note("same server setup was tested moments ago; result reused to avoid half-open IKE SAs")
}

var (
	ike2Cache sync.Map
	ike2Locks sync.Map
)

func ike2CacheKey(addr string, port int, prm *ike2Params) string {
	h := sha256.New()
	for _, ca := range prm.cas {
		h.Write(ca.Raw)
	}
	return fmt.Sprintf("%s|%d|%s|%s|%s|%s|%x", addr, port, prm.auth, prm.eapType, prm.spec.RemoteID, strings.Join(prm.spec.IKEProposals, ","), h.Sum(nil)[:8])
}

func ike2CacheGet(k string) *ike2Snap {
	v, ok := ike2Cache.Load(k)
	if !ok {
		return nil
	}
	s := v.(*ike2Snap)
	if time.Since(s.at) > 90*time.Second {
		ike2Cache.Delete(k)
		return nil
	}
	return s
}

func ike2CachePut(k string, p *probe) {
	ike2Cache.Store(k, &ike2Snap{res: *p.res, latency: p.latency, failed: p.failed, at: time.Now()})
}

func ike2KeyLock(k string) *sync.Mutex {
	v, _ := ike2Locks.LoadOrStore(k, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func ike2FlushNotes(p *probe, s *ike2Session) {
	for _, n := range s.notes {
		p.Note("%s", n)
	}
}

func ike2Report(p *probe, s *ike2Session, err error, stage string) {
	if s != nil && s.gotResponse {
		p.Pass(StageTransport)
	}
	var f *ike2Failure
	switch {
	case errors.As(err, &f):
		if f.state == StateUnsupported {
			p.Unsupported(f.msg)
		} else {
			p.Fail(f.stage, f.state, errors.New(f.msg))
		}
	case errors.Is(err, ike2ErrNoResponse):
		where := ""
		if s != nil {
			where = " from " + netip.AddrPortFrom(s.addr, uint16(s.port)).String()
		}
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("no IKE response%s (timeout)", where))
		p.res.ErrorCode = "TIMEOUT"
	default:
		st := classifyErr(StageTransport, err)
		if st == StatePortUnreachable && s != nil {
			err = fmt.Errorf("ICMP port unreachable from %s (no IKE service)", netip.AddrPortFrom(s.addr, uint16(s.port)))
		}
		p.Fail(StageTransport, st, err)
	}
}

func ike2ResolveRedirect(ctx context.Context, target string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(target); err == nil {
		return a.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", target)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		return netip.Addr{}, err
	}
	return ips[0].Unmap(), nil
}

func ike2GWIdent(a netip.Addr) []byte {
	if a.Is4() {
		return append([]byte{1, 4}, a.AsSlice()...)
	}
	return append([]byte{2, 16}, a.AsSlice()...)
}

func ike2Digest16(s *ikeSpec, prm *ike2Params) string {
	h := sha256.New()
	for _, b := range [][]byte{[]byte(s.PSK), []byte(s.Password), []byte(s.Username), []byte(prm.eapType), []byte(strings.Join(s.IKEProposals, ","))} {
		h.Write(b)
		h.Write([]byte{0})
	}
	if prm.cert != nil {
		h.Write(prm.cert.Raw)
	}
	if prm.key != nil {
		if der, err := x509.MarshalPKCS8PrivateKey(prm.key); err == nil {
			h.Write(der)
		}
	}
	for _, ca := range prm.cas {
		h.Write(ca.Raw)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

const ike2PerHost = 2

var ike2Slots sync.Map

func ike2Acquire(ctx context.Context, key string) (func(), bool) {
	v, _ := ike2Slots.LoadOrStore(key, make(chan struct{}, ike2PerHost))
	ch := v.(chan struct{})
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	case <-ctx.Done():
		return nil, false
	}
}

func ike2LibreswanToken(t string) string {
	switch t {
	case "sha2", "sha2_256":
		return "sha256"
	case "sha2_384":
		return "sha384"
	case "sha2_512":
		return "sha512"
	case "aes_gcm", "aes_gcm128", "aes_gcm_c128", "aes_gcm16_128":
		return "aes128gcm16"
	case "aes_gcm256", "aes_gcm_c256", "aes_gcm16_256":
		return "aes256gcm16"
	case "aes_cbc", "aes128_cbc":
		return "aes128"
	case "aes256_cbc", "aes_cbc256":
		return "aes256"
	}
	if strings.HasPrefix(t, "dh") {
		if n, err := strconv.Atoi(t[2:]); err == nil {
			if tok := mcGroupToken(int64(n)); tok != "" {
				return tok
			}
		}
	}
	return t
}
