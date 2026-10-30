package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

func (s *ike2Session) signedOctets(initiator bool, idBody []byte) []byte {
	if initiator {
		m := ike2Mac(s.keys.prf, s.keys.skpi, idBody)
		return append(append(append([]byte{}, s.initReq...), s.nr...), m...)
	}
	m := ike2Mac(s.keys.prf, s.keys.skpr, idBody)
	return append(append(append([]byte{}, s.initResp...), s.ni...), m...)
}

func (s *ike2Session) sharedKeyAuth(key []byte, initiator bool, idBody []byte) []byte {
	k := ike2Mac(s.keys.prf, key, []byte("Key Pad for IKEv2"))
	return ike2Mac(s.keys.prf, k, s.signedOctets(initiator, idBody))
}

func ike2CertReq(cas []*x509.Certificate) []byte {
	b := []byte{4}
	for _, c := range cas {
		if !c.IsCA {
			continue
		}
		h := sha1.Sum(c.RawSubjectPublicKeyInfo)
		b = append(b, h[:]...)
	}
	return b
}

func (s *ike2Session) childPayloads(prm *ike2Params) []ike2P {
	cp := []byte{1, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0}
	if s.childless {
		return []ike2P{{t: ike2PCP, body: cp}}
	}
	props := prm.esp
	if len(props) == 0 {
		props = ike2DefaultESP()
	}
	spi := ike2Random(4)
	out := make([]ike2Proposal, len(props))
	for i, p := range props {
		p.spi = spi
		p.proto = 3
		out[i] = p
	}
	ts := []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
	return []ike2P{{t: ike2PCP, body: cp}, {t: ike2PSA, body: ike2EncodeSA(out)}, {t: ike2PTSi, body: ts}, {t: ike2PTSr, body: ts}}
}

func (s *ike2Session) netErr(err error, what string) error {
	if errors.Is(err, ike2ErrNoResponse) {
		return ike2Fail(StageAuth, StateHandshakeFailed, "no response to %s (timeout)", what)
	}
	var f *ike2Failure
	if errors.As(err, &f) {
		return err
	}
	return ike2Fail(StageAuth, classifyErr(StageTransport, err), "%s: %s", what, shortErr(err))
}

func (s *ike2Session) checkResponse(resp []ike2P, eap *ike2EAP) error {
	if _, ok := ike2FindNotify(resp, ike2NAuthFailed); ok {
		s.authRejected = true
		msg := "AUTHENTICATION_FAILED"
		if eap != nil && eap.failure != "" {
			msg += ": " + eap.failure
		}
		return ike2Fail(StageAuth, StateAuthFailed, "%s", msg)
	}
	if ike2Find(resp, ike2PAuth) != nil || ike2Find(resp, ike2PEAP) != nil {
		return nil
	}
	if n, ok := ike2ErrorNotify(resp); ok {
		s.authRejected = true
		if n.typ == 46 {
			return ike2Fail(StageAuth, StateAuthFailed, "AUTHORIZATION_FAILED")
		}
		return ike2Fail(StageAuth, StateHandshakeFailed, "IKE_AUTH rejected: %s", ike2NotifyName(n.typ))
	}
	return ike2Fail(StageAuth, StateHandshakeFailed, "IKE_AUTH response without AUTH payload")
}

func (s *ike2Session) childNotes(resp []ike2P) {
	for _, n := range ike2Notifies(resp) {
		if n.typ < 16384 && n.typ != ike2NAuthFailed {
			s.note("CHILD_SA: %s", ike2NotifyName(n.typ))
		}
	}
	if s.childless {
		s.note("childless IKE SA (RFC 6023)")
	} else if ike2Find(resp, ike2PSA) != nil {
		s.note("CHILD_SA accepted")
	}
	if cp := ike2Find(resp, ike2PCP); len(cp) >= 4 && cp[0] == 2 {
		a := cp[4:]
		for len(a) >= 4 {
			t := int(a[0]&0x7f)<<8 | int(a[1])
			l := int(a[2])<<8 | int(a[3])
			if 4+l > len(a) {
				break
			}
			if t == 1 && l >= 4 {
				s.note("virtual IP %d.%d.%d.%d", a[4], a[5], a[6], a[7])
			}
			a = a[4+l:]
		}
	}
	if n, ok := ike2FindNotify(resp, ike2NRedirect); ok {
		if t := ike2RedirectTarget(n.data); t != "" {
			s.note("responder redirects clients to %s", t)
		}
	}
}

func (s *ike2Session) verifyResponder(prm *ike2Params, resp []ike2P, authBody []byte, sharedKey []byte, what string) error {
	if len(authBody) < 5 {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "malformed responder AUTH payload")
	}
	if s.idr == nil {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "responder sent no IDr")
	}
	method := authBody[0]
	data := authBody[4:]
	idr := ike2IDFromBody(s.idr)
	want, hasWant := prm.remoteID()
	if method == 2 {
		if hasWant && what != "EAP" && !ike2IDMatch(want, idr) {
			return ike2TrustFail("server identity mismatch: expected %s, got %s", want.text, idr.text)
		}
		if sharedKey == nil {
			s.note("responder uses PSK authentication (not verifiable without key)")
			return nil
		}
		want := s.sharedKeyAuth(sharedKey, false, s.idr)
		if !hmac.Equal(want, data) {
			if what == "psk" {
				return ike2Fail(StageAuth, StateAuthFailed, "responder AUTH does not match the pre-shared key")
			}
			return ike2Fail(StageHandshake, StateHandshakeFailed, "responder %s AUTH invalid", what)
		}
		return nil
	}
	var certs []*x509.Certificate
	for _, cb := range ike2FindAll(resp, ike2PCert) {
		if len(cb) < 2 || cb[0] != 4 {
			continue
		}
		if c, err := x509.ParseCertificate(cb[1:]); err == nil {
			certs = append(certs, c)
		}
	}
	var leaf *x509.Certificate
	octets := s.signedOctets(false, s.idr)
	if len(certs) > 0 {
		leaf = certs[0]
		if err := ike2VerifySig(leaf.PublicKey, method, data, octets); err != nil {
			return ike2Fail(StageHandshake, StateHandshakeFailed, "responder AUTH signature invalid: %v", err)
		}
	} else {
		for _, c := range prm.cas {
			if ike2VerifySig(c.PublicKey, method, data, octets) == nil {
				leaf = c
				break
			}
		}
		if leaf == nil {
			if len(prm.cas) == 0 {
				s.note("responder sent no certificate; signature not verifiable")
				return nil
			}
			return ike2TrustFail("server certificate not trusted: responder sent no certificate and no configured certificate verifies its AUTH")
		}
		certs = []*x509.Certificate{leaf}
	}
	if hasWant && !ike2IDMatch(want, idr) && !ike2CertHasID(leaf, want) {
		return ike2TrustFail("server identity mismatch: expected %s, got %s", want.text, idr.text)
	}
	if !ike2CertHasID(leaf, idr) {
		s.note("server certificate does not contain its identity %s", idr.text)
	}
	if len(prm.cas) > 0 {
		if err := ike2VerifyChain(leaf, certs[1:], prm.cas); err != nil {
			return ike2TrustFail("server certificate not trusted: %s", ike2ErrText(err))
		}
		s.note("server certificate %q verified", leaf.Subject.CommonName)
	} else {
		ip := x509.NewCertPool()
		for _, c := range certs[1:] {
			ip.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: ip, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			s.note("server certificate %q verified against system CAs", leaf.Subject.CommonName)
		} else {
			s.note("server certificate %q not verified (no CA in config)", leaf.Subject.CommonName)
		}
	}
	if _, ok := prm.remoteID(); !ok && prm.spec.Host != "" {
		hid, _ := ike2ParseID(prm.spec.Host)
		if hid.typ != 0 && !ike2CertHasID(leaf, hid) && !ike2IDMatch(hid, idr) {
			s.note("server certificate does not match host %s", prm.spec.Host)
		}
	}
	return nil
}

func (s *ike2Session) authenticate(ctx context.Context, prm *ike2Params) error {
	rounds := prm.rounds()
	idi := prm.localID(rounds[0], s)
	ps := []ike2P{{t: ike2PIDi, body: idi.body()}}
	if rounds[0] == "pubkey" {
		ps = append(ps, ike2P{t: ike2PCert, body: append([]byte{4}, prm.cert.Raw...)})
		for _, c := range prm.chain {
			ps = append(ps, ike2P{t: ike2PCert, body: append([]byte{4}, c...)})
		}
	}
	ps = append(ps, ike2P{t: ike2PCertReq, body: ike2CertReq(prm.cas)})
	if rid, ok := prm.remoteID(); ok {
		ps = append(ps, ike2P{t: ike2PIDr, body: rid.body()})
	}
	switch rounds[0] {
	case "psk":
		ps = append(ps, ike2P{t: ike2PAuth, body: append([]byte{2, 0, 0, 0}, s.sharedKeyAuth([]byte(prm.spec.PSK), true, idi.body())...)})
	case "pubkey":
		method, sig, err := ike2Sign(prm.key, s.signedOctets(true, idi.body()), s.sigHashes)
		if err != nil {
			return ike2Fail(StageAuth, StateAuthFailed, "signing AUTH failed: %v", err)
		}
		ps = append(ps, ike2P{t: ike2PAuth, body: append([]byte{method, 0, 0, 0}, sig...)})
	}
	if len(rounds) > 1 {
		if !s.multiAuth {
			return ike2Fail(StageAuth, StateHandshakeFailed, "responder does not support multiple authentication rounds")
		}
		ps = append(ps, ike2Notify(ike2NMultipleAuth, nil), ike2Notify(ike2NAnotherAuth, nil))
	}
	ps = append(ps, s.childPayloads(prm)...)
	resp, err := s.exchange(ctx, ike2ExAuth, ps)
	if err != nil {
		return s.netErr(err, "IKE_AUTH")
	}
	if err := s.checkResponse(resp, nil); err != nil {
		return err
	}
	if b := ike2Find(resp, ike2PIDr); b != nil {
		s.idr = append([]byte(nil), b...)
	}
	verified := false
	if a := ike2Find(resp, ike2PAuth); a != nil {
		var key []byte
		if rounds[0] == "psk" || rounds[0] == "eap" && prm.spec.PSK != "" {
			key = []byte(prm.spec.PSK)
		}
		if err := s.verifyResponder(prm, resp, a, key, rounds[0]); err != nil {
			return err
		}
		verified = true
	}
	for i, r := range rounds {
		if i > 0 {
			id2 := prm.eapIdentityID(s)
			resp, err = s.exchange(ctx, ike2ExAuth, []ike2P{{t: ike2PIDi, body: id2.body()}})
			if err != nil {
				return s.netErr(err, "IKE_AUTH")
			}
			if err := s.checkResponse(resp, nil); err != nil {
				return err
			}
			idi = id2
		}
		if r != "eap" {
			continue
		}
		if !verified && ike2Find(resp, ike2PAuth) == nil && ike2Find(resp, ike2PEAP) != nil && len(prm.cas) > 0 {
			s.note("responder did not authenticate before EAP")
		}
		if prm.eapType == "ttls" || prm.eapType == "peap" {
			return &ike2CannotErr{msg: ike2EAPLabel(prm.eapType) + " is not implemented"}
		}
		if !prm.hasEAPCreds() {
			return ike2ErrNoCreds
		}
		resp, err = s.eapRound(ctx, prm, resp, idi.body())
		if err != nil {
			return err
		}
		verified = true
	}
	if !verified {
		return ike2Fail(StageHandshake, StateHandshakeFailed, "responder did not authenticate")
	}
	s.childNotes(resp)
	s.established = true
	return nil
}

var ike2ErrNoCreds = errors.New("no credentials")

func (s *ike2Session) eapRound(ctx context.Context, prm *ike2Params, resp []ike2P, idiBody []byte) ([]ike2P, error) {
	e := prm.newEAP()
	if e.tls != nil {
		defer e.tls.close()
	}
	var err error
	for {
		pkt := ike2Find(resp, ike2PEAP)
		if pkt == nil {
			if err := s.checkResponse(resp, e); err != nil {
				return nil, err
			}
			return nil, ike2Fail(StageAuth, StateHandshakeFailed, "EAP payload missing in IKE_AUTH response")
		}
		out, st, perr := e.process(pkt)
		if perr != nil {
			var f *ike2Failure
			if errors.As(perr, &f) {
				return nil, perr
			}
		}
		switch st {
		case ike2EAPCannot:
			return nil, &ike2CannotErr{msg: shortErr(perr)}
		case ike2EAPDoneFail:
			s.authRejected = true
			msg := e.failure
			if msg == "" && perr != nil {
				msg = shortErr(perr)
			}
			if msg == "" {
				msg = "EAP failure"
			}
			if e.nakSent && e.used == 0 {
				msg = fmt.Sprintf("EAP method negotiation failed (server wanted %s)", ike2EAPName(e.requested))
			}
			return nil, ike2Fail(StageAuth, StateAuthFailed, "%s", msg)
		case ike2EAPDoneOK:
			key := e.msk
			if len(key) == 0 {
				key = s.keys.skpi
			}
			resp, err = s.exchange(ctx, ike2ExAuth, []ike2P{{t: ike2PAuth, body: append([]byte{2, 0, 0, 0}, s.sharedKeyAuth(key, true, idiBody)...)}})
			if err != nil {
				return nil, s.netErr(err, "IKE_AUTH (final AUTH)")
			}
			if err := s.checkResponse(resp, e); err != nil {
				return nil, err
			}
			a := ike2Find(resp, ike2PAuth)
			if a == nil {
				return nil, ike2Fail(StageAuth, StateHandshakeFailed, "responder sent no AUTH after EAP")
			}
			rkey := e.msk
			if len(rkey) == 0 {
				rkey = s.keys.skpr
			}
			if err := s.verifyResponder(prm, resp, a, rkey, "EAP"); err != nil {
				return nil, err
			}
			if e.used != 0 {
				s.note("%s ok", ike2EAPName(e.used))
			}
			return resp, nil
		}
		resp, err = s.exchange(ctx, ike2ExAuth, []ike2P{{t: ike2PEAP, body: out}})
		if err != nil {
			return nil, s.netErr(err, "IKE_AUTH (EAP)")
		}
		if _, ok := ike2FindNotify(resp, ike2NAuthFailed); ok && ike2Find(resp, ike2PEAP) == nil {
			return nil, s.checkResponse(resp, e)
		}
	}
}

type ike2CannotErr struct {
	msg string
}

func (e *ike2CannotErr) Error() string { return e.msg }

func ike2AuthLabel(prm *ike2Params) string {
	switch prm.auth {
	case "psk":
		return "PSK"
	case "pubkey":
		return "cert"
	case "pubkey+eap":
		return "cert+" + ike2EAPLabel(prm.eapType)
	case "eap":
		return ike2EAPLabel(prm.eapType)
	}
	return strings.ToUpper(prm.auth)
}

func ike2EAPLabel(t string) string {
	switch t {
	case "mschapv2":
		return "EAP-MSCHAPv2"
	case "md5":
		return "EAP-MD5"
	case "gtc":
		return "EAP-GTC"
	case "tls":
		return "EAP-TLS"
	case "ttls":
		return "EAP-TTLS"
	case "peap":
		return "PEAP"
	}
	return "EAP"
}

func ike2TrustFail(format string, args ...any) error {
	return &ike2Failure{stage: StageHandshake, state: StateHandshakeFailed, msg: fmt.Sprintf(format, args...), trust: true}
}
