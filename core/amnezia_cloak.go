package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const amzCloakProto = "OpenVPN over Cloak"

type amzCloakPayload struct {
	ck   *ckConfig
	ovpn *Config
}

type amzCloakValidator struct{}

func (amzCloakValidator) Validate(c *Config) error {
	pl, _ := c.Payload.(*amzCloakPayload)
	if pl == nil || pl.ck == nil || pl.ovpn == nil {
		return errors.New("missing Cloak/OpenVPN config")
	}
	if pl.ovpn.Validator != nil {
		if err := pl.ovpn.Validator.Validate(pl.ovpn); err != nil {
			return fmt.Errorf("OpenVPN: %v", err)
		}
	}
	return nil
}

type amzCloakTester struct{}

func (amzCloakTester) Test(ctx context.Context, c *Config, p *probe) {
	pl, _ := c.Payload.(*amzCloakPayload)
	if pl == nil || pl.ck == nil || pl.ovpn == nil {
		p.Fail(StageParse, StateInvalid, errors.New("missing Cloak/OpenVPN config"))
		return
	}
	p.Engine("cloak+mihomo-openvpn")
	var last *ckConn
	dial := ovpnStreamDialer(func(dctx context.Context, isp *probe, r ovpnRemote) net.Conn {
		cc := ckDial(dctx, p, pl.ck)
		if cc == nil {
			isp.Fail(StageHandshake, p.res.Result, errors.New(p.res.ErrorMessage))
			return nil
		}
		last = cc
		return cc
	})
	sp := newProbe(p.opt, pl.ovpn)
	sp.ctx = ctx
	sp.res.ID = p.res.ID
	sp.Pass(StageParse)
	OpenVpnConnectivityTester{}.Test(context.WithValue(ctx, ovpnStreamDialerKey{}, dial), pl.ovpn, sp)
	if p.failed {
		return
	}
	r := sp.res
	if r.Note != "" {
		p.Note("%s", r.Note)
	}
	switch r.Result {
	case StateConnectable, StateDataPlaneVerified:
		if r.Stages.Authentication != nil && *r.Stages.Authentication {
			p.Pass(StageAuth)
		}
		p.Connectable(sp.latency)
		if r.Stages.DataPlane != nil {
			if *r.Stages.DataPlane {
				p.DataPlaneOK(sp.latency)
			} else {
				p.DataPlaneFail(nil)
			}
		}
		return
	case StateUnsupported:
		p.Unsupported(r.ErrorMessage)
		return
	case StateInvalid:
		p.Fail(StageParse, StateInvalid, errors.New(r.ErrorMessage))
		return
	}
	msg := firstNonEmpty(r.ErrorMessage, "failed")
	if strings.Contains(msg, "key method") && strings.Contains(msg, "EOF") {
		msg = "server closed the session right after the TLS handshake (client certificate rejected or revoked)"
	}
	state := StateAuthFailed
	if last == nil {
		state = StateHandshakeFailed
	} else if last.got.Load() == 0 && last.peerFin.Load() {
		state = StateHandshakeFailed
		msg = "Cloak accepted the session but closed the OpenVPN stream (its OpenVPN backend is down or ProxyMethod is not routed)"
	}
	p.Fail(StageAuth, state, errors.New("OpenVPN: "+msg))
	if r.ErrorCode == "TIMEOUT" {
		p.res.ErrorCode = "TIMEOUT"
	}
}

func (b *amzBuilder) cloak(ci int, cont map[string]any, label, host string) {
	_, ckProto := amzProtoKey(cont, "cloak")
	n := amzLastConfig(ckProto)
	if n == nil || len(n.lc) == 0 {
		b.noClient(ci, amzCloakProto, label)
		return
	}
	defPort, _ := strconv.Atoi(amzStr(ckProto, "port"))
	ck, err := ckParseConfig(n.lc, host, defPort)
	ch := b.child(ci, "cloak", "cloak.json", n.text)
	if err != nil {
		var c *Config
		if strings.Contains(err.Error(), "not supported") {
			c = unsupportedConfig(ch, "AmneziaVPN", amzCloakProto, err.Error())
		} else {
			c = invalidConfig(ch, "AmneziaVPN", err)
			c.Protocol = amzCloakProto
		}
		c.Name, c.Host, c.Port = label, ck.RemoteHost, ck.RemotePort
		b.add(ci, c)
		return
	}
	_, ovProto := amzProtoKey(cont, "openvpn")
	on := amzLastConfig(ovProto)
	if on == nil || strings.TrimSpace(on.text) == "" {
		b.noClient(ci, amzCloakProto, label)
		return
	}
	och := b.child(ci, "openvpn", "openvpn-cloak.ovpn", amzSubst(on.text, b.doc))
	cs, _ := parseAs("OpenVPN", och, b.fs)
	if len(cs) == 0 {
		b.noClient(ci, amzCloakProto, label)
		return
	}
	b.add(ci, amzCloakConfig(ch, cs[0], ck, label))
}

func amzCloakConfig(ch *vfile, inner *Config, ck *ckConfig, label string) *Config {
	m, _ := inner.Payload.(*ovpnModel)
	if inner.Status != StateParsed || m == nil || len(m.Remotes) == 0 {
		inner.Format, inner.Protocol, inner.Name = "AmneziaVPN", amzCloakProto, label
		inner.Host, inner.Port = ck.RemoteHost, ck.RemotePort
		if inner.Status == StateParsed {
			inner.Status, inner.Error = StateInvalid, "OpenVPN part has no remote"
			inner.Tester, inner.Validator, inner.Payload = nil, nil, nil
		}
		return inner
	}
	r := m.Remotes[0]
	r.Proto, r.Family, r.Proxy = "tcp", "", nil
	m.Remotes = []ovpnRemote{r}
	m.RemoteRandom = false
	c := newConfig(ch, "AmneziaVPN", amzCloakProto)
	c.Name = label
	c.Host, c.Port = ck.RemoteHost, ck.RemotePort
	c.Transport = "tcp"
	c.Security = "cloak+" + strings.ToLower(firstNonEmpty(ck.EncName, "plain"))
	c.SNI = ck.ServerName
	c.PublicKey = ck.publicKeyString()
	c.Username, c.Password = inner.Username, inner.Password
	h := sha256.Sum256([]byte(ck.fingerprint() + "\x00" + inner.Extra + "\x00" + inner.Username + "\x00" + inner.Password))
	c.Extra = "cloak:" + hex.EncodeToString(h[:10])
	c.Certificates = inner.Certificates
	c.Dependencies = inner.Dependencies
	for _, w := range inner.Warnings {
		lw := strings.ToLower(w)
		if strings.Contains(lw, "proxy") || strings.Contains(lw, "remote-random") {
			continue
		}
		c.Warn("%s", w)
	}
	for _, n := range ck.Notes {
		c.Warn("%s", n)
	}
	if ck.ProxyMethod != "openvpn" {
		c.Warn("Cloak ProxyMethod is %q; Amnezia uses \"openvpn\" for this container", ck.ProxyMethod)
	}
	c.Payload = &amzCloakPayload{ck: ck, ovpn: inner}
	c.Validator = amzCloakValidator{}
	c.Tester = amzCloakTester{}
	return c
}
