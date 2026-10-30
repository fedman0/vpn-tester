package main

import (
	"context"
	"errors"
	"strings"
)

func ckDoc(f *vfile) map[string]any {
	if len(f.Data) == 0 || len(f.Data) > 1<<20 || !f.IsText() {
		return nil
	}
	t := strings.TrimSpace(string(pxStripJSONC(f.Data)))
	if !strings.HasPrefix(t, "{") {
		return nil
	}
	m, err := amzDecodeJSON([]byte(t))
	if err != nil {
		return nil
	}
	if ckLookup(m, "UID") == nil || ckLookup(m, "PublicKey") == nil || ckLookup(m, "ProxyMethod") == nil {
		return nil
	}
	return m
}

type CloakDetector struct{}

func (CloakDetector) Detect(f *vfile) int {
	if ckDoc(f) == nil {
		return 0
	}
	return 90
}

type CloakParser struct{}

func (CloakParser) Parse(f *vfile, fs *vfs) ([]*Config, error) {
	m := ckDoc(f)
	if m == nil {
		return nil, errors.New("not a Cloak client config")
	}
	ck, err := ckParseConfig(m, "", 0)
	name := strings.TrimSuffix(f.Name, "."+f.Ext)
	if err != nil {
		var c *Config
		if strings.Contains(err.Error(), "not supported") {
			c = unsupportedConfig(f, "Cloak", "Cloak", err.Error())
		} else {
			c = invalidConfig(f, "Cloak", err)
			c.Protocol = "Cloak"
		}
		c.Name, c.Host, c.Port = name, ck.RemoteHost, ck.RemotePort
		return []*Config{c}, nil
	}
	c := newConfig(f, "Cloak", "Cloak")
	c.Name = name
	c.Host, c.Port = ck.RemoteHost, ck.RemotePort
	c.Transport = "tcp"
	c.Security = "cloak+" + strings.ToLower(ck.EncName)
	c.SNI = ck.ServerName
	c.PublicKey = ck.publicKeyString()
	c.Extra = "cloak:" + ck.fingerprint()
	for _, n := range ck.Notes {
		c.Warn("%s", n)
	}
	c.Payload = ck
	c.Tester = cloakTester{}
	return []*Config{c}, nil
}

type cloakTester struct{}

func (cloakTester) Test(ctx context.Context, c *Config, p *probe) {
	ck, _ := c.Payload.(*ckConfig)
	if ck == nil {
		p.Fail(StageParse, StateInvalid, errors.New("missing Cloak config"))
		return
	}
	p.Engine("cloak")
	start := p.Elapsed()
	cc := ckDial(ctx, p, ck)
	if cc == nil {
		return
	}
	d := p.Elapsed() - start
	cc.Close()
	p.Pass(StageAuth)
	p.Connectable(d)
	p.DataPlaneFail(errors.New("Cloak session established; the " + ck.ProxyMethod + " service behind it is not tested"))
}

func init() {
	registerFormat(&fileFormat{Name: "Cloak", Detector: CloakDetector{}, Parser: CloakParser{}})
}
