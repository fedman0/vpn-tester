package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type ocACInput struct {
	Type   string
	Name   string
	Label  string
	Value  string
	Second bool
	Opts   []ocOption
}

type ocACReply struct {
	typ     string
	authID  string
	message string
	errMsg  string
	banner  string
	action  string
	hasForm bool
	inputs  []*ocACInput
	opaque  *ocNode
	token   string
	sso     string
	certReq bool
	multi   bool
}

func ocACParse(b []byte) *ocACReply {
	t := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	if !strings.HasPrefix(t, "<?xml") && !strings.HasPrefix(t, "<config-auth") && !strings.HasPrefix(t, "<auth") {
		return nil
	}
	doc := ocParseXML(b)
	r := &ocACReply{}
	ca := doc.find("config-auth")
	var top *ocNode
	if ca != nil {
		r.typ = ca.a("type")
		top = ca
	} else if a := doc.child("auth"); a != nil {
		top = doc
	} else {
		return nil
	}
	for _, n := range top.Children {
		switch strings.ToLower(n.Name) {
		case "auth":
			r.authID = n.a("id")
			ocACParseAuth(r, n)
		case "opaque":
			r.opaque = n
		case "session-token":
			r.token = n.text()
		case "client-cert-request":
			r.certReq = true
		case "multiple-client-cert-request":
			r.multi = true
		case "error":
			if r.errMsg == "" {
				r.errMsg = ocACMsg(n)
			}
		}
	}
	if r.authID == "" && r.typ == "" && !r.certReq && !r.multi {
		return nil
	}
	return r
}

func ocACMsg(n *ocNode) string {
	s := n.deepText()
	for _, p := range []string{"param1", "param2"} {
		if v := n.a(p); v != "" && strings.Contains(s, "%s") {
			s = strings.Replace(s, "%s", v, 1)
		}
	}
	s = strings.ReplaceAll(s, "%s", "")
	return strings.TrimSpace(s)
}

func ocACParseAuth(r *ocACReply, n *ocNode) {
	for _, c := range n.Children {
		switch strings.ToLower(c.Name) {
		case "banner":
			r.banner = c.deepText()
		case "message":
			r.message = c.deepText()
		case "error":
			r.errMsg = ocACMsg(c)
		case "sso-v2-login":
			r.sso = c.text()
		case "authentication-complete":
			r.authID = "success"
		case "form":
			r.hasForm = true
			r.action = c.a("action")
			for _, in := range c.Children {
				switch strings.ToLower(in.Name) {
				case "input":
					typ := strings.ToLower(in.a("type"))
					if typ == "submit" || typ == "reset" || in.a("name") == "" {
						continue
					}
					r.inputs = append(r.inputs, &ocACInput{Type: typ, Name: in.a("name"), Label: in.a("label"), Value: in.a("value"), Second: in.a("second-auth") == "1"})
				case "select":
					inp := &ocACInput{Type: "select", Name: in.a("name"), Label: in.a("label")}
					for _, o := range in.children("option") {
						v := o.a("value")
						if v == "" {
							v = o.text()
						}
						inp.Opts = append(inp.Opts, ocOption{Value: v, Label: o.text(), Selected: o.a("selected") == "true"})
					}
					if len(inp.Opts) > 0 && inp.Name != "" {
						r.inputs = append(r.inputs, inp)
					}
				}
			}
		}
	}
}

func ocACCommon(typ string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<config-auth client="vpn" type="` + typ + `" aggregate-auth-version="2">` +
		`<version who="vpn">v9.12</version><device-id>linux-64</device-id>` +
		`<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>`
}

func ocACInitXML(groupURL, group string, certFail bool) []byte {
	var b strings.Builder
	b.WriteString(ocACCommon("init"))
	b.WriteString("<group-access>" + ocXMLEsc(groupURL) + "</group-access>")
	if certFail {
		b.WriteString("<client-cert-fail/>")
	}
	if group != "" {
		b.WriteString("<group-select>" + ocXMLEsc(group) + "</group-select>")
	}
	b.WriteString("</config-auth>\n")
	return []byte(b.String())
}

func ocACHeaders(xmlpost bool) map[string]string {
	h := map[string]string{"X-Transcend-Version": "1"}
	if xmlpost {
		h["X-Aggregate-Auth"] = "1"
	}
	return h
}

func ocAnyConnectTest(s *ocSession) {
	path := s.spec.Path
	if path == "" {
		path = "/"
	}
	orig := s.resolve(path)
	cur := orig
	xmlpost := true
	certFail := false
	var rep *ocACReply
	var resp *ocResp
	var lastErr error
	for tries := 0; tries < 6 && rep == nil; tries++ {
		var err error
		t0 := time.Now()
		if xmlpost {
			resp, err = s.do(ocReq{method: "POST", url: cur, ctype: "application/xml; charset=utf-8", body: ocACInitXML(cur.String(), s.spec.Group, certFail), headers: ocACHeaders(true)})
		} else {
			resp, err = s.do(ocReq{method: "GET", url: cur, headers: ocACHeaders(false), follow: 5})
		}
		if err != nil {
			s.failNoResponse("no response to AnyConnect auth request", err)
			return
		}
		lat := time.Since(t0)
		if xmlpost {
			if loc := resp.location(); loc != "" {
				nu, perr := cur.Parse(loc)
				if perr == nil && !strings.EqualFold(nu.Host, cur.Host) {
					cur = nu
					continue
				}
				xmlpost = false
				cur = orig
				continue
			}
		}
		rep = ocACParse(resp.Body)
		if rep == nil {
			lastErr = ocHTTPErr(resp)
			if xmlpost {
				xmlpost = false
				cur = orig
				continue
			}
			break
		}
		if rep.certReq && !certFail && rep.authID == "" {
			certFail = true
			rep = nil
			if s.pol.client == nil {
				s.p.Note("server requested a client certificate; none configured")
			}
			continue
		}
		s.handshakeOK(lat)
	}
	if rep == nil {
		if lastErr == nil {
			lastErr = errors.New("no AnyConnect auth form")
		}
		s.handshakeFail("not an AnyConnect/ocserv gateway (%s)", shortErr(lastErr))
		return
	}
	if rep.multi {
		s.p.Note("server requires multiple-certificate authentication; auth not tested")
		return
	}
	if rep.typ == "complete" || rep.authID == "success" {
		s.authOK()
		ocACLogout(s, rep)
		return
	}
	if g := ocACGroupInput(rep); g != nil && s.spec.Group != "" && xmlpost {
		want, ok := ocChooseOption(&ocField{Options: g.Opts}, s.spec.Group)
		sel, _ := ocChooseOption(&ocField{Options: g.Opts}, "")
		if ok && want != sel {
			r2, err := s.do(ocReq{method: "POST", url: resp.URL, ctype: "application/xml; charset=utf-8", body: ocACInitXML(resp.URL.String(), want, certFail), headers: ocACHeaders(true)})
			if err == nil {
				if n := ocACParse(r2.Body); n != nil {
					rep, resp = n, r2
				}
			}
		}
	}
	if rep.sso != "" && !ocACHasPassword(rep) {
		s.p.Note("server requires SSO (SAML) login; auth not tested")
		return
	}
	if !s.hasCreds() {
		if g := ocACGroupInput(rep); g != nil && s.spec.Group != "" {
			if _, ok := ocChooseOption(&ocField{Options: g.Opts}, s.spec.Group); !ok {
				s.p.Note("group %q not offered by server (available: %s)", s.spec.Group, ocOptionList(&ocField{Options: g.Opts}))
			}
		}
		s.noCreds()
		return
	}
	ocACAuth(s, rep, resp.URL, xmlpost)
}

func ocACGroupInput(r *ocACReply) *ocACInput {
	for _, in := range r.inputs {
		if in.Type == "select" && in.Name == "group_list" {
			return in
		}
	}
	return nil
}

func ocACIsUser(in *ocACInput) bool {
	n := strings.ToLower(in.Name)
	l := strings.ToLower(in.Label)
	return n == "username" || n == "user" || n == "uname" || n == "login" || n == "email" || n == "secondary_username" || strings.Contains(l, "user") || strings.Contains(l, "login")
}

func ocACAuth(s *ocSession, rep *ocACReply, at *url.URL, xmlpost bool) {
	passSent := false
	userSent := false
	groupNoted := false
	for round := 0; round < 8; round++ {
		if rep.typ == "complete" || rep.authID == "success" {
			s.authOK()
			ocACLogout(s, rep)
			return
		}
		if rep.errMsg != "" && passSent {
			s.authFail("%s%s", ocShort(rep.errMsg, 120), ocACGroupCtx(s))
			return
		}
		if rep.sso != "" && !ocACHasPassword(rep) {
			s.p.Note("server requires SSO (SAML) login; auth not tested")
			return
		}
		if len(rep.inputs) == 0 {
			if rep.errMsg != "" {
				s.authFail("%s", ocShort(rep.errMsg, 120))
				return
			}
			s.authError(fmt.Errorf("unexpected AnyConnect auth response: %s", ocShort(firstNonEmpty(rep.message, rep.authID, rep.typ), 80)))
			return
		}
		var vals [][2]string
		group := ""
		passThis := false
		for _, in := range rep.inputs {
			switch in.Type {
			case "hidden":
				vals = append(vals, [2]string{in.Name, in.Value})
			case "select":
				want := ""
				if in.Name == "group_list" {
					want = s.spec.Group
				}
				v, ok := ocChooseOption(&ocField{Options: in.Opts, Value: in.Value}, want)
				if !ok && want != "" && !groupNoted {
					groupNoted = true
					s.p.Note("group %q not offered by server (available: %s); using default", want, ocOptionList(&ocField{Options: in.Opts}))
				}
				if in.Name == "group_list" {
					group = v
				}
				vals = append(vals, [2]string{in.Name, v})
			case "text":
				if ocACIsUser(in) || len(rep.inputs) == 1 {
					vals = append(vals, [2]string{in.Name, s.spec.Username})
					userSent = true
					continue
				}
				s.p.Note("server asks for %q; auth not completed", ocShort(firstNonEmpty(in.Label, in.Name), 40))
				return
			case "password":
				n := strings.ToLower(in.Name)
				l := strings.ToLower(in.Label)
				if n == "new_password" || n == "verify_password" || n == "verify_pin" {
					if passSent {
						s.authOK()
						s.p.Note("password accepted; server requires a password change")
					} else {
						s.p.Note("server requires a password change; auth not tested")
					}
					return
				}
				if passThis || in.Second || strings.Contains(n, "secondary") || n == "answer" || n == "whichpin" || ocACLooksOTP(l) {
					if passSent {
						s.p.Note("password accepted; server requires an additional factor (%s); not tested", ocShort(firstNonEmpty(in.Label, in.Name), 40))
					} else {
						s.p.Note("server requires an additional factor (%s); auth not tested", ocShort(firstNonEmpty(in.Label, in.Name), 40))
					}
					return
				}
				if passSent {
					s.authFail("server asked for the password again (credentials rejected)%s", ocACGroupCtx(s))
					return
				}
				if s.spec.Password == "" {
					s.p.Note("server asks for a password but none is in the file; auth not tested")
					return
				}
				vals = append(vals, [2]string{in.Name, s.spec.Password})
				passThis = true
			case "sso":
				s.p.Note("server requires SSO (SAML) login; auth not tested")
				return
			}
		}
		if !passThis && !userSent && group == "" {
			s.authError(errors.New("AnyConnect form has no fields to fill"))
			return
		}
		target := at
		if rep.action != "" {
			if u, err := at.Parse(rep.action); err == nil {
				target = u
			}
		}
		var r *ocResp
		var err error
		if xmlpost {
			r, err = s.do(ocReq{method: "POST", url: target, ctype: "application/xml; charset=utf-8", body: ocACReplyXML(rep, vals, group), headers: ocACHeaders(true), stage: StageAuth})
		} else {
			r, err = s.do(ocReq{method: "POST", url: target, ctype: "application/x-www-form-urlencoded", body: []byte(ocFormEncode(vals)), headers: ocACHeaders(false), stage: StageAuth, follow: 3})
		}
		if err != nil {
			s.authError(fmt.Errorf("auth request failed: %s", shortErr(err)))
			return
		}
		if passThis {
			passSent = true
		}
		next := ocACParse(r.Body)
		if next == nil {
			if r.Status == 401 || r.Status == 403 {
				s.authFail("login rejected (HTTP %d)%s", r.Status, ocACGroupCtx(s))
				return
			}
			if wv := s.cookie("webvpn"); wv != "" && passSent {
				s.authOK()
				ocACLogout(s, &ocACReply{token: wv})
				return
			}
			s.authError(fmt.Errorf("unexpected response to AnyConnect auth reply: %s", shortErr(ocHTTPErr(r))))
			return
		}
		rep = next
		at = r.URL
	}
	s.authError(errors.New("too many AnyConnect auth rounds"))
}

func ocACGroupCtx(s *ocSession) string {
	if s.spec.Group == "" {
		return ""
	}
	return fmt.Sprintf(" (group %q)", s.spec.Group)
}

func ocACHasPassword(r *ocACReply) bool {
	for _, in := range r.inputs {
		if in.Type == "password" {
			return true
		}
	}
	return false
}

func ocACLooksOTP(l string) bool {
	for _, k := range []string{"second", "otp", "token", "passcode", "one-time", "one time", "verification", "duo", "code", "pin"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func ocACReplyXML(rep *ocACReply, vals [][2]string, group string) []byte {
	var b strings.Builder
	b.WriteString(ocACCommon("auth-reply"))
	if rep.opaque != nil {
		rep.opaque.xml(&b)
	}
	b.WriteString("<auth>")
	for _, kv := range vals {
		name := kv[0]
		switch name {
		case "group_list":
			continue
		case "answer", "whichpin", "new_password":
			name = "password"
		case "verify_pin", "verify_password":
			continue
		}
		if !ocXMLName(name) {
			continue
		}
		b.WriteString("<" + name + ">" + ocXMLEsc(kv[1]) + "</" + name + ">")
	}
	b.WriteString("</auth>")
	if group != "" {
		b.WriteString("<group-select>" + ocXMLEsc(group) + "</group-select>")
	}
	b.WriteString("</config-auth>\n")
	return []byte(b.String())
}

func ocXMLName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && (r >= '0' && r <= '9' || r == '-' || r == '.') {
			continue
		}
		return false
	}
	return true
}

func ocACLogout(s *ocSession, rep *ocACReply) {
	if s.cookie("webvpn") == "" && rep != nil && rep.token != "" {
		s.cookies["webvpn"] = rep.token
		s.order = append(s.order, "webvpn")
	}
	if s.cookie("webvpn") == "" {
		return
	}
	s.logout("/+webvpn+/webvpn_logout.html", nil)
}
