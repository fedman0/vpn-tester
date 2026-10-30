package main

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ocGPResult struct {
	kind     string
	status   string
	msg      string
	saml     bool
	doc      *ocNode
	jsStatus string
	jsMsg    string
}

var ocGPRespStatus = regexp.MustCompile(`respStatus\s*=\s*"([^"]*)"`)
var ocGPRespMsg = regexp.MustCompile(`respMsg\s*=\s*"((?:[^"\\]|\\.)*)"`)

func ocGPParse(r *ocResp) *ocGPResult {
	body := r.Body
	res := &ocGPResult{}
	t := strings.TrimSpace(string(body))
	if m := ocGPRespStatus.FindStringSubmatch(t); m != nil {
		res.kind = "js"
		res.jsStatus = m[1]
		if mm := ocGPRespMsg.FindStringSubmatch(t); mm != nil {
			res.jsMsg = strings.NewReplacer(`\n`, " ", `\"`, `"`, `\'`, "'").Replace(mm[1])
		}
		return res
	}
	if !strings.HasPrefix(t, "<") {
		return res
	}
	doc := ocParseXML(body)
	for _, n := range doc.Children {
		if n.Name == "#comment" || n.Name == "" {
			continue
		}
		res.doc = n
		res.kind = strings.ToLower(n.Name)
		break
	}
	switch res.kind {
	case "prelogin-response":
		res.status = res.doc.childText("status")
		res.msg = res.doc.childText("msg")
		res.saml = res.doc.childText("saml-auth-method") != "" && res.doc.childText("saml-request") != ""
	case "response":
		res.status = res.doc.a("status")
		res.msg = res.doc.childText("error")
	case "challenge":
		res.msg = res.doc.childText("respmsg")
	case "html":
		bt := ocStripTags(t)
		if m := ocGPRespStatus.FindStringSubmatch(bt); m != nil {
			res.kind = "js"
			res.jsStatus = m[1]
			if mm := ocGPRespMsg.FindStringSubmatch(bt); mm != nil {
				res.jsMsg = mm[1]
			}
		}
	}
	return res
}

func ocGPForm(s *ocSession) [][2]string {
	return [][2]string{
		{"jnlpReady", "jnlpReady"}, {"ok", "Login"}, {"direct", "yes"}, {"clientVer", "4100"}, {"prot", "https:"}, {"internal", "no"},
		{"ipv6-support", "yes"}, {"clientos", "Linux"}, {"os-version", "linux-64"}, {"server", s.spec.Host}, {"computer", "vpntester"},
		{"user", s.spec.Username}, {"passwd", s.spec.Password},
	}
}

func ocGPTest(s *ocSession) {
	s.ua = "PAN GlobalProtect"
	p := strings.ToLower(strings.Trim(s.spec.Path, "/"))
	g := strings.ToLower(strings.TrimSpace(s.spec.Group))
	order := []string{"global-protect", "ssl-vpn"}
	switch {
	case strings.HasPrefix(p, "global-protect") || p == "portal" || g == "portal":
		order = []string{"global-protect"}
	case strings.HasPrefix(p, "ssl-vpn") || p == "gateway" || g == "gateway":
		order = []string{"ssl-vpn"}
	}
	iface := ""
	var pre *ocGPResult
	var lastErr error
	for _, pfx := range order {
		t0 := time.Now()
		r, err := s.postForm(s.resolve("/"+pfx+"/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux"), "", 3, StageHandshake, nil)
		if err != nil {
			s.failNoResponse("no response to GlobalProtect prelogin", err)
			return
		}
		lat := time.Since(t0)
		res := ocGPParse(r)
		if res.kind != "prelogin-response" {
			lastErr = ocHTTPErr(r)
			continue
		}
		if !strings.EqualFold(res.status, "Success") && strings.Contains(strings.ToLower(res.msg), "does not exist") {
			lastErr = errors.New(res.msg)
			continue
		}
		s.handshakeOK(lat)
		iface, pre = pfx, res
		break
	}
	if iface == "" {
		if lastErr == nil {
			lastErr = errors.New("no prelogin response")
		}
		s.handshakeFail("not a GlobalProtect portal or gateway (%s)", shortErr(lastErr))
		return
	}
	kind := "portal"
	if iface == "ssl-vpn" {
		kind = "gateway"
	}
	if !strings.EqualFold(pre.status, "Success") {
		s.p.Note("GlobalProtect %s prelogin: %s; auth not tested", kind, ocShort(firstNonEmpty(pre.msg, pre.status), 80))
		return
	}
	if pre.saml {
		s.p.Note("GlobalProtect %s requires SAML login; auth not tested", kind)
		return
	}
	if !s.hasCreds() {
		s.noCreds()
		return
	}
	target := "/global-protect/getconfig.esp"
	if kind == "gateway" {
		target = "/ssl-vpn/login.esp"
	}
	r, err := s.postForm(s.resolve(target), ocFormEncode(ocGPForm(s)), 0, StageAuth, nil)
	if err != nil {
		s.authError(fmt.Errorf("GlobalProtect login request failed: %s", shortErr(err)))
		return
	}
	if r.Status == 512 {
		s.authFail("invalid username or password")
		return
	}
	res := ocGPParse(r)
	switch {
	case kind == "portal" && res.kind == "policy":
		s.authOK()
		if gws := res.doc.find("gateways"); gws != nil {
			n := 0
			for _, l := range ocFindAll(gws, "list") {
				n += len(l.children("entry"))
			}
			if n > 0 {
				s.p.Note("portal login ok, %d gateway(s) offered", n)
			}
		}
	case kind == "gateway" && res.kind == "jnlp":
		args := ocGPJnlpArgs(res.doc)
		if len(args) < 5 || args[1] == "" || args[1] == "(null)" {
			s.authError(errors.New("GlobalProtect login response has no auth cookie"))
			return
		}
		s.authOK()
		ocGPLogout(s, args)
	case res.kind == "challenge" || res.kind == "js" && strings.EqualFold(res.jsStatus, "Challenge"):
		s.p.Note("password accepted; server requires an additional factor (%s); not tested", ocShort(firstNonEmpty(res.msg, res.jsMsg, "challenge"), 60))
	case res.kind == "js" && strings.EqualFold(res.jsStatus, "Error"):
		s.authFail("%s", ocShort(firstNonEmpty(res.jsMsg, "login failed"), 120))
	case res.kind == "response" && strings.EqualFold(res.status, "error"):
		s.authFail("%s", ocShort(firstNonEmpty(res.msg, "login failed"), 120))
	case strings.Contains(strings.ToLower(r.text()), "invalid username or password") || strings.Contains(strings.ToLower(r.text()), "authentication failed"):
		s.authFail("%s", ocShort(ocStripTags(r.text()), 120))
	default:
		s.authError(fmt.Errorf("unexpected GlobalProtect login response: %s", shortErr(ocHTTPErr(r))))
	}
}

func ocGPJnlpArgs(doc *ocNode) []string {
	ad := doc.find("application-desc")
	if ad == nil {
		return nil
	}
	var out []string
	for _, a := range ad.children("argument") {
		v := a.text()
		if u, err := url.QueryUnescape(v); err == nil {
			v = u
		}
		out = append(out, v)
	}
	return out
}

func ocGPLogout(s *ocSession, args []string) {
	get := func(i int) string {
		if i < len(args) && args[i] != "(null)" && args[i] != "-1" {
			return args[i]
		}
		return ""
	}
	kv := [][2]string{{"authcookie", get(1)}, {"portal", get(3)}, {"user", get(4)}, {"domain", get(7)}}
	if ip := get(15); ip != "" {
		kv = append(kv, [2]string{"preferred-ip", ip})
	}
	kv = append(kv, [2]string{"computer", "vpntester"})
	body := []byte(ocFormEncode(kv))
	s.logout("/ssl-vpn/logout.esp", func(r *ocReq) {
		r.method = "POST"
		r.ctype = "application/x-www-form-urlencoded"
		r.body = body
	})
}
