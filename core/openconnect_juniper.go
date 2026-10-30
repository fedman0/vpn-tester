package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

func ocJuniperTest(s *ocSession) {
	start := "/"
	if p := strings.TrimSpace(s.spec.Path); p != "" {
		start = p
	}
	t0 := time.Now()
	r, err := s.get(start, 6, StageHandshake)
	if err != nil {
		s.failNoResponse("no response from Juniper/Pulse login page", err)
		return
	}
	lat := time.Since(t0)
	forms := ocParseHTMLForms(r.Body)
	login := ocFindForm(forms, "frmLogin", "loginForm")
	if login == nil && !strings.Contains(r.URL.Path, "/dana-na/") {
		t0 = time.Now()
		r2, err := s.get("/dana-na/auth/url_default/welcome.cgi", 4, StageHandshake)
		if err == nil {
			lat = time.Since(t0)
			r = r2
			forms = ocParseHTMLForms(r.Body)
			login = ocFindForm(forms, "frmLogin", "loginForm")
		}
	}
	if login == nil {
		if s.cookie("DSID") != "" || strings.Contains(r.URL.Path, "/dana-na/") || strings.Contains(r.URL.Path, "/dana/") {
			s.handshakeOK(lat)
			s.p.Note("Juniper/Pulse portal without a standard login form; auth not tested")
			return
		}
		s.handshakeFail("not a Juniper/Pulse SSL VPN (no frmLogin form: %s)", shortErr(ocHTTPErr(r)))
		return
	}
	s.handshakeOK(lat)
	if !s.hasCreds() {
		if f := ocJuniperRealmField(login); f != nil && s.spec.Group != "" {
			if _, ok := ocChooseOption(f, s.spec.Group); !ok {
				s.p.Note("realm %q not offered by server (available: %s)", s.spec.Group, ocOptionList(f))
			}
		}
		s.noCreds()
		return
	}
	ocJuniperLogin(s, login, r.URL)
}

func ocJuniperRealmField(f *ocForm) *ocField {
	for _, fl := range f.Fields {
		if fl.Type == "select" && (strings.EqualFold(fl.Name, "realm") || strings.Contains(strings.ToLower(fl.Name), "realm")) {
			return fl
		}
	}
	return nil
}

func ocJuniperLogin(s *ocSession, form *ocForm, at *url.URL) {
	passSent := false
	for round := 0; round < 6; round++ {
		name := strings.ToLower(firstNonEmpty(form.Name, form.ID))
		switch name {
		case "frmlogin", "loginform":
			if passSent {
				s.authFail("invalid username or password")
				return
			}
		case "frmconfirmation":
			s.authOK()
			s.p.Note("credentials accepted; server asks to confirm/close an existing session (not continued)")
			ocJuniperLogout(s)
			return
		case "frmselectroles":
			s.authOK()
			s.p.Note("credentials accepted; role selection required")
			ocJuniperLogout(s)
			return
		case "frmdefender", "frmnexttoken", "frmtotptoken":
			s.p.Note("password accepted; server requires a token code (2FA); not tested")
			return
		default:
			if passSent {
				if form.hasPassword() {
					s.authFail("invalid username or password")
				} else {
					s.authError(fmt.Errorf("unexpected Juniper form %q after login", ocShort(name, 40)))
				}
				return
			}
		}
		vals, submitName, note := ocFillHTMLForm(s, form, map[string]string{"btnSubmit": "Sign In", "submitButton": "Sign In"})
		if note != "" {
			s.p.Note("%s", note)
			return
		}
		if submitName == "" && (name == "frmlogin") {
			vals = append(vals, [2]string{"btnSubmit", "Sign In"})
		}
		target := at
		if form.Action != "" {
			if u, err := at.Parse(form.Action); err == nil {
				target = u
			}
		}
		r, err := s.postForm(target, ocFormEncode(vals), 6, StageAuth, nil)
		if err != nil {
			s.authError(fmt.Errorf("Juniper login request failed: %s", shortErr(err)))
			return
		}
		passSent = true
		if s.cookie("DSID") != "" {
			s.authOK()
			ocJuniperLogout(s)
			return
		}
		if strings.Contains(r.URL.RawQuery, "p=failed") || strings.Contains(r.URL.RawQuery, "p=user-locked") {
			msg := "invalid username or password"
			if strings.Contains(r.URL.RawQuery, "user-locked") {
				msg = "account locked"
			}
			s.authFail("%s", msg)
			return
		}
		forms := ocParseHTMLForms(r.Body)
		next := ocFindForm(forms, "frmLogin", "loginForm", "frmConfirmation", "frmSelectRoles", "frmDefender", "frmNextToken", "frmTotpToken")
		if next == nil {
			low := strings.ToLower(ocStripTags(r.text()))
			if strings.Contains(low, "invalid username or password") || strings.Contains(low, "invalid credentials") || strings.Contains(low, "authentication failed") {
				s.authFail("invalid username or password")
				return
			}
			s.authError(fmt.Errorf("Juniper login returned no session cookie (%s)", shortErr(ocHTTPErr(r))))
			return
		}
		form = next
		at = r.URL
	}
	s.authError(fmt.Errorf("too many Juniper login rounds"))
}

func ocFillHTMLForm(s *ocSession, form *ocForm, submits map[string]string) ([][2]string, string, string) {
	var vals [][2]string
	userDone, passDone := false, false
	submitName := ""
	for _, fl := range form.Fields {
		if fl.Name == "" {
			continue
		}
		n := strings.ToLower(fl.Name)
		switch fl.Type {
		case "hidden":
			vals = append(vals, [2]string{fl.Name, fl.Value})
		case "text", "email", "tel", "":
			if !userDone && (strings.Contains(n, "user") || strings.Contains(n, "login") || strings.Contains(n, "name") || strings.Contains(n, "mail")) {
				vals = append(vals, [2]string{fl.Name, s.spec.Username})
				userDone = true
			} else if !userDone {
				vals = append(vals, [2]string{fl.Name, s.spec.Username})
				userDone = true
			} else {
				vals = append(vals, [2]string{fl.Name, fl.Value})
			}
		case "password":
			if !passDone {
				vals = append(vals, [2]string{fl.Name, s.spec.Password})
				passDone = true
			} else if fl.Value != "" {
				vals = append(vals, [2]string{fl.Name, fl.Value})
			} else {
				return nil, "", fmt.Sprintf("server asks for a second password (%s); auth not tested", ocShort(fl.Name, 30))
			}
		case "select":
			want := ""
			if strings.Contains(n, "realm") || strings.Contains(n, "domain") || strings.Contains(n, "group") {
				want = s.spec.Group
			}
			v, ok := ocChooseOption(fl, want)
			if !ok && want != "" {
				s.p.Note("%s %q not offered by server (available: %s); using default", fl.Name, want, ocOptionList(fl))
			}
			vals = append(vals, [2]string{fl.Name, v})
		case "checkbox", "radio":
			if fl.Checked {
				vals = append(vals, [2]string{fl.Name, firstNonEmpty(fl.Value, "on")})
			}
		case "submit", "image":
			if submitName == "" {
				if _, ok := submits[fl.Name]; ok || len(submits) == 0 {
					submitName = fl.Name
					vals = append(vals, [2]string{fl.Name, fl.Value})
				}
			}
		}
	}
	return vals, submitName, ""
}

func ocJuniperLogout(s *ocSession) {
	s.logout("/dana-na/auth/logout.cgi", nil)
}
