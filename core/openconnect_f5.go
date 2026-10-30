package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ocF5AppLoader = regexp.MustCompile(`(?s)appLoader\.configure\((\{.*?\})\);`)

func ocF5JSONForm(b []byte) *ocForm {
	m := ocF5AppLoader.FindSubmatch(b)
	if m == nil {
		return nil
	}
	var j struct {
		Logon struct {
			Form struct {
				ID     string `json:"id"`
				Fields []struct {
					Type  string `json:"type"`
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"fields"`
			} `json:"form"`
		} `json:"logon"`
	}
	if json.Unmarshal(m[1], &j) != nil || len(j.Logon.Form.Fields) == 0 {
		return nil
	}
	f := &ocForm{ID: firstNonEmpty(j.Logon.Form.ID, "auth_form")}
	for _, fl := range j.Logon.Form.Fields {
		f.Fields = append(f.Fields, &ocField{Tag: "input", Type: strings.ToLower(fl.Type), Name: fl.Name, Value: fl.Value})
	}
	return f
}

func ocF5Form(b []byte) *ocForm {
	forms := ocParseHTMLForms(b)
	if f := ocFindForm(forms, "auth_form"); f != nil {
		return f
	}
	if f := ocF5JSONForm(b); f != nil {
		return f
	}
	for _, f := range forms {
		if f.hasPassword() {
			return f
		}
	}
	for _, f := range forms {
		if len(f.Fields) > 0 && (f.Method == "" || f.Method == "POST") {
			return f
		}
	}
	return nil
}

func ocF5Success(s *ocSession) bool {
	return s.cookie("MRHSession") != "" && s.cookie("F5_ST") != ""
}

func ocF5Test(s *ocSession) {
	start := "/"
	if p := strings.TrimSpace(s.spec.Path); p != "" {
		start = p
	}
	t0 := time.Now()
	r, err := s.get(start, 6, StageHandshake)
	if err != nil {
		s.failNoResponse("no response from F5 logon page", err)
		return
	}
	lat := time.Since(t0)
	form := ocF5Form(r.Body)
	isF5 := strings.Contains(r.URL.Path, "/my.policy") || s.cookie("MRHSession") != "" || s.cookie("LastMRH_Session") != "" || form != nil && strings.EqualFold(form.ID, "auth_form")
	if !isF5 {
		t0 = time.Now()
		r2, err := s.get("/my.policy", 4, StageHandshake)
		if err == nil {
			lat = time.Since(t0)
			if f := ocF5Form(r2.Body); f != nil || s.cookie("MRHSession") != "" || s.cookie("LastMRH_Session") != "" {
				r, form, isF5 = r2, f, true
			}
		}
	}
	if !isF5 {
		s.handshakeFail("not an F5 BIG-IP APM logon page (%s)", shortErr(ocHTTPErr(r)))
		return
	}
	s.handshakeOK(lat)
	if ocF5Success(s) {
		s.authOK()
		s.p.Note("session established without credentials")
		ocF5Logout(s)
		return
	}
	if form == nil {
		s.p.Note("F5 logon page has no recognizable login form; auth not tested")
		return
	}
	if !s.hasCreds() {
		s.noCreds()
		return
	}
	at := r.URL
	passSent := false
	for round := 0; round < 6; round++ {
		if passSent && form.hasPassword() {
			var newPass bool
			for _, fl := range form.Fields {
				n := strings.ToLower(fl.Name)
				if fl.Type == "password" && n != "password" && !strings.HasPrefix(n, "password") {
					newPass = true
				}
			}
			if newPass {
				s.p.Note("password accepted; server requires an additional factor; not tested")
				return
			}
			s.authFail("%s", ocF5Error(r.Body))
			return
		}
		vals, _, note := ocFillHTMLForm(s, form, nil)
		if note != "" {
			s.p.Note("%s", note)
			return
		}
		if form.hasPassword() {
			passSent = true
		}
		target := at
		if form.Action != "" {
			if u, err := at.Parse(form.Action); err == nil {
				target = u
			}
		}
		if target.Path == "" || target.Path == "/" {
			target = s.resolve("/my.policy")
		}
		r, err = s.postForm(target, ocFormEncode(vals), 6, StageAuth, nil)
		if err != nil {
			s.authError(fmt.Errorf("F5 logon request failed: %s", shortErr(err)))
			return
		}
		if ocF5Success(s) {
			s.authOK()
			ocF5Logout(s)
			return
		}
		at = r.URL
		if strings.Contains(r.URL.Path, "/my.logout.php3") || strings.Contains(strings.ToLower(r.URL.RawQuery), "errorcode") {
			s.authFail("access denied by access policy (%s)", ocShort(ocStripTags(r.text()), 80))
			return
		}
		next := ocF5Form(r.Body)
		if next == nil {
			low := strings.ToLower(r.text())
			if strings.Contains(low, "/vdesk/") || strings.Contains(low, "webtop") {
				if s.cookie("MRHSession") != "" {
					s.authOK()
					ocF5Logout(s)
					return
				}
			}
			if passSent {
				s.authError(fmt.Errorf("F5 logon returned no session (%s)", shortErr(ocHTTPErr(r))))
				return
			}
			s.authError(errors.New("F5 logon flow ended without a form"))
			return
		}
		form = next
	}
	s.authError(errors.New("too many F5 logon rounds"))
}

func ocF5Error(b []byte) string {
	t := ocStripTags(string(b))
	low := strings.ToLower(t)
	for _, k := range []string{"username or password is not correct", "password is not correct", "not correct", "invalid", "failed", "denied"} {
		if i := strings.Index(low, k); i >= 0 {
			from := i - 60
			if from < 0 {
				from = 0
			}
			return ocShort(t[from:], 120)
		}
	}
	return "invalid username or password (logon page shown again)"
}

func ocF5Logout(s *ocSession) {
	s.logout("/vdesk/hangup.php3?hangup_error=1", nil)
}

func ocArrayTest(s *ocSession) {
	t0 := time.Now()
	r, err := s.get("/prx/000/http/localhost/login", 4, StageHandshake)
	if err != nil {
		s.failNoResponse("no response from Array login page", err)
		return
	}
	lat := time.Since(t0)
	if r.Status != 200 || !strings.Contains(r.URL.Path, "/prx/000/") {
		s.handshakeFail("not an Array Networks SSL VPN (GET /prx/000/http/localhost/login: %s)", shortErr(ocHTTPErr(r)))
		return
	}
	s.handshakeOK(lat)
	if n, _ := s.cookiePrefix("ANsession"); n != "" {
		delete(s.cookies, n)
	}
	if !s.hasCreds() {
		s.noCreds()
		return
	}
	body := "method=" + url.QueryEscape(s.spec.Group) + "&" + ocFormEncode([][2]string{{"uname", s.spec.Username}, {"pwd", s.spec.Password}})
	lr, err := s.postForm(s.resolve("/prx/000/http/localhost/login"), body, 4, StageAuth, nil)
	if err != nil {
		s.authError(fmt.Errorf("Array login request failed: %s", shortErr(err)))
		return
	}
	if n, _ := s.cookiePrefix("ANsession"); n != "" {
		s.authOK()
		s.logout("/prx/000/http/localhost/logout", nil)
		return
	}
	low := strings.ToLower(ocStripTags(lr.text()))
	msg := "login rejected (no ANsession cookie)"
	for _, k := range []string{"invalid", "incorrect", "failed", "denied"} {
		if i := strings.Index(low, k); i >= 0 {
			from := i - 40
			if from < 0 {
				from = 0
			}
			msg = ocShort(low[from:], 100)
			break
		}
	}
	s.authFail("%s", msg)
}
