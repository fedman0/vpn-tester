package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ocFortiTopLoc = regexp.MustCompile(`top\.location\s*=\s*"([^"]+)"`)
var ocFortiErr = regexp.MustCompile(`err=([a-z0-9_]+)`)

func ocFortinetTest(s *ocSession) {
	realm := strings.TrimSpace(s.spec.Group)
	start := "/"
	if p := strings.Trim(s.spec.Path, "/"); p != "" {
		if strings.HasPrefix(p, "remote/") {
			start = "/" + p
		} else {
			start = "/" + p
			if realm == "" {
				realm = p
			}
		}
	}
	t0 := time.Now()
	r, err := s.get(start, 5, StageHandshake)
	if err != nil {
		s.failNoResponse("no response from FortiGate login page", err)
		return
	}
	lat := time.Since(t0)
	for i := 0; i < 2; i++ {
		m := ocFortiTopLoc.FindStringSubmatch(r.text())
		if m == nil {
			break
		}
		nu, perr := r.URL.Parse(m[1])
		if perr != nil {
			break
		}
		r, err = s.do(ocReq{method: "GET", url: nu, follow: 5})
		if err != nil {
			s.handshakeFail("no response from FortiGate login page: %s", shortErr(err))
			return
		}
	}
	if realm == "" {
		realm = r.URL.Query().Get("realm")
	}
	ok := r.Status == 200 && strings.Contains(r.URL.Path, "/remote/login")
	if !ok {
		q := "/remote/login?lang=en"
		if realm != "" {
			q += "&realm=" + url.QueryEscape(realm)
		}
		t0 = time.Now()
		r2, err := s.get(q, 3, StageHandshake)
		if err != nil {
			s.handshakeFail("no response from FortiGate login page: %s", shortErr(err))
			return
		}
		lat = time.Since(t0)
		if r2.Status != 200 || !strings.Contains(r2.URL.Path, "/remote/login") {
			s.handshakeFail("not a FortiGate SSL-VPN (GET /remote/login: %s)", shortErr(ocHTTPErr(r2)))
			return
		}
	}
	s.handshakeOK(lat)
	if !s.hasCreds() {
		s.noCreds()
		return
	}
	form := ocFormEncode([][2]string{{"username", s.spec.Username}, {"credential", s.spec.Password}}) + "&realm=" + url.QueryEscape(realm) + "&ajax=1&just_logged_in=1"
	lr, err := s.postForm(s.resolve("/remote/logincheck"), form, 0, StageAuth, nil)
	if err != nil {
		s.authError(fmt.Errorf("FortiGate login request failed: %s", shortErr(err)))
		return
	}
	body := strings.TrimSpace(lr.text())
	switch {
	case s.cookie("SVPNCOOKIE") != "":
		s.authOK()
		s.logout("/remote/logout", nil)
	case strings.HasPrefix(body, "ret=") && strings.Contains(body, ",tokeninfo="):
		s.p.Note("password accepted; server requires a token code (2FA); not tested")
	case lr.Status == 401 && strings.Contains(strings.ToLower(body), "<form"):
		s.p.Note("password accepted; server requires an additional factor (HTML challenge); not tested")
	case lr.Status == 405 || strings.HasPrefix(body, "ret=0") || strings.Contains(body, "sslvpn_login_permission_denied"):
		msg := "invalid credentials"
		if m := ocFortiErr.FindStringSubmatch(body); m != nil {
			msg += " (" + m[1] + ")"
		}
		s.authFail("%s", msg)
	case strings.HasPrefix(body, "ret=1") || strings.HasPrefix(body, "ret=2"):
		s.authError(fmt.Errorf("FortiGate accepted the login but issued no session cookie (%s)", ocShort(body, 80)))
	default:
		s.authError(fmt.Errorf("unexpected FortiGate login response: %s", shortErr(ocHTTPErr(lr))))
	}
}
