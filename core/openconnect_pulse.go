package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	ocVendorJuniper    = 0xa4c
	ocVendorJuniper2   = 0x583
	ocVendorTCG        = 0x5597
	ocIFTVersionReq    = 1
	ocIFTVersionResp   = 2
	ocIFTAuthChallenge = 5
	ocIFTAuthResponse  = 6
	ocIFTAuthSuccess   = 7
	ocJuniper1         = ocVendorJuniper<<8 | 1
	ocExpandedJuniper  = 0xfe<<24 | ocVendorJuniper
	ocEAPRequest       = 1
	ocEAPResponse      = 2
	ocEAPSuccess       = 3
	ocEAPTypeIdentity  = 1
	ocEAPTypeGTC       = 6
	ocEAPTypeTTLS      = 0x15
	ocEAPTypeExpanded  = 0xfe
	ocAVPEAPMessage    = 79
	ocAVPVendorFlag    = 0x80
	ocAVPMandatory     = 0x40
	ocJ2PassReq        = 0x01
	ocJ2PassRetry      = 0x81
	ocJ2PassChange     = 0x43
	ocJ2PassFail       = 0xc5
)

type ocIFT struct {
	c   net.Conn
	br  *bufio.Reader
	seq uint32
}

func (t *ocIFT) send(vendor, typ uint32, payload []byte) error {
	b := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint32(b[0:], vendor)
	binary.BigEndian.PutUint32(b[4:], typ)
	binary.BigEndian.PutUint32(b[8:], uint32(len(b)))
	binary.BigEndian.PutUint32(b[12:], t.seq)
	t.seq++
	copy(b[16:], payload)
	_, err := t.c.Write(b)
	return err
}

func (t *ocIFT) recv() (uint32, uint32, []byte, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(t.br, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[8:])
	if n < 16 || n > 1<<20 {
		return 0, 0, nil, fmt.Errorf("invalid IF-T/TLS packet length %d", n)
	}
	payload := make([]byte, n-16)
	if _, err := io.ReadFull(t.br, payload); err != nil {
		return 0, 0, nil, err
	}
	return binary.BigEndian.Uint32(hdr[0:]) & 0xffffff, binary.BigEndian.Uint32(hdr[4:]), payload, nil
}

type ocAVP struct {
	code   uint32
	vendor uint32
	flags  byte
	data   []byte
}

func ocParseAVPs(b []byte) ([]ocAVP, error) {
	var out []ocAVP
	for len(b) > 0 {
		if len(b) < 8 {
			return out, errors.New("truncated AVP")
		}
		code := binary.BigEndian.Uint32(b)
		flags := b[4]
		ln := int(binary.BigEndian.Uint32(b[4:]) & 0xffffff)
		if ln < 8 || ln > len(b) {
			return out, errors.New("invalid AVP length")
		}
		hdr := 8
		var vendor uint32
		if flags&ocAVPVendorFlag != 0 {
			if ln < 12 {
				return out, errors.New("invalid vendor AVP")
			}
			vendor = binary.BigEndian.Uint32(b[8:])
			hdr = 12
		}
		out = append(out, ocAVP{code: code, vendor: vendor, flags: flags, data: b[hdr:ln]})
		adv := (ln + 3) &^ 3
		if adv > len(b) {
			adv = len(b)
		}
		b = b[adv:]
	}
	return out, nil
}

func ocAppendAVP(b []byte, code uint32, data []byte) []byte {
	var h [12]byte
	binary.BigEndian.PutUint32(h[0:], code)
	binary.BigEndian.PutUint16(h[4:], 0x8000)
	binary.BigEndian.PutUint16(h[6:], uint16(len(data)+12))
	binary.BigEndian.PutUint32(h[8:], ocVendorJuniper2)
	b = append(b, h[:]...)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func ocEAPExpanded(code, ident byte, subtype uint32, body []byte) []byte {
	b := make([]byte, 12, 12+len(body))
	b[0], b[1] = code, ident
	binary.BigEndian.PutUint32(b[4:], ocExpandedJuniper)
	binary.BigEndian.PutUint32(b[8:], subtype)
	b = append(b, body...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func ocJ1Response(ident byte, avps []byte) []byte {
	p := make([]byte, 4, 4+12+len(avps))
	binary.BigEndian.PutUint32(p, ocJuniper1)
	return append(p, ocEAPExpanded(ocEAPResponse, ident, 1, avps)...)
}

func ocPulseTest(s *ocSession) {
	if !s.connect() {
		return
	}
	s.mu.Lock()
	conn := s.first
	s.first = nil
	s.mu.Unlock()
	if conn == nil {
		s.handshakeFail("internal: no connection")
		return
	}
	defer s.finish()
	ok := ocPulseRun(s, conn)
	conn.Close()
	if ok && s.cookie("DSID") != "" {
		ocJuniperLogout(s)
	}
}

func ocPulseRun(s *ocSession, conn net.Conn) bool {
	hctx, cancel := s.p.StageCtx(s.ctx, StageHandshake)
	dl, _ := hctx.Deadline()
	cancel()
	conn.SetDeadline(dl)
	path := strings.TrimPrefix(s.spec.Path, "/")
	host := ocHostPort(s.spec.Host, s.spec.Port)
	req := "GET /" + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + s.ua + "\r\nContent-Type: EAP\r\nUpgrade: IF-T/TLS 1.0\r\nContent-Length: 0\r\n\r\n"
	t0 := time.Now()
	if _, err := io.WriteString(conn, req); err != nil {
		s.handshakeFail("IF-T/TLS upgrade request failed: %s", shortErr(err))
		return false
	}
	br := bufio.NewReader(conn)
	status, err := ocReadHTTPHead(br)
	if err != nil {
		s.handshakeFail("no response to IF-T/TLS upgrade: %s", shortErr(err))
		return false
	}
	if status != 101 {
		s.handshakeFail("server does not support IF-T/TLS (HTTP %d); try protocol nc", status)
		return false
	}
	t := &ocIFT{c: conn, br: br}
	if err := t.send(ocVendorTCG, ocIFTVersionReq, []byte{0, 1, 2, 2}); err != nil {
		s.handshakeFail("IF-T/TLS version request failed: %s", shortErr(err))
		return false
	}
	v, typ, pl, err := t.recv()
	if err != nil {
		s.handshakeFail("no IF-T/TLS version response: %s", shortErr(err))
		return false
	}
	lat := time.Since(t0)
	if v != ocVendorTCG || typ != ocIFTVersionResp || len(pl) != 4 {
		s.handshakeFail("unexpected IF-T/TLS version response (vendor 0x%x type %d)", v, typ)
		return false
	}
	local := "vpntester"
	info := "clientHostName=" + local
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		info += " clientIp=" + la.IP.String()
	}
	info += " clientCapabilities={}\n\x00"
	if err := t.send(ocVendorJuniper, 0x88, []byte(info)); err != nil {
		s.handshakeFail("IF-T/TLS client info failed: %s", shortErr(err))
		return false
	}
	v, typ, pl, err = t.recv()
	if err != nil {
		s.handshakeFail("no IF-T/TLS auth challenge: %s", shortErr(err))
		return false
	}
	if v != ocVendorTCG || typ != ocIFTAuthChallenge || len(pl) < 4 || binary.BigEndian.Uint32(pl) != ocJuniper1 {
		s.handshakeFail("unexpected IF-T/TLS auth challenge (vendor 0x%x type %d)", v, typ)
		return false
	}
	s.handshakeOK(lat)
	if !s.hasCreds() {
		s.noCreds()
		return false
	}
	actx, acancel := s.p.StageCtx(s.ctx, StageAuth)
	adl, _ := actx.Deadline()
	acancel()
	conn.SetDeadline(adl)
	ident := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(ident, ocJuniper1)
	idEAP := []byte{ocEAPResponse, 1, 0, 0, ocEAPTypeIdentity}
	idEAP = append(idEAP, "anonymous"...)
	binary.BigEndian.PutUint16(idEAP[2:], uint16(len(idEAP)))
	if err := t.send(ocVendorTCG, ocIFTAuthResponse, append(ident, idEAP...)); err != nil {
		s.authError(err)
		return false
	}
	eap, err := ocPulseRecvEAP(t)
	if err != nil {
		if errors.Is(err, ocErrTTLS) {
			s.p.Note("Pulse server uses EAP-TTLS (certificate-based) authentication; auth not tested")
			return false
		}
		s.authError(err)
		return false
	}
	resp := ocAppendAVP(nil, 0xd5e, []byte("Linux"))
	resp = ocAppendAVP(resp, 0xd70, []byte("Pulse-Secure/22.2.1.1295 ("+s.ua+")"))
	if err := t.send(ocVendorTCG, ocIFTAuthResponse, ocJ1Response(eap[1], resp)); err != nil {
		s.authError(err)
		return false
	}
	passSent := false
	askUser := true
	realmNoted := false
	for round := 0; round < 12; round++ {
		eap, err = ocPulseRecvEAP(t)
		if err != nil {
			if passSent && (errors.Is(err, io.EOF) || strings.Contains(err.Error(), "reset")) {
				s.authFail("server closed the session after the password was sent")
				return false
			}
			s.authError(err)
			return false
		}
		avps, perr := ocParseAVPs(eap[12:])
		if perr != nil {
			s.authError(fmt.Errorf("Pulse auth packet: %s", perr))
			return false
		}
		var realms, regions []string
		var cookie string
		realmEntry, oldSessions, signin := false, false, false
		var j2 []byte
		var gtc bool
		for _, a := range avps {
			if a.vendor == ocVendorJuniper2 {
				switch a.code {
				case 0xd60:
					code := uint32(0)
					if len(a.data) == 4 {
						code = binary.BigEndian.Uint32(a.data)
					}
					switch code {
					case 0x0d:
						s.authFail("account locked out")
					case 0x0e:
						s.authFail("client certificate required")
					default:
						s.authFail("authentication failure (code 0x%02x)", code)
					}
					return false
				case 0xd53:
					cookie = string(a.data)
				case 0xd4e:
					realms = append(realms, string(a.data))
				case 0xd4f:
					realmEntry = true
				case 0xd51:
					regions = append(regions, string(a.data))
				case 0xd65:
					oldSessions = true
				case 0xd7b:
					signin = true
				case 0xd73:
					if len(a.data) == 4 {
						switch binary.BigEndian.Uint32(a.data) {
						case 3, 15:
							askUser = false
						default:
							askUser = true
						}
					}
				}
				continue
			}
			if a.vendor == 0 && a.code == ocAVPEAPMessage {
				d := a.data
				if len(d) < 5 || d[0] != ocEAPRequest {
					continue
				}
				if d[4] == ocEAPTypeGTC {
					gtc = true
				} else if len(d) >= 13 && binary.BigEndian.Uint32(d[4:]) == ocExpandedJuniper {
					sub := binary.BigEndian.Uint32(d[8:])
					switch sub {
					case 2, 5:
						j2 = d
					case 3:
						s.p.Note("Pulse server requires Host Checker (TNCC); auth not tested")
						return false
					}
				}
			}
		}
		var out []byte
		switch {
		case cookie != "":
			s.cookies["DSID"] = cookie
			s.order = append(s.order, "DSID")
			if err := t.send(ocVendorTCG, ocIFTAuthResponse, ocJ1Response(eap[1], nil)); err != nil {
				s.authError(err)
				return false
			}
			v, typ, pl, err := t.recv()
			if err != nil {
				s.authError(fmt.Errorf("no IF-T/TLS auth success: %s", shortErr(err)))
				return false
			}
			if v != ocVendorTCG || typ != ocIFTAuthSuccess || len(pl) < 5 || pl[4] != ocEAPSuccess {
				s.authError(fmt.Errorf("unexpected packet instead of IF-T/TLS auth success (vendor 0x%x type %d)", v, typ))
				return false
			}
			s.authOK()
			t.send(ocVendorJuniper, 0x89, nil)
			return true
		case oldSessions:
			s.authOK()
			s.p.Note("credentials accepted; server reports existing sessions at the session limit (none closed)")
			return false
		case realmEntry:
			if s.spec.Group == "" {
				s.p.Note("server asks for a realm name; none in file; auth not tested")
				return false
			}
			out = ocAppendAVP(nil, 0xd50, []byte(s.spec.Group))
		case len(realms) > 0:
			fl := &ocField{}
			for _, r := range realms {
				fl.Options = append(fl.Options, ocOption{Value: r, Label: r})
			}
			v, ok := ocChooseOption(fl, s.spec.Group)
			if !ok && s.spec.Group != "" && !realmNoted {
				realmNoted = true
				s.p.Note("realm %q not offered by server (available: %s); using default", s.spec.Group, ocOptionList(fl))
			}
			out = ocAppendAVP(nil, 0xd50, []byte(v))
		case len(regions) > 0:
			out = ocAppendAVP(nil, 0xd52, []byte(regions[0]))
		case j2 != nil:
			code := j2[12]
			sub := binary.BigEndian.Uint32(j2[8:])
			switch {
			case sub == 2 && code == ocJ2PassFail:
				msg := "password rejected"
				if len(j2) > 15 && j2[13] == 1 {
					msg = strings.TrimRight(string(j2[15:]), "\x00")
				}
				s.authFail("%s", ocShort(msg, 120))
				return false
			case sub == 2 && code == ocJ2PassChange:
				if passSent {
					s.authOK()
					s.p.Note("password accepted; server requires a password change")
				} else {
					s.p.Note("server requires a password change; auth not tested")
				}
				return false
			case code == ocJ2PassRetry && passSent:
				s.authFail("invalid username or password")
				return false
			case passSent && sub == 2 && code == ocJ2PassReq:
				s.p.Note("password accepted; server requires a secondary password; not tested")
				return false
			case code == ocJ2PassReq || code == ocJ2PassRetry:
			default:
				s.authError(fmt.Errorf("unknown Pulse password request code 0x%02x", code))
				return false
			}
			if askUser && s.spec.Username != "" {
				out = ocAppendAVP(out, 0xd6d, []byte(s.spec.Username))
			}
			var inner []byte
			pw := []byte(s.spec.Password)
			if sub == 5 {
				buf := make([]byte, 19)
				buf[0] = 1
				copy(buf[1:], pw)
				inner = ocEAPExpanded(ocEAPResponse, j2[1], 5, buf)
			} else {
				if len(pw) > 253 {
					pw = pw[:253]
				}
				body := append([]byte{0x02, 0x02, byte(len(pw) + 2)}, pw...)
				inner = ocEAPExpanded(ocEAPResponse, j2[1], 2, body)
			}
			out = ocAppendEAPMessage(out, inner)
			passSent = true
		case gtc:
			if passSent {
				s.p.Note("password accepted; server requires a token code (GTC); not tested")
			} else {
				s.p.Note("server requires a token code (GTC); auth not tested")
			}
			return false
		case signin:
			out = ocAppendAVP(nil, 0xd7c, []byte{0, 0, 0, 1})
		default:
			if passSent {
				s.authFail("login rejected")
			} else {
				s.authError(errors.New("unhandled Pulse authentication request"))
			}
			return false
		}
		if err := t.send(ocVendorTCG, ocIFTAuthResponse, ocJ1Response(eap[1], out)); err != nil {
			s.authError(err)
			return false
		}
	}
	s.authError(errors.New("too many Pulse auth rounds"))
	return false
}

func ocAppendEAPMessage(b []byte, eap []byte) []byte {
	var h [8]byte
	binary.BigEndian.PutUint32(h[0:], ocAVPEAPMessage)
	binary.BigEndian.PutUint32(h[4:], uint32(ocAVPMandatory)<<24|uint32(len(eap)+8))
	b = append(b, h[:]...)
	b = append(b, eap...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

var ocErrTTLS = errors.New("EAP-TTLS")

func ocPulseRecvEAP(t *ocIFT) ([]byte, error) {
	v, typ, pl, err := t.recv()
	if err != nil {
		return nil, err
	}
	if v != ocVendorTCG || typ != ocIFTAuthChallenge || len(pl) < 4+5 || binary.BigEndian.Uint32(pl) != ocJuniper1 {
		if v == ocVendorTCG && typ == ocIFTAuthSuccess {
			return nil, errors.New("unexpected IF-T/TLS auth success")
		}
		return nil, fmt.Errorf("unexpected IF-T/TLS packet (vendor 0x%x type %d)", v, typ)
	}
	eap := pl[4:]
	if eap[0] != ocEAPRequest || int(binary.BigEndian.Uint16(eap[2:])) != len(eap) {
		return nil, errors.New("invalid EAP request in IF-T/TLS packet")
	}
	if eap[4] == ocEAPTypeTTLS {
		return nil, ocErrTTLS
	}
	if len(eap) < 12 || binary.BigEndian.Uint32(eap[4:]) != ocExpandedJuniper || binary.BigEndian.Uint32(eap[8:]) != 1 {
		return nil, fmt.Errorf("unexpected EAP type 0x%x from Pulse server", eap[4])
	}
	return eap, nil
}

func ocReadHTTPHead(br *bufio.Reader) (int, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
		return 0, fmt.Errorf("not an HTTP response")
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return 0, fmt.Errorf("bad HTTP status")
	}
	clen := 0
	for i := 0; i < 100; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			return code, err
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			clen, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if code != 101 && clen > 0 && clen < 1<<16 {
		io.CopyN(io.Discard, br, int64(clen))
	}
	return code, nil
}
