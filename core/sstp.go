package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	sstpURI = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"

	sstpMsgConnectRequest = 0x0001
	sstpMsgConnectAck     = 0x0002
	sstpMsgConnectNak     = 0x0003
	sstpMsgConnected      = 0x0004
	sstpMsgAbort          = 0x0005
	sstpMsgDisconnect     = 0x0006
	sstpMsgDisconnectAck  = 0x0007
	sstpMsgEchoRequest    = 0x0008
	sstpMsgEchoResponse   = 0x0009

	sstpAttrEncapProto = 0x01
	sstpAttrStatusInfo = 0x02
	sstpAttrCryptoReq  = 0x04
)

var sstpStatusNames = map[uint32]string{
	0:  "no error",
	1:  "duplicate attribute",
	2:  "unrecognized attribute",
	3:  "invalid attribute value length",
	4:  "value not supported",
	5:  "unacceptable frame received",
	6:  "retry count exceeded",
	7:  "invalid frame received",
	8:  "negotiation timeout",
	9:  "attribute not supported in message",
	10: "required attribute missing",
	11: "status info not supported in message",
}

type sstpPayload struct {
	CACert []byte
	Domain string
}

type sstpValidator struct{}

func (sstpValidator) Validate(c *Config) error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("missing server address")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}
	return nil
}

func sstpHostPort(raw string, port, def int) (string, int) {
	h := strings.TrimSpace(raw)
	if i := strings.Index(h, "://"); i >= 0 {
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			h = u.Host
		} else {
			h = h[i+3:]
		}
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if hh, pp, err := net.SplitHostPort(h); err == nil {
		if n, err := strconv.Atoi(pp); err == nil && n > 0 && n <= 65535 && port <= 0 {
			port = n
		}
		h = hh
	}
	h = strings.Trim(h, "[]")
	if port <= 0 {
		port = def
	}
	return h, port
}

func sstpIsIP(h string) bool {
	_, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil
}

func sstpBuild(f *vfile, fs *vfs, s *sstpSpec) *Config {
	c := newConfig(f, "SSTP", "SSTP")
	host, port := sstpHostPort(s.Host, s.Port, 443)
	c.Name = strings.TrimSpace(s.Name)
	if c.Name == "" {
		c.Name = host
	}
	c.Host, c.Port = host, port
	c.Transport, c.Security = "tcp", "tls"
	if host != "" && !sstpIsIP(host) {
		c.SNI = host
	}
	c.Username, c.Password = s.Username, s.Password
	c.Extra = s.Domain
	if s.Password != "" || len(s.CACert) > 0 {
		h := sha1.Sum([]byte(s.Password + "\x00" + string(s.CACert)))
		c.Extra += "|" + hex.EncodeToString(h[:6])
	}
	pl := &sstpPayload{Domain: s.Domain}
	if len(s.CACert) > 0 {
		if len(sstpParseCerts(s.CACert)) == 0 {
			c.Warn("CA certificate could not be parsed; server certificate is not pinned")
		} else {
			pl.CACert = s.CACert
		}
	}
	c.Payload = pl
	c.Validator = sstpValidator{}
	c.Tester = SSTPConnectivityTester{}
	return c
}

func init() {
	buildSSTPConfig = sstpBuild
}

func sstpParseCerts(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	if bytes.Contains(data, []byte("-----BEGIN")) {
		rest := data
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				out = append(out, c)
			}
		}
		return out
	}
	if cs, err := x509.ParseCertificates(data); err == nil {
		return cs
	}
	if b, err := b64decode(strings.TrimSpace(string(data))); err == nil {
		if cs, err := x509.ParseCertificates(b); err == nil {
			return cs
		}
	}
	return nil
}

func sstpTLSConfig(host string) *tls.Config {
	var suites []uint16
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: suites}
	if host != "" && !sstpIsIP(host) {
		cfg.ServerName = host
	}
	return cfg
}

func sstpCheckCert(st tls.ConnectionState, host string, ca []byte) (trusted bool, err error) {
	if len(st.PeerCertificates) == 0 {
		return false, errors.New("server sent no certificate")
	}
	leaf := st.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if len(ca) > 0 {
		cas := sstpParseCerts(ca)
		pool := x509.NewCertPool()
		for _, c := range cas {
			if bytes.Equal(c.Raw, leaf.Raw) {
				return true, nil
			}
			pool.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return false, errors.New("server certificate is not signed by the configured CA")
		}
		return true, nil
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return verr == nil, nil
}

type sstpSession struct {
	conn net.Conn
	buf  []byte
	tmp  []byte
}

type sstpPacket struct {
	control bool
	msg     uint16
	attrs   map[byte][]byte
	data    []byte
}

func sstpDeadline(ctx context.Context, slice time.Duration) time.Time {
	d := time.Now().Add(slice)
	if dl, ok := ctx.Deadline(); ok && dl.Before(d) {
		return dl
	}
	return d
}

func sstpTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (s *sstpSession) fill(deadline time.Time) error {
	if s.tmp == nil {
		s.tmp = make([]byte, 8192)
	}
	s.conn.SetReadDeadline(deadline)
	n, err := s.conn.Read(s.tmp)
	s.buf = append(s.buf, s.tmp[:n]...)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("server closed the connection")
		}
		return err
	}
	return nil
}

func (s *sstpSession) readLine(deadline time.Time) (string, error) {
	for {
		if i := bytes.IndexByte(s.buf, '\n'); i >= 0 {
			line := strings.TrimRight(string(s.buf[:i]), "\r")
			s.buf = s.buf[i+1:]
			return line, nil
		}
		if len(s.buf) > 16<<10 {
			return "", errors.New("oversized HTTP response header")
		}
		if err := s.fill(deadline); err != nil {
			return "", err
		}
	}
}

func (s *sstpSession) write(ctx context.Context, b []byte) error {
	s.conn.SetWriteDeadline(sstpDeadline(ctx, 5*time.Second))
	_, err := s.conn.Write(b)
	return err
}

func (s *sstpSession) readPacket(deadline time.Time) (*sstpPacket, error) {
	for {
		if len(s.buf) >= 4 {
			if s.buf[0] != 0x10 {
				return nil, fmt.Errorf("invalid SSTP packet (version 0x%02x)", s.buf[0])
			}
			l := int(binary.BigEndian.Uint16(s.buf[2:]) & 0x0FFF)
			if l < 4 {
				return nil, errors.New("invalid SSTP packet length")
			}
			if len(s.buf) >= l {
				body := append([]byte(nil), s.buf[4:l]...)
				ctl := s.buf[1]&1 == 1
				s.buf = s.buf[l:]
				if !ctl {
					return &sstpPacket{data: body}, nil
				}
				return sstpParseControl(body)
			}
		}
		if err := s.fill(deadline); err != nil {
			return nil, err
		}
	}
}

func sstpParseControl(b []byte) (*sstpPacket, error) {
	if len(b) < 4 {
		return nil, errors.New("short SSTP control packet")
	}
	pk := &sstpPacket{control: true, msg: binary.BigEndian.Uint16(b), attrs: map[byte][]byte{}}
	n := int(binary.BigEndian.Uint16(b[2:]))
	b = b[4:]
	for i := 0; i < n && len(b) >= 4; i++ {
		l := int(binary.BigEndian.Uint16(b[2:]) & 0x0FFF)
		if l < 4 || l > len(b) {
			break
		}
		pk.attrs[b[1]] = b[4:l]
		b = b[l:]
	}
	return pk, nil
}

func sstpControl(msg uint16, attrs ...[]byte) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body, msg)
	binary.BigEndian.PutUint16(body[2:], uint16(len(attrs)))
	for _, a := range attrs {
		body = append(body, a...)
	}
	out := []byte{0x10, 0x01, 0, 0}
	binary.BigEndian.PutUint16(out[2:], uint16(4+len(body)))
	return append(out, body...)
}

func sstpAttr(id byte, val []byte) []byte {
	a := []byte{0, id, 0, 0}
	binary.BigEndian.PutUint16(a[2:], uint16(4+len(val)))
	return append(a, val...)
}

func sstpData(frame []byte) []byte {
	out := []byte{0x10, 0x00, 0, 0}
	binary.BigEndian.PutUint16(out[2:], uint16(4+len(frame)))
	return append(out, frame...)
}

func sstpStatusText(v []byte) string {
	if len(v) < 8 {
		return ""
	}
	st := binary.BigEndian.Uint32(v[4:8])
	name := sstpStatusNames[st]
	if name == "" {
		name = "status " + strconv.Itoa(int(st))
	}
	if v[3] != 0 {
		name += fmt.Sprintf(" (attribute %d)", v[3])
	}
	return name
}

func sstpGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("{%X-%X-%X-%X-%X}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *sstpSession) httpHandshake(ctx context.Context, host string, port int) error {
	hh := host
	if strings.Contains(hh, ":") {
		hh = "[" + hh + "]"
	}
	if port != 443 {
		hh += ":" + strconv.Itoa(port)
	}
	req := "SSTP_DUPLEX_POST " + sstpURI + " HTTP/1.1\r\n" +
		"Host: " + hh + "\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"SSTPCORRELATIONID: " + sstpGUID() + "\r\n\r\n"
	if err := s.write(ctx, []byte(req)); err != nil {
		return err
	}
	dl := sstpDeadline(ctx, time.Hour)
	line, err := s.readLine(dl)
	if err != nil {
		return fmt.Errorf("no HTTP response to SSTP request: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return errors.New("server is not an SSTP endpoint (non-HTTP response)")
	}
	code, _ := strconv.Atoi(parts[1])
	for i := 0; ; i++ {
		h, err := s.readLine(dl)
		if err != nil {
			return fmt.Errorf("incomplete HTTP response: %w", err)
		}
		if h == "" {
			break
		}
		if i > 100 {
			return errors.New("too many HTTP response headers")
		}
	}
	if code != 200 {
		st := strings.TrimSpace(strings.Join(parts[1:], " "))
		return fmt.Errorf("server is not an SSTP endpoint (HTTP %s)", st)
	}
	return nil
}

func (s *sstpSession) callConnect(ctx context.Context) (time.Duration, []byte, error) {
	proto := []byte{0, 1}
	t0 := time.Now()
	if err := s.write(ctx, sstpControl(sstpMsgConnectRequest, sstpAttr(sstpAttrEncapProto, proto))); err != nil {
		return 0, nil, err
	}
	dl := sstpDeadline(ctx, time.Hour)
	for {
		pk, err := s.readPacket(dl)
		if err != nil {
			return 0, nil, fmt.Errorf("no SSTP Call Connect Ack: %w", err)
		}
		if !pk.control {
			continue
		}
		switch pk.msg {
		case sstpMsgConnectAck:
			return time.Since(t0), pk.attrs[sstpAttrCryptoReq], nil
		case sstpMsgConnectNak:
			msg := "server rejected SSTP Call Connect"
			if t := sstpStatusText(pk.attrs[sstpAttrStatusInfo]); t != "" {
				msg += ": " + t
			}
			return 0, nil, errors.New(msg)
		case sstpMsgEchoRequest:
			s.write(ctx, sstpControl(sstpMsgEchoResponse))
		case sstpMsgAbort, sstpMsgDisconnect:
			msg := "server aborted the SSTP call"
			if t := sstpStatusText(pk.attrs[sstpAttrStatusInfo]); t != "" {
				msg += ": " + t
			}
			return 0, nil, errors.New(msg)
		}
	}
}

func (s *sstpSession) runPPP(ctx context.Context, pp *sstpPPP) error {
	if err := pp.start(); err != nil {
		return err
	}
	for !pp.done {
		if err := ctx.Err(); err != nil {
			return err
		}
		pk, err := s.readPacket(sstpDeadline(ctx, 500*time.Millisecond))
		if err != nil {
			if sstpTimeout(err) && ctx.Err() == nil {
				if err := pp.tick(time.Now()); err != nil {
					return err
				}
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if pk.control {
			switch pk.msg {
			case sstpMsgEchoRequest:
				s.write(ctx, sstpControl(sstpMsgEchoResponse))
			case sstpMsgAbort, sstpMsgDisconnect:
				if pk.msg == sstpMsgDisconnect {
					s.write(ctx, sstpControl(sstpMsgDisconnectAck))
				}
				msg := "server closed the SSTP call during PPP negotiation"
				if t := sstpStatusText(pk.attrs[sstpAttrStatusInfo]); t != "" {
					msg += ": " + t
				}
				return errors.New(msg)
			}
			continue
		}
		if err := pp.input(pk.data); err != nil {
			return err
		}
		if err := pp.tick(time.Now()); err != nil {
			return err
		}
	}
	return pp.err
}

func (s *sstpSession) disconnect(ctx context.Context, pp *sstpPPP) {
	dctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < 1500*time.Millisecond {
		if time.Until(dl) <= 0 {
			return
		}
		var c2 context.CancelFunc
		dctx, c2 = context.WithDeadline(dctx, dl)
		defer c2()
	}
	if pp != nil {
		pp.send = func(f []byte) error { return s.write(dctx, sstpData(f)) }
		if pp.terminate() != nil {
			return
		}
	}
	if s.write(dctx, sstpControl(sstpMsgDisconnect)) != nil {
		return
	}
	dl := sstpDeadline(dctx, time.Hour)
	for {
		pk, err := s.readPacket(dl)
		if err != nil {
			return
		}
		if pk.control && (pk.msg == sstpMsgDisconnectAck || pk.msg == sstpMsgAbort) {
			return
		}
		if pk.control && pk.msg == sstpMsgDisconnect {
			s.write(dctx, sstpControl(sstpMsgDisconnectAck))
			return
		}
	}
}

type SSTPConnectivityTester struct{}

func (SSTPConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	pl, _ := c.Payload.(*sstpPayload)
	if pl == nil {
		pl = &sstpPayload{}
	}
	raw := p.DialTCP(ctx, c.Host, c.Port)
	if raw == nil {
		return
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	hctx, hcancel := p.StageCtx(ctx, StageHandshake)
	defer hcancel()
	tc := tls.Client(raw, sstpTLSConfig(c.Host))
	if err := tc.HandshakeContext(hctx); err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("TLS handshake failed: %w", err))
		return
	}
	trusted, err := sstpCheckCert(tc.ConnectionState(), c.Host, pl.CACert)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return
	}
	if !trusted {
		p.Note("server certificate not trusted")
	}
	s := &sstpSession{conn: tc}
	if err := s.httpHandshake(hctx, c.Host, c.Port); err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return
	}
	lat, _, err := s.callConnect(hctx)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return
	}
	p.Pass(StageHandshake)
	hcancel()

	if c.Username == "" || c.Password == "" {
		if c.Username == "" {
			p.Note("auth not tested: no credentials in file")
		} else {
			p.Note("auth not tested: no password in file")
		}
		s.disconnect(ctx, nil)
		p.Connectable(lat)
		return
	}
	actx, acancel := p.StageCtx(ctx, StageAuth)
	defer acancel()
	pp := newSSTPPPP(c.Username, pl.Domain, c.Password, func(f []byte) error { return s.write(actx, sstpData(f)) })
	err = s.runPPP(actx, pp)
	for _, n := range pp.notes {
		p.Note("%s", n)
	}
	if err != nil {
		s.disconnect(ctx, pp)
		var af *sstpAuthFailure
		if errors.As(err, &af) {
			p.Fail(StageAuth, StateAuthFailed, err)
		} else {
			p.Fail(StageAuth, StateHandshakeFailed, fmt.Errorf("PPP: %w", err))
		}
		return
	}
	p.Pass(StageAuth)
	if pp.method != "" && pp.method != "none" {
		p.Note("PPP %s authentication succeeded", pp.method)
	}
	s.disconnect(ctx, pp)
	p.Connectable(lat)
}
