package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	pptpMagic = 0x1A2B3C4D

	pptpSCCRQ  = 1
	pptpSCCRP  = 2
	pptpStopRQ = 3
	pptpStopRP = 4
	pptpEchoRQ = 5
	pptpEchoRP = 6
	pptpOCRQ   = 7
	pptpOCRP   = 8
	pptpCCRQ   = 12
	pptpCDN    = 13
)

var pptpGeneralErrors = map[byte]string{
	0: "no general error",
	1: "not connected",
	2: "bad format",
	3: "bad value",
	4: "no resource",
	5: "bad call ID",
	6: "PAC error",
}

var pptpSCCRPResults = map[byte]string{
	2: "general error",
	3: "command channel already exists",
	4: "requester is not authorized to establish a command channel",
	5: "protocol version not supported",
}

var pptpOCRPResults = map[byte]string{
	2: "general error",
	3: "no carrier",
	4: "busy",
	5: "no dial tone",
	6: "time-out",
	7: "call not accepted",
}

type pptpPayload struct {
	Domain string
}

type pptpValidator struct{}

func (pptpValidator) Validate(c *Config) error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("missing server address")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}
	return nil
}

func pptpBuild(f *vfile, fs *vfs, s *pptpSpec) *Config {
	c := newConfig(f, "PPTP", "PPTP")
	host, port := sstpHostPort(s.Host, 0, 1723)
	c.Name = strings.TrimSpace(s.Name)
	if c.Name == "" {
		c.Name = host
	}
	c.Host, c.Port = host, port
	c.Transport = "tcp"
	c.Username, c.Password = s.Username, s.Password
	c.Extra = s.Domain
	c.Payload = &pptpPayload{Domain: s.Domain}
	c.Validator = pptpValidator{}
	c.Tester = PPTPConnectivityTester{}
	return c
}

func init() {
	buildPPTPConfig = pptpBuild
}

type pptpConn struct {
	conn net.Conn
	buf  []byte
	tmp  []byte
}

func pptpMsg(typ uint16, body []byte) []byte {
	b := make([]byte, 12+len(body))
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	binary.BigEndian.PutUint16(b[2:], 1)
	binary.BigEndian.PutUint32(b[4:], pptpMagic)
	binary.BigEndian.PutUint16(b[8:], typ)
	copy(b[12:], body)
	return b
}

func (c *pptpConn) write(ctx context.Context, b []byte) error {
	c.conn.SetWriteDeadline(sstpDeadline(ctx, 5*time.Second))
	_, err := c.conn.Write(b)
	return err
}

func (c *pptpConn) read(deadline time.Time) (uint16, []byte, error) {
	if c.tmp == nil {
		c.tmp = make([]byte, 4096)
	}
	for {
		if len(c.buf) >= 12 {
			l := int(binary.BigEndian.Uint16(c.buf))
			if l < 12 || binary.BigEndian.Uint32(c.buf[4:]) != pptpMagic {
				return 0, nil, errors.New("server is not a PPTP server (bad control message)")
			}
			if len(c.buf) >= l {
				typ := binary.BigEndian.Uint16(c.buf[8:])
				body := append([]byte(nil), c.buf[12:l]...)
				c.buf = c.buf[l:]
				return typ, body, nil
			}
		}
		c.conn.SetReadDeadline(deadline)
		n, err := c.conn.Read(c.tmp)
		c.buf = append(c.buf, c.tmp[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, nil, errors.New("server closed the control connection")
			}
			return 0, nil, err
		}
	}
}

func (c *pptpConn) await(ctx context.Context, want uint16) ([]byte, error) {
	dl := sstpDeadline(ctx, time.Hour)
	for {
		typ, body, err := c.read(dl)
		if err != nil {
			return nil, err
		}
		switch typ {
		case want:
			return body, nil
		case pptpEchoRQ:
			if len(body) >= 4 {
				r := make([]byte, 8)
				copy(r, body[:4])
				r[4] = 1
				c.write(ctx, pptpMsg(pptpEchoRP, r))
			}
		case pptpStopRQ:
			c.write(ctx, pptpMsg(pptpStopRP, []byte{1, 0, 0, 0}))
			return nil, errors.New("server stopped the control connection")
		}
	}
}

func pptpField(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

func pptpResult(code, gerr byte, names map[byte]string) string {
	s := names[code]
	if s == "" {
		s = fmt.Sprintf("result code %d", code)
	}
	if code == 2 && gerr != 0 {
		g := pptpGeneralErrors[gerr]
		if g == "" {
			g = fmt.Sprintf("error code %d", gerr)
		}
		s += " (" + g + ")"
	}
	return s
}

type PPTPConnectivityTester struct{}

func (PPTPConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	raw := p.DialTCP(ctx, c.Host, c.Port)
	if raw == nil {
		return
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	pc := &pptpConn{conn: raw}

	hctx, hcancel := p.StageCtx(ctx, StageHandshake)
	defer hcancel()

	sccrq := make([]byte, 144)
	binary.BigEndian.PutUint16(sccrq[0:], 0x0100)
	binary.BigEndian.PutUint32(sccrq[4:], 3)
	binary.BigEndian.PutUint32(sccrq[8:], 3)
	binary.BigEndian.PutUint16(sccrq[12:], 0)
	binary.BigEndian.PutUint16(sccrq[14:], 1)
	copy(sccrq[16:], pptpField("local", 64))
	copy(sccrq[80:], pptpField("vpntester", 64))
	t0 := time.Now()
	if err := pc.write(hctx, pptpMsg(pptpSCCRQ, sccrq)); err != nil {
		p.FailErr(StageHandshake, err)
		return
	}
	body, err := pc.await(hctx, pptpSCCRP)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("no Start-Control-Connection-Reply: %w", err))
		return
	}
	lat := time.Since(t0)
	if len(body) < 4 {
		p.Fail(StageHandshake, StateHandshakeFailed, errors.New("malformed Start-Control-Connection-Reply"))
		return
	}
	if body[2] != 1 {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("server refused control connection: %s", pptpResult(body[2], body[3], pptpSCCRPResults)))
		return
	}
	vendor := ""
	if len(body) >= 144 {
		vendor = sstpPrintable(pptpTrimNul(body[80:144]))
	}

	var idb [4]byte
	rand.Read(idb[:])
	callID := binary.BigEndian.Uint16(idb[:2])
	if callID == 0 {
		callID = 1
	}
	ocrq := make([]byte, 156)
	binary.BigEndian.PutUint16(ocrq[0:], callID)
	binary.BigEndian.PutUint16(ocrq[2:], binary.BigEndian.Uint16(idb[2:]))
	binary.BigEndian.PutUint32(ocrq[4:], 300)
	binary.BigEndian.PutUint32(ocrq[8:], 100000000)
	binary.BigEndian.PutUint32(ocrq[12:], 3)
	binary.BigEndian.PutUint32(ocrq[16:], 3)
	binary.BigEndian.PutUint16(ocrq[20:], 64)
	binary.BigEndian.PutUint16(ocrq[22:], 0)
	if err := pc.write(hctx, pptpMsg(pptpOCRQ, ocrq)); err != nil {
		p.FailErr(StageHandshake, err)
		return
	}
	body, err = pc.await(hctx, pptpOCRP)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("no Outgoing-Call-Reply: %w", err))
		pptpStop(ctx, pc)
		return
	}
	if len(body) < 8 {
		p.Fail(StageHandshake, StateHandshakeFailed, errors.New("malformed Outgoing-Call-Reply"))
		pptpStop(ctx, pc)
		return
	}
	if body[4] != 1 {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("server rejected the call: %s", pptpResult(body[4], body[5], pptpOCRPResults)))
		pptpStop(ctx, pc)
		return
	}
	p.Pass(StageHandshake)
	hcancel()
	if vendor != "" {
		p.Note("PPTP server %q accepted the call", vendor)
	}
	p.Note("PPP authentication over GRE is not possible without root")
	pptpClear(ctx, pc, callID)
	pptpStop(ctx, pc)
	p.Connectable(lat)
}

func pptpTrimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

func pptpCleanupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	d := 1500 * time.Millisecond
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < d {
		return context.WithDeadline(context.Background(), dl)
	}
	return context.WithTimeout(context.Background(), d)
}

func pptpClear(ctx context.Context, pc *pptpConn, callID uint16) {
	cctx, cancel := pptpCleanupCtx(ctx)
	defer cancel()
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, callID)
	if pc.write(cctx, pptpMsg(pptpCCRQ, b)) != nil {
		return
	}
	pc.await(cctx, pptpCDN)
}

func pptpStop(ctx context.Context, pc *pptpConn) {
	cctx, cancel := pptpCleanupCtx(ctx)
	defer cancel()
	if pc.write(cctx, pptpMsg(pptpStopRQ, []byte{1, 0, 0, 0})) != nil {
		return
	}
	pc.await(cctx, pptpStopRP)
}
