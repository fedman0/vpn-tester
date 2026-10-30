package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/salsa20"
)

const (
	ckFrameHeader   = 14
	ckMaxWire       = 16401
	ckMaxUnit       = ckMaxWire - ckFrameHeader - 255
	ckEncPlain      = 0
	ckEncAES256GCM  = 1
	ckEncChaCha20   = 2
	ckEncAES128GCM  = 3
	ckClosingNone   = 0
	ckClosingStream = 1
	ckClosingSesh   = 2
)

var (
	errCkRejected = errors.New("Cloak server did not accept the credentials and answered as its decoy website (wrong UID or PublicKey, ProxyMethod not served, or device clock off by more than 3 minutes)")
	errCkNoTLS    = errors.New("server did not answer the Cloak ClientHello with TLS")
)

type ckConfig struct {
	ServerName  string
	ProxyMethod string
	EncMethod   byte
	EncName     string
	UID         []byte
	PublicKey   []byte
	RemoteHost  string
	RemotePort  int
	Transport   string
	Browser     string
	NumConn     int
	Unordered   bool
	Notes       []string
}

func ckLookup(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	for _, k := range keys {
		for mk, v := range m {
			if v != nil && strings.EqualFold(mk, k) {
				return v
			}
		}
	}
	return nil
}

func ckString(m map[string]any, keys ...string) string {
	switch x := ckLookup(m, keys...).(type) {
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func ckBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	return amzDecodeB64(s)
}

func ckEncMethod(s string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "plain":
		return ckEncPlain, nil
	case "aes-gcm", "aes-256-gcm":
		return ckEncAES256GCM, nil
	case "aes-128-gcm":
		return ckEncAES128GCM, nil
	case "chacha20-poly1305":
		return ckEncChaCha20, nil
	case "":
		return 0, errors.New("Cloak EncryptionMethod is missing")
	}
	return 0, fmt.Errorf("unknown Cloak EncryptionMethod %q", s)
}

func ckParseConfig(m map[string]any, defHost string, defPort int) (*ckConfig, error) {
	c := &ckConfig{}
	c.ServerName = ckString(m, "ServerName")
	c.ProxyMethod = ckString(m, "ProxyMethod")
	c.RemoteHost = firstNonEmpty(ckString(m, "RemoteHost", "remote"), defHost)
	c.Transport = strings.ToLower(firstNonEmpty(ckString(m, "Transport"), "direct"))
	c.Browser = strings.ToLower(firstNonEmpty(ckString(m, "BrowserSig"), "chrome"))
	c.NumConn, _ = strconv.Atoi(ckString(m, "NumConn"))
	c.Unordered, _ = strconv.ParseBool(ckString(m, "UDP"))
	ps := ckString(m, "RemotePort", "port")
	if ps == "" && defPort > 0 {
		ps = strconv.Itoa(defPort)
	}
	if ps == "" {
		ps = "443"
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p <= 0 || p > 65535 {
		return c, fmt.Errorf("invalid Cloak RemotePort %q", ps)
	}
	c.RemotePort = p
	if c.RemoteHost == "" {
		return c, errors.New("Cloak RemoteHost is missing")
	}
	if c.ServerName == "" {
		return c, errors.New("Cloak ServerName is missing")
	}
	if c.ProxyMethod == "" {
		return c, errors.New("Cloak ProxyMethod is missing")
	}
	if len(c.ProxyMethod) > 12 {
		return c, fmt.Errorf("Cloak ProxyMethod %q is longer than 12 bytes", c.ProxyMethod)
	}
	c.EncName = ckString(m, "EncryptionMethod")
	if c.EncMethod, err = ckEncMethod(c.EncName); err != nil {
		return c, err
	}
	uid, err := ckBytes(ckString(m, "UID"))
	if err != nil {
		return c, errors.New("Cloak UID is missing or not base64")
	}
	if len(uid) != 16 {
		c.Notes = append(c.Notes, fmt.Sprintf("Cloak UID is %d bytes instead of 16", len(uid)))
	}
	c.UID = uid
	pub, err := ckBytes(ckString(m, "PublicKey"))
	if err != nil || len(pub) != 32 {
		return c, errors.New("Cloak PublicKey is missing or is not a base64 X25519 key")
	}
	c.PublicKey = pub
	switch c.Transport {
	case "direct":
	case "cdn":
		return c, errors.New("Cloak CDN (WebSocket) transport is not supported")
	default:
		return c, fmt.Errorf("unknown Cloak Transport %q", c.Transport)
	}
	switch c.Browser {
	case "chrome", "firefox", "safari":
	default:
		c.Notes = append(c.Notes, "unknown BrowserSig "+c.Browser+"; using chrome")
		c.Browser = "chrome"
	}
	return c, nil
}

func (c *ckConfig) fingerprint() string {
	h := sha256.New()
	h.Write(c.UID)
	h.Write([]byte{0})
	h.Write(c.PublicKey)
	fmt.Fprintf(h, "\x00%s\x00%d\x00%s", strings.ToLower(c.ProxyMethod), c.EncMethod, strings.ToLower(c.ServerName))
	return hex.EncodeToString(h.Sum(nil)[:10])
}

func (c *ckConfig) publicKeyString() string {
	return base64.StdEncoding.EncodeToString(c.PublicKey)
}

func ckGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func ckReadRecord(r *bufio.Reader, max int) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if hdr[1] != 0x03 || n > max {
		return hdr[0], nil, errCkNoTLS
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return hdr[0], nil, err
	}
	return hdr[0], b, nil
}

func ckRandSession() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if v := binary.BigEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

func ckHandshake(ctx context.Context, raw net.Conn, cfg *ckConfig) (*ckConn, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	srvPub, err := ecdh.X25519().NewPublicKey(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Cloak PublicKey: %v", err)
	}
	shared, err := eph.ECDH(srvPub)
	if err != nil {
		return nil, fmt.Errorf("Cloak PublicKey: %v", err)
	}
	ephPub := eph.PublicKey().Bytes()
	sid := ckRandSession()
	plain := make([]byte, 48)
	copy(plain[0:16], cfg.UID)
	copy(plain[16:28], cfg.ProxyMethod)
	plain[28] = cfg.EncMethod
	binary.BigEndian.PutUint64(plain[29:37], uint64(time.Now().UTC().Unix()))
	binary.BigEndian.PutUint32(plain[37:41], sid)
	if cfg.Unordered {
		plain[41] |= 0x01
	}
	gcm, err := ckGCM(shared)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, ephPub[:12], plain, nil)
	hello := ckBuildHello(ckHelloFields{random: ephPub, sessionID: ct[0:32], keyShare: ct[32:64], serverName: cfg.ServerName, browser: cfg.Browser})
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Now()) })
	defer stop()
	if _, err := raw.Write(hello); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(raw, 32<<10)
	typ, sh, err := ckReadRecord(br, 1<<15)
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.DeadlineExceeded
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("server closed the connection after the Cloak ClientHello (not a Cloak server, or the decoy site is unreachable from it)")
		}
		if errors.Is(err, errCkNoTLS) {
			return nil, errCkNoTLS
		}
		return nil, err
	}
	switch typ {
	case 0x16:
	case 0x15:
		return nil, errCkRejected
	default:
		return nil, errCkNoTLS
	}
	if len(sh) < 116 || sh[0] != 0x02 {
		return nil, errCkRejected
	}
	enc := append(append([]byte{}, sh[6:38]...), sh[84:116]...)
	key, err := gcm.Open(nil, enc[0:12], enc[12:60], nil)
	if err != nil || len(key) != 32 {
		return nil, errCkRejected
	}
	for i := 0; i < 2; i++ {
		t, _, err := ckReadRecord(br, 1<<15)
		if err != nil {
			if ctx.Err() != nil {
				return nil, context.DeadlineExceeded
			}
			return nil, fmt.Errorf("Cloak handshake: %v", err)
		}
		if i == 0 && t != 0x14 || i == 1 && t != 0x17 {
			return nil, errors.New("Cloak handshake: unexpected TLS record from server")
		}
	}
	raw.SetDeadline(time.Time{})
	c := &ckConn{raw: raw, br: br, sid: sid, stream: 1}
	copy(c.key[:], key)
	switch cfg.EncMethod {
	case ckEncAES256GCM:
		c.aead, err = ckGCM(key)
	case ckEncAES128GCM:
		c.aead, err = ckGCM(key[:16])
	case ckEncChaCha20:
		c.aead, err = chacha20poly1305.New(key)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

type ckConn struct {
	raw     net.Conn
	br      *bufio.Reader
	key     [32]byte
	aead    cipher.AEAD
	sid     uint32
	stream  uint32
	wmu     sync.Mutex
	wseq    uint64
	rmu     sync.Mutex
	rbuf    []byte
	rerr    error
	closed  atomic.Bool
	got     atomic.Int64
	peerFin atomic.Bool
}

func (c *ckConn) frame(stream uint32, seq uint64, closing byte, payload []byte) []byte {
	tag := 8
	if c.aead != nil {
		tag = c.aead.Overhead()
	}
	n := ckFrameHeader + len(payload) + tag
	buf := make([]byte, 5+n)
	buf[0], buf[1], buf[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(n))
	f := buf[5:]
	hdr := f[:ckFrameHeader]
	binary.BigEndian.PutUint32(hdr[0:4], stream)
	binary.BigEndian.PutUint64(hdr[4:12], seq)
	hdr[12] = closing
	hdr[13] = byte(tag)
	copy(f[ckFrameHeader:], payload)
	if c.aead != nil {
		c.aead.Seal(f[ckFrameHeader:ckFrameHeader], hdr[:c.aead.NonceSize()], f[ckFrameHeader:ckFrameHeader+len(payload)], nil)
	} else {
		rand.Read(f[ckFrameHeader+len(payload):])
	}
	salsa20.XORKeyStream(hdr, hdr, f[n-8:], &c.key)
	return buf
}

func (c *ckConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n := 0
	for n < len(p) {
		chunk := p[n:]
		if len(chunk) > ckMaxUnit {
			chunk = chunk[:ckMaxUnit]
		}
		buf := c.frame(c.stream, c.wseq, ckClosingNone, chunk)
		c.wseq++
		if _, err := c.raw.Write(buf); err != nil {
			return n, err
		}
		n += len(chunk)
	}
	return n, nil
}

func (c *ckConn) deframe(in []byte) (uint32, byte, []byte, error) {
	if len(in) < ckFrameHeader+8 {
		return 0, 0, nil, errors.New("Cloak frame too short")
	}
	hdr := in[:ckFrameHeader]
	salsa20.XORKeyStream(hdr, hdr, in[len(in)-8:], &c.key)
	stream := binary.BigEndian.Uint32(hdr[0:4])
	closing := hdr[12]
	extra := int(hdr[13])
	rest := in[ckFrameHeader:]
	useful := len(rest) - extra
	if useful < 0 {
		return 0, 0, nil, errors.New("Cloak frame has a bad length")
	}
	if c.aead != nil {
		if _, err := c.aead.Open(rest[:0], hdr[:c.aead.NonceSize()], rest, nil); err != nil {
			return 0, 0, nil, errors.New("Cloak frame failed authentication")
		}
	}
	return stream, closing, rest[:useful], nil
}

func (c *ckConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		typ, rec, err := ckReadRecord(c.br, 1<<15)
		if err != nil {
			c.rerr = err
			continue
		}
		if typ != 0x17 {
			c.rerr = errors.New("Cloak: unexpected TLS record type from server")
			continue
		}
		stream, closing, payload, err := c.deframe(rec)
		if err != nil {
			c.rerr = err
			continue
		}
		if closing == ckClosingSesh || closing == ckClosingStream && stream == c.stream {
			c.peerFin.Store(true)
			c.rerr = io.EOF
			continue
		}
		if stream != c.stream || len(payload) == 0 {
			continue
		}
		c.got.Add(int64(len(payload)))
		c.rbuf = append(c.rbuf[:0], payload...)
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *ckConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.raw.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	c.wmu.Lock()
	pad := make([]byte, 1+int(ckRandSession()%64))
	rand.Read(pad)
	if c.wseq > 0 {
		c.raw.Write(c.frame(c.stream, c.wseq, ckClosingStream, pad))
	}
	c.raw.Write(c.frame(0xffffffff, 0, ckClosingSesh, pad))
	c.wmu.Unlock()
	return c.raw.Close()
}

func (c *ckConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *ckConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *ckConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *ckConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *ckConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func ckDial(ctx context.Context, p *probe, cfg *ckConfig) *ckConn {
	raw := p.DialTCP(ctx, cfg.RemoteHost, cfg.RemotePort)
	if raw == nil {
		return nil
	}
	hctx, cancel := p.StageCtx(ctx, StageHandshake)
	defer cancel()
	cc, err := ckHandshake(hctx, raw, cfg)
	if err != nil {
		raw.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			p.Fail(StageHandshake, StateHandshakeFailed, errors.New("timeout waiting for the Cloak server reply"))
			p.res.ErrorCode = "TIMEOUT"
			return nil
		}
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return nil
	}
	p.Pass(StageHandshake)
	return cc
}
