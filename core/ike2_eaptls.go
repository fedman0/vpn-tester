package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type ike2TLSPipe struct {
	mu      sync.Mutex
	out     []byte
	in      chan []byte
	want    chan struct{}
	pending []byte
	closed  chan struct{}
	once    sync.Once
}

func newIke2TLSPipe() *ike2TLSPipe {
	return &ike2TLSPipe{in: make(chan []byte), want: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (p *ike2TLSPipe) Read(b []byte) (int, error) {
	if len(p.pending) == 0 {
		select {
		case p.want <- struct{}{}:
		default:
		}
		select {
		case d := <-p.in:
			p.pending = d
		case <-p.closed:
			return 0, io.EOF
		}
	}
	n := copy(b, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

func (p *ike2TLSPipe) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	p.mu.Lock()
	p.out = append(p.out, b...)
	p.mu.Unlock()
	return len(b), nil
}

func (p *ike2TLSPipe) take() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.out
	p.out = nil
	return b
}

func (p *ike2TLSPipe) feed(b []byte) bool {
	select {
	case p.in <- b:
		return true
	case <-p.closed:
		return false
	case <-time.After(5 * time.Second):
		return false
	}
}

func (p *ike2TLSPipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *ike2TLSPipe) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (p *ike2TLSPipe) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (p *ike2TLSPipe) SetDeadline(t time.Time) error      { return nil }
func (p *ike2TLSPipe) SetReadDeadline(t time.Time) error  { return nil }
func (p *ike2TLSPipe) SetWriteDeadline(t time.Time) error { return nil }

type ike2EAPTLSState struct {
	cert     tls.Certificate
	cas      []*x509.Certificate
	pipe     *ike2TLSPipe
	conn     *tls.Conn
	started  bool
	inbuf    []byte
	outq     []byte
	hsErr    chan error
	done     bool
	keylog   bytes.Buffer
	klMu     sync.Mutex
	srvRand  []byte
	msk      []byte
	trustErr error
	verified bool
}

func (t *ike2EAPTLSState) Write(b []byte) (int, error) {
	t.klMu.Lock()
	defer t.klMu.Unlock()
	return t.keylog.Write(b)
}

func (t *ike2EAPTLSState) close() {
	if t.pipe != nil {
		t.pipe.Close()
	}
}

func (t *ike2EAPTLSState) start() {
	t.pipe = newIke2TLSPipe()
	t.hsErr = make(chan error, 1)
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{t.cert},
		KeyLogWriter:       t,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("EAP-TLS server sent no certificate")
			}
			var certs []*x509.Certificate
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			if len(t.cas) == 0 {
				return nil
			}
			if err := ike2VerifyChain(certs[0], certs[1:], t.cas); err != nil {
				t.trustErr = err
				return err
			}
			t.verified = true
			return nil
		},
	}
	t.conn = tls.Client(t.pipe, cfg)
	go func() {
		t.hsErr <- t.conn.Handshake()
	}()
}

func (t *ike2EAPTLSState) wait() ([]byte, error) {
	select {
	case <-t.pipe.want:
	case err := <-t.hsErr:
		t.done = true
		if err != nil {
			return nil, err
		}
	case <-time.After(8 * time.Second):
		return nil, errors.New("EAP-TLS engine stalled")
	}
	return t.pipe.take(), nil
}

func (t *ike2EAPTLSState) frag(id byte) []byte {
	const max = 1000
	if len(t.outq) <= max {
		d := append([]byte{0}, t.outq...)
		t.outq = nil
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, d)
	}
	d := []byte{0x40}
	d = append(d, t.outq[:max]...)
	t.outq = t.outq[max:]
	return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, d)
}

func (t *ike2EAPTLSState) send(id byte, out []byte) []byte {
	const max = 1000
	if len(out) <= max {
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, append([]byte{0}, out...))
	}
	d := []byte{0xc0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(d[1:], uint32(len(out)))
	d = append(d, out[:max]...)
	t.outq = append([]byte(nil), out[max:]...)
	return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, d)
}

func (t *ike2EAPTLSState) process(id byte, data []byte) ([]byte, ike2EAPState, error) {
	if len(data) < 1 {
		return nil, ike2EAPDoneFail, errors.New("bad EAP-TLS packet")
	}
	flags := data[0]
	d := data[1:]
	if flags&0x80 != 0 {
		if len(d) < 4 {
			return nil, ike2EAPDoneFail, errors.New("bad EAP-TLS length")
		}
		d = d[4:]
	}
	if flags&0x20 != 0 && !t.started {
		t.started = true
		t.start()
		out, err := t.wait()
		if err != nil {
			return nil, ike2EAPDoneFail, err
		}
		return t.send(id, out), ike2EAPContinue, nil
	}
	if !t.started {
		return nil, ike2EAPDoneFail, errors.New("EAP-TLS without start")
	}
	if len(t.outq) > 0 && len(d) == 0 {
		return t.frag(id), ike2EAPContinue, nil
	}
	t.inbuf = append(t.inbuf, d...)
	if flags&0x40 != 0 {
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, []byte{0}), ike2EAPContinue, nil
	}
	full := t.inbuf
	t.inbuf = nil
	if t.srvRand == nil && len(full) >= 43 && full[0] == 22 && full[5] == 2 {
		t.srvRand = append([]byte(nil), full[11:43]...)
	}
	if t.done {
		return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, []byte{0}), ike2EAPContinue, nil
	}
	if !t.pipe.feed(full) {
		return nil, ike2EAPDoneFail, errors.New("EAP-TLS engine closed")
	}
	out, err := t.wait()
	if err != nil {
		if t.trustErr != nil {
			return nil, ike2EAPDoneFail, &ike2Failure{stage: StageHandshake, state: StateHandshakeFailed, msg: "EAP-TLS server certificate not trusted: " + ike2ErrText(t.trustErr), trust: true}
		}
		return nil, ike2EAPDoneFail, &ike2Failure{stage: StageAuth, state: StateAuthFailed, msg: "EAP-TLS: " + shortErr(err)}
	}
	if t.done {
		t.msk = t.deriveMSK()
		if len(out) == 0 {
			return ike2EAPPacket(ike2EAPResponse, id, ike2EAPTLS, []byte{0}), ike2EAPContinue, nil
		}
	}
	return t.send(id, out), ike2EAPContinue, nil
}

func ike2PHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	var out []byte
	a := seed
	for len(out) < n {
		m := hmac.New(h, secret)
		m.Write(a)
		a = m.Sum(nil)
		m = hmac.New(h, secret)
		m.Write(a)
		m.Write(seed)
		out = append(out, m.Sum(nil)...)
	}
	return out[:n]
}

func (t *ike2EAPTLSState) deriveMSK() []byte {
	st := t.conn.ConnectionState()
	if st.Version == tls.VersionTLS12 || st.Version < tls.VersionTLS12 {
		if b, err := st.ExportKeyingMaterial("client EAP encryption", nil, 128); err == nil {
			return b[:64]
		}
	}
	t.klMu.Lock()
	lines := strings.Split(t.keylog.String(), "\n")
	t.klMu.Unlock()
	var cr, ms []byte
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 3 && f[0] == "CLIENT_RANDOM" {
			cr, _ = hex.DecodeString(f[1])
			ms, _ = hex.DecodeString(f[2])
		}
	}
	if cr == nil || ms == nil || t.srvRand == nil {
		return nil
	}
	h := sha256.New
	if strings.Contains(tls.CipherSuiteName(st.CipherSuite), "SHA384") {
		h = sha512.New384
	}
	seed := append(append([]byte("client EAP encryption"), cr...), t.srvRand...)
	if st.Version < tls.VersionTLS12 {
		return nil
	}
	return ike2PHash(h, ms, seed, 64)
}

func ike2TLSCert(certDER []byte, chain [][]byte, key crypto.Signer) tls.Certificate {
	c := tls.Certificate{Certificate: append([][]byte{certDER}, chain...), PrivateKey: key}
	return c
}
