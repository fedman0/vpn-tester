package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

func seSHA0(data []byte) [20]byte {
	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	ml := uint64(len(data)) * 8
	msg := make([]byte, 0, len(data)+72)
	msg = append(msg, data...)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	msg = binary.BigEndian.AppendUint64(msg, ml)
	var w [80]uint32
	for off := 0; off < len(msg); off += 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[off+i*4:])
		}
		for i := 16; i < 80; i++ {
			w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		}
		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5A827999
			case i < 40:
				f, k = b^c^d, 0x6ED9EBA1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8F1BBCDC
			default:
				f, k = b^c^d, 0xCA62C1D6
			}
			t := (a<<5 | a>>27) + f + e + k + w[i]
			e, d, c, b, a = d, c, b<<30|b>>2, a, t
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	var out [20]byte
	for i, v := range h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}

func seHashPassword(user, pass string) []byte {
	s := seSHA0([]byte(pass + strings.ToUpper(user)))
	return s[:]
}

const (
	sePackInt    = 0
	sePackData   = 1
	sePackStr    = 2
	sePackUniStr = 3
	sePackInt64  = 4
)

type sePackElem struct {
	Name string
	Type uint32
	Nums []uint64
	Bufs [][]byte
}

type sePack struct {
	elems []*sePackElem
}

func (p *sePack) set(name string, typ uint32, num uint64, buf []byte) {
	for i, e := range p.elems {
		if strings.EqualFold(e.Name, name) {
			p.elems = append(p.elems[:i], p.elems[i+1:]...)
			break
		}
	}
	e := &sePackElem{Name: name, Type: typ}
	if typ == sePackInt || typ == sePackInt64 {
		e.Nums = []uint64{num}
	} else {
		e.Bufs = [][]byte{buf}
	}
	p.elems = append(p.elems, e)
}

func (p *sePack) addInt(name string, v uint32)  { p.set(name, sePackInt, uint64(v), nil) }
func (p *sePack) addStr(name, v string)         { p.set(name, sePackStr, 0, []byte(v)) }
func (p *sePack) addData(name string, v []byte) { p.set(name, sePackData, 0, v) }

func (p *sePack) addBool(name string, v bool) {
	n := uint32(0)
	if v {
		n = 1
	}
	p.addInt(name, n)
}

func (p *sePack) get(name string) *sePackElem {
	for _, e := range p.elems {
		if strings.EqualFold(e.Name, name) {
			return e
		}
	}
	return nil
}

func (p *sePack) getInt(name string) uint32 {
	e := p.get(name)
	if e == nil || len(e.Nums) == 0 {
		return 0
	}
	return uint32(e.Nums[0])
}

func (p *sePack) getStr(name string) (string, bool) {
	e := p.get(name)
	if e == nil || len(e.Bufs) == 0 || (e.Type != sePackStr && e.Type != sePackUniStr) {
		return "", false
	}
	return string(bytes.TrimRight(e.Bufs[0], "\x00")), true
}

func (p *sePack) getData(name string) []byte {
	e := p.get(name)
	if e == nil || len(e.Bufs) == 0 || e.Type != sePackData {
		return nil
	}
	return e.Bufs[0]
}

func (p *sePack) encode() []byte {
	es := append([]*sePackElem(nil), p.elems...)
	sort.SliceStable(es, func(i, j int) bool { return strings.ToLower(es[i].Name) < strings.ToLower(es[j].Name) })
	var b bytes.Buffer
	u32 := func(v uint32) { b.Write(binary.BigEndian.AppendUint32(nil, v)) }
	u32(uint32(len(es)))
	for _, e := range es {
		u32(uint32(len(e.Name) + 1))
		b.WriteString(e.Name)
		u32(e.Type)
		switch e.Type {
		case sePackInt:
			u32(uint32(len(e.Nums)))
			for _, n := range e.Nums {
				u32(uint32(n))
			}
		case sePackInt64:
			u32(uint32(len(e.Nums)))
			for _, n := range e.Nums {
				b.Write(binary.BigEndian.AppendUint64(nil, n))
			}
		case sePackUniStr:
			u32(uint32(len(e.Bufs)))
			for _, v := range e.Bufs {
				u32(uint32(len(v) + 1))
				b.Write(v)
				b.WriteByte(0)
			}
		default:
			u32(uint32(len(e.Bufs)))
			for _, v := range e.Bufs {
				u32(uint32(len(v)))
				b.Write(v)
			}
		}
	}
	return b.Bytes()
}

func seDecodePack(d []byte) (*sePack, error) {
	r := &seBinReader{b: d}
	n := r.u32()
	if n > 262144 {
		return nil, errors.New("pack: too many elements")
	}
	p := &sePack{}
	for i := uint32(0); i < n && r.err == nil; i++ {
		nl := r.u32()
		if r.err == nil && (nl == 0 || nl > 64) {
			return nil, errors.New("pack: bad element name")
		}
		name := string(r.bytesN(nl - 1))
		e := &sePackElem{Name: name, Type: r.u32()}
		cnt := r.u32()
		if cnt > 262144 {
			return nil, errors.New("pack: too many values")
		}
		for j := uint32(0); j < cnt && r.err == nil; j++ {
			switch e.Type {
			case sePackInt:
				e.Nums = append(e.Nums, uint64(r.u32()))
			case sePackInt64:
				e.Nums = append(e.Nums, r.u64())
			case sePackData, sePackStr, sePackUniStr:
				e.Bufs = append(e.Bufs, r.bytesN(r.u32()))
			default:
				return nil, fmt.Errorf("pack: unknown value type %d", e.Type)
			}
		}
		p.elems = append(p.elems, e)
	}
	if r.err != nil {
		return nil, fmt.Errorf("pack: %w", r.err)
	}
	return p, nil
}

var seErrNames = map[uint32]string{
	1: "ERR_CONNECT_FAILED", 2: "ERR_SERVER_IS_NOT_VPN", 3: "ERR_DISCONNECTED", 4: "ERR_PROTOCOL_ERROR",
	5: "ERR_CLIENT_IS_NOT_VPN", 6: "ERR_USER_CANCEL", 7: "ERR_AUTHTYPE_NOT_SUPPORTED", 8: "ERR_HUB_NOT_FOUND",
	9: "ERR_AUTH_FAILED", 10: "ERR_HUB_STOPPING", 11: "ERR_SESSION_REMOVED", 12: "ERR_ACCESS_DENIED",
	13: "ERR_SESSION_TIMEOUT", 14: "ERR_INVALID_PROTOCOL", 15: "ERR_TOO_MANY_CONNECTION", 16: "ERR_HUB_IS_BUSY",
	20: "ERR_TOO_MANY_USER_SESSION", 21: "ERR_LICENSE_ERROR", 23: "ERR_INTERNAL_ERROR", 33: "ERR_NOT_SUPPORTED",
	52: "ERR_NOT_ENOUGH_RIGHT", 56: "ERR_CIPHER_NOT_SUPPORTED", 63: "ERR_TOO_MANY_USER", 68: "ERR_USER_AUTHTYPE_NOT_PASSWORD",
	81: "ERR_SE_VPN_BLOCK", 85: "ERR_CERT_NOT_TRUSTED", 101: "ERR_BAD_CLOCK", 103: "ERR_CLIENT_LICENSE_NOT_ENOUGH",
	105: "ERR_SERVER_CANT_ACCEPT", 107: "ERR_MONITOR_MODE_DENIED", 108: "ERR_BRIDGE_MODE_DENIED", 109: "ERR_IP_ADDRESS_DENIED",
	124: "ERR_BRANDED_C_TO_S", 125: "ERR_BRANDED_C_FROM_S", 126: "ERR_AUTO_DISCONNECTED", 127: "ERR_CLIENT_ID_REQUIRED",
	138: "ERR_MSCHAP2_PASSWORD_NEED_RESET", 143: "ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE", 144: "ERR_VPNGATE",
	145: "ERR_VPNGATE_CLIENT", 148: "ERR_SUSPENDING",
}

var seErrText = map[uint32]string{
	7: "authentication method not supported by server", 8: "virtual hub not found", 9: "authentication failed",
	10: "virtual hub is stopping", 12: "access denied", 15: "too many connections", 16: "virtual hub is busy",
	20: "too many sessions for this user", 63: "too many users", 68: "user is not configured for password authentication",
	81: "server blocks this client", 105: "server cannot accept the connection", 107: "monitor mode denied",
	108: "bridge/routing mode denied", 109: "client IP address denied", 127: "client ID required",
	138: "password must be changed", 143: "authentication method not supported by open-source server",
}

func seErrString(code uint32) string {
	name := seErrNames[code]
	if name == "" {
		name = "ERR"
	}
	if t := seErrText[code]; t != "" {
		return fmt.Sprintf("%s: %s (%d)", t, name, code)
	}
	return fmt.Sprintf("server error %s (%d)", name, code)
}

func seAuthErr(code uint32) bool {
	switch code {
	case 7, 8, 9, 12, 68, 109, 138, 143:
		return true
	}
	return false
}

const (
	seClientStr   = "SoftEther VPN Client"
	seClientVer   = 443
	seClientBuild = 9799
)

func seRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func seRandInt(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

func seWritePack(w io.Writer, host string, p *sePack) error {
	p.addData("pencore", seRandom(int(seRandInt(1000))))
	body := p.encode()
	hdr := "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n" +
		"Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\r\n" +
		"Host: " + host + "\r\n" +
		"Keep-Alive: timeout=15; max=19\r\n" +
		"Connection: Keep-Alive\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	_, err := w.Write(append([]byte(hdr), body...))
	return err
}

func seWriteSignature(w io.Writer, host string) error {
	pad := seRandom(int(seRandInt(2000)))
	body := append(append([]byte(nil), seWaterMark...), pad...)
	hdr := "POST /vpnsvc/connect.cgi HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Content-Type: image/jpeg\r\n" +
		"Connection: Keep-Alive\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	_, err := w.Write(append([]byte(hdr), body...))
	return err
}

var seErrNotVPN = errors.New("not a SoftEther VPN server")

func seReadPack(br *bufio.Reader, w io.Writer, host string) (*sePack, error) {
	for i := 0; i < 32; i++ {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, errors.New("server closed the connection")
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, context.DeadlineExceeded
			}
			return nil, fmt.Errorf("%w: %v", seErrNotVPN, err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%w (HTTP %s)", seErrNotVPN, resp.Status)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.EqualFold(strings.TrimSpace(ct), "application/octet-stream") {
			return nil, fmt.Errorf("%w (unexpected content type %q)", seErrNotVPN, ct)
		}
		if resp.ContentLength <= 0 || resp.ContentLength > 16<<20 {
			return nil, fmt.Errorf("%w (bad content length)", seErrNotVPN)
		}
		body := make([]byte, resp.ContentLength)
		_, err = io.ReadFull(resp.Body, body)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, context.DeadlineExceeded
			}
			return nil, fmt.Errorf("reading pack: %v", err)
		}
		p, err := seDecodePack(body)
		if err != nil {
			return nil, fmt.Errorf("%w (%v)", seErrNotVPN, err)
		}
		switch p.getInt("noop") {
		case 2:
			continue
		case 1:
			np := &sePack{}
			np.addInt("error", 0)
			np.addInt("noop", 1)
			if err := seWritePack(w, host, np); err != nil {
				return nil, err
			}
			continue
		}
		return p, nil
	}
	return nil, errors.New("too many keep-alive packets from server")
}

func seCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

func seTLSConfig(host string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       seCipherSuites(),
	}
	if _, err := netip.ParseAddr(host); err != nil {
		cfg.ServerName = host
	}
	return cfg
}

func seCheckCert(st tls.ConnectionState, host string, a *seAccount) (trusted bool, err error) {
	if len(st.PeerCertificates) == 0 {
		return false, errors.New("server sent no certificate")
	}
	leaf := st.PeerCertificates[0]
	if a.CheckServerCert && len(a.ServerCert) > 0 {
		if bytes.Equal(leaf.Raw, a.ServerCert) {
			return true, nil
		}
		if pin, perr := x509.ParseCertificate(a.ServerCert); perr == nil {
			if bytes.Equal(pin.Raw, leaf.Raw) || leaf.CheckSignatureFrom(pin) == nil {
				return true, nil
			}
		}
		return false, errors.New("server certificate does not match the certificate saved in the account")
	}
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return verr == nil, nil
}

func seProxyHandshake(conn net.Conn, a *seAccount, ip string) error {
	target := net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
	br := bufio.NewReader(conn)
	switch a.ProxyType {
	case 1:
		req := "CONNECT " + target + " HTTP/1.0\r\nHost: " + target + "\r\n"
		if a.ProxyUser != "" {
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(a.ProxyUser+":"+a.ProxyPass)) + "\r\n"
		}
		for _, l := range strings.FieldsFunc(a.ProxyHeader, func(r rune) bool { return r == '\r' || r == '\n' }) {
			if strings.Contains(l, ":") {
				req += strings.TrimSpace(l) + "\r\n"
			}
		}
		req += "\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return err
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			return fmt.Errorf("HTTP proxy: %v", err)
		}
		if resp.StatusCode == 407 {
			return fmt.Errorf("HTTP proxy authentication failed (407)")
		}
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("HTTP proxy refused CONNECT: %s", resp.Status)
		}
		if br.Buffered() > 0 {
			return errors.New("HTTP proxy sent unexpected data")
		}
		return nil
	case 2:
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			return errors.New("SOCKS4 proxy requires an IPv4 server address")
		}
		req := []byte{4, 1, byte(a.Port >> 8), byte(a.Port)}
		v4 := addr.As4()
		req = append(req, v4[:]...)
		req = append(req, []byte(a.ProxyUser)...)
		req = append(req, 0)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		resp := make([]byte, 8)
		if _, err := io.ReadFull(br, resp); err != nil {
			return fmt.Errorf("SOCKS4 proxy: %v", err)
		}
		if resp[1] != 0x5a {
			return fmt.Errorf("SOCKS4 proxy rejected the request (code %d)", resp[1])
		}
		return nil
	case 3:
		methods := []byte{0}
		if a.ProxyUser != "" {
			methods = append(methods, 2)
		}
		if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
			return err
		}
		sel := make([]byte, 2)
		if _, err := io.ReadFull(br, sel); err != nil {
			return fmt.Errorf("SOCKS5 proxy: %v", err)
		}
		if sel[0] != 5 {
			return errors.New("SOCKS5 proxy: bad reply")
		}
		switch sel[1] {
		case 0:
		case 2:
			u, pw := a.ProxyUser, a.ProxyPass
			if len(u) > 255 || len(pw) > 255 {
				return errors.New("SOCKS5 proxy: credentials too long")
			}
			msg := append([]byte{1, byte(len(u))}, u...)
			msg = append(msg, byte(len(pw)))
			msg = append(msg, pw...)
			if _, err := conn.Write(msg); err != nil {
				return err
			}
			ar := make([]byte, 2)
			if _, err := io.ReadFull(br, ar); err != nil {
				return fmt.Errorf("SOCKS5 proxy: %v", err)
			}
			if ar[1] != 0 {
				return errors.New("SOCKS5 proxy: proxy authentication failed")
			}
		default:
			return errors.New("SOCKS5 proxy: no acceptable authentication method")
		}
		req := []byte{5, 1, 0}
		if addr, err := netip.ParseAddr(a.Host); err == nil {
			if addr.Is4() {
				v := addr.As4()
				req = append(append(req, 1), v[:]...)
			} else {
				v := addr.As16()
				req = append(append(req, 4), v[:]...)
			}
		} else {
			if len(a.Host) > 255 {
				return errors.New("SOCKS5 proxy: hostname too long")
			}
			req = append(append(req, 3, byte(len(a.Host))), a.Host...)
		}
		req = append(req, byte(a.Port>>8), byte(a.Port))
		if _, err := conn.Write(req); err != nil {
			return err
		}
		hd := make([]byte, 4)
		if _, err := io.ReadFull(br, hd); err != nil {
			return fmt.Errorf("SOCKS5 proxy: %v", err)
		}
		if hd[1] != 0 {
			switch hd[1] {
			case 3, 4:
				return fmt.Errorf("SOCKS5 proxy: host unreachable (code %d)", hd[1])
			case 5:
				return errors.New("SOCKS5 proxy: connection refused")
			}
			return fmt.Errorf("SOCKS5 proxy: request failed (code %d)", hd[1])
		}
		skip := 0
		switch hd[3] {
		case 1:
			skip = 4
		case 4:
			skip = 16
		case 3:
			l, err := br.ReadByte()
			if err != nil {
				return err
			}
			skip = int(l)
		}
		if _, err := io.ReadFull(br, make([]byte, skip+2)); err != nil {
			return fmt.Errorf("SOCKS5 proxy: %v", err)
		}
		return nil
	}
	return fmt.Errorf("unsupported proxy type %d", a.ProxyType)
}

func seProxyState(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "authentication"):
		return StateAuthFailed
	case strings.Contains(s, "refused"):
		return StatePortUnreachable
	case strings.Contains(s, "unreachable"):
		return StateHostUnreachable
	}
	return classifyErr(StageTransport, err)
}

func seAuthPack(a *seAccount, random []byte, host string, port int) (*sePack, error) {
	p := &sePack{}
	p.addStr("method", "login")
	p.addStr("hubname", a.Hub)
	p.addStr("username", a.Username)
	switch a.AuthType {
	case 0:
		p.addInt("authtype", 0)
	case 1:
		h := a.Hashed
		if h == nil {
			h = seHashPassword(a.Username, a.Plain)
		}
		sp := seSHA0(append(append([]byte(nil), h...), random...))
		p.addInt("authtype", 1)
		p.addData("secure_password", sp[:])
	case 2:
		p.addInt("authtype", 2)
		p.addStr("plain_password", a.Plain)
	case 3:
		cert, err := x509.ParseCertificate(a.ClientCert)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %v", err)
		}
		key, err := seParseRSAKey(a.ClientKey)
		if err != nil {
			return nil, err
		}
		digest := sha1.Sum(random)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
		if err != nil {
			return nil, fmt.Errorf("signing: %v", err)
		}
		p.addInt("authtype", 3)
		p.addData("cert", cert.Raw)
		p.addData("sign", sig)
	default:
		return nil, fmt.Errorf("%s authentication is not supported", seAuthTypeName(a.AuthType))
	}
	p.addStr("client_str", seClientStr)
	p.addInt("client_ver", seClientVer)
	p.addInt("client_build", seClientBuild)
	p.addInt("protocol", 0)
	p.addStr("hello", seClientStr)
	p.addInt("version", seClientVer)
	p.addInt("build", seClientBuild)
	p.addInt("client_id", 0)
	p.addInt("max_connection", 1)
	p.addBool("use_encrypt", a.UseEncrypt)
	p.addBool("use_compress", false)
	p.addBool("half_connection", false)
	p.addBool("require_bridge_routing_mode", a.BridgeMode)
	p.addBool("require_monitor_mode", a.MonitorMode)
	p.addBool("qos", !a.DisableQoS)
	p.addBool("support_bulk_on_rudp", true)
	p.addBool("support_hmac_on_bulk_of_rudp", true)
	p.addBool("support_udp_recovery", true)
	p.addData("unique_id", seRandom(20))
	p.addInt("rudp_bulk_max_version", 2)
	p.addStr("ClientProductName", seClientStr)
	p.addStr("ServerProductName", "")
	p.addStr("ClientOsName", "Linux")
	p.addStr("ClientOsVer", "")
	p.addStr("ClientOsProductId", "")
	p.addStr("ClientHostname", "localhost")
	p.addStr("ServerHostname", host)
	p.addStr("ProxyHostname", "")
	p.addStr("HubName", a.Hub)
	p.addData("UniqueId", seRandom(16))
	p.addInt("ClientProductVer", seClientVer)
	p.addInt("ClientProductBuild", seClientBuild)
	p.addInt("ServerProductVer", 0)
	p.addInt("ServerProductBuild", 0)
	p.addData("ClientIpAddress6", make([]byte, 16))
	p.addInt("ClientPort", 0)
	p.addData("ServerIpAddress6", make([]byte, 16))
	p.addInt("ServerPort2", uint32(port))
	p.addData("ProxyIpAddress6", make([]byte, 16))
	p.addInt("ProxyPort", 0)
	p.addBool("V_IsWindows", false)
	p.addBool("V_IsNT", false)
	p.addBool("V_IsServer", false)
	p.addBool("V_IsBeta", false)
	p.addInt("V_VerMajor", 0)
	p.addInt("V_VerMinor", 0)
	p.addInt("V_Build", 0)
	p.addInt("V_ServicePack", 0)
	p.addStr("V_Title", "Linux")
	return p, nil
}

func seParseRSAKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("client key is not RSA")
	}
	return nil, errors.New("client key could not be parsed")
}

func seHasCreds(a *seAccount) (bool, string) {
	switch a.AuthType {
	case 0:
		if a.Username == "" {
			return false, "auth not tested: no credentials in file"
		}
		return true, ""
	case 1:
		if a.Username == "" || (a.Hashed == nil && !a.HasPlain) {
			return false, "auth not tested: no credentials in file"
		}
		return true, ""
	case 2:
		if a.Username == "" || !a.HasPlain {
			return false, "auth not tested: no credentials in file"
		}
		return true, ""
	case 3:
		if a.Username == "" || len(a.ClientCert) == 0 || len(a.ClientKey) == 0 {
			return false, "auth not tested: certificate or private key not embedded in file"
		}
		return true, ""
	}
	return false, "auth not tested: " + seAuthTypeName(a.AuthType) + " authentication requires a hardware device"
}

func seSetDeadline(conn net.Conn, ctx context.Context) {
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	}
}

func seStageErr(err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return context.DeadlineExceeded
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

type SoftEtherConnectivityTester struct{}

func (SoftEtherConnectivityTester) Test(ctx context.Context, c *Config, p *probe) {
	a, _ := c.Payload.(*seAccount)
	if a == nil {
		p.Fail(StageParse, StateInvalid, errors.New("missing account data"))
		return
	}
	dialHost, dialPort := a.Host, a.Port
	if a.ProxyType != 0 {
		dialHost, dialPort = a.ProxyHost, a.ProxyPort
	}
	if a.ProxyType == 0 && a.Hint != "" {
		if _, err := netip.ParseAddr(a.Host); err != nil {
			dctx, cancel := p.StageCtx(ctx, StageDNS)
			ips, err := net.DefaultResolver.LookupNetIP(dctx, "ip", a.Host)
			cancel()
			if err != nil || len(ips) == 0 {
				dialHost = a.Hint
				p.Note("DNS lookup failed, using hint address %s", a.Hint)
			}
		}
	}
	if p.Resolve(ctx, dialHost) == nil {
		return
	}
	raw := p.DialTCP(ctx, dialHost, dialPort)
	if raw == nil {
		return
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	hostHdr := p.res.Address
	if a.ProxyType != 0 {
		tctx, cancel := p.StageCtx(ctx, StageTransport)
		seSetDeadline(raw, tctx)
		ip := a.Host
		if a.ProxyType == 2 {
			if _, err := netip.ParseAddr(a.Host); err != nil {
				ips, lerr := net.DefaultResolver.LookupNetIP(tctx, "ip4", a.Host)
				if lerr != nil || len(ips) == 0 {
					cancel()
					p.Fail(StageDNS, StateDNSFailed, fmt.Errorf("no such host %s", a.Host))
					return
				}
				ip = ips[0].String()
			}
		}
		err := seProxyHandshake(raw, a, ip)
		if err != nil {
			err = seStageErr(err, tctx)
			cancel()
			p.Fail(StageTransport, seProxyState(err), err)
			return
		}
		cancel()
		p.Note("via %s proxy %s:%d", seProxyName(a.ProxyType), a.ProxyHost, a.ProxyPort)
		hostHdr = a.Host
	}
	hctx, hcancel := p.StageCtx(ctx, StageHandshake)
	defer hcancel()
	seSetDeadline(raw, hctx)
	tc := tls.Client(raw, seTLSConfig(a.Host))
	defer func() {
		raw.SetDeadline(time.Now().Add(500 * time.Millisecond))
		tc.Close()
	}()
	if err := tc.HandshakeContext(hctx); err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("TLS handshake: %v", seStageErr(err, hctx)))
		return
	}
	trusted, err := seCheckCert(tc.ConnectionState(), a.Host, a)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, err)
		return
	}
	br := bufio.NewReader(tc)
	t0 := time.Now()
	if err := seWriteSignature(tc, hostHdr); err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, seStageErr(err, hctx))
		return
	}
	hello, err := seReadPack(br, tc, hostHdr)
	rtt := time.Since(t0)
	if err != nil {
		p.Fail(StageHandshake, StateHandshakeFailed, seStageErr(err, hctx))
		return
	}
	if code := hello.getInt("error"); code != 0 {
		p.Fail(StageHandshake, StateHandshakeFailed, errors.New(seErrString(code)))
		return
	}
	random := hello.getData("random")
	srvStr, ok := hello.getStr("hello")
	if !ok || len(random) != 20 {
		p.Fail(StageHandshake, StateHandshakeFailed, fmt.Errorf("%w (invalid hello packet)", seErrNotVPN))
		return
	}
	p.Pass(StageHandshake)
	ver, build := hello.getInt("version"), hello.getInt("build")
	p.Note("server: %s %d.%02d build %d", seClean(srvStr), ver/100, ver%100, build)
	if !trusted {
		p.Note("server certificate not trusted")
	}
	ok, why := seHasCreds(a)
	if !ok {
		p.Note("%s", why)
		p.Connectable(rtt)
		return
	}
	actx, acancel := p.StageCtx(ctx, StageAuth)
	defer acancel()
	seSetDeadline(raw, actx)
	pk, err := seAuthPack(a, random, a.Host, a.Port)
	if err != nil {
		p.Note("auth not tested: %s", shortErr(err))
		p.Connectable(rtt)
		return
	}
	if err := seWritePack(tc, hostHdr, pk); err != nil {
		p.Fail(StageAuth, StateHandshakeFailed, seStageErr(err, actx))
		return
	}
	welcome, err := seReadPack(br, tc, hostHdr)
	if err != nil {
		p.Fail(StageAuth, StateHandshakeFailed, fmt.Errorf("authentication: %v", seStageErr(err, actx)))
		return
	}
	if code := welcome.getInt("error"); code != 0 {
		if seAuthErr(code) {
			p.Fail(StageAuth, StateAuthFailed, errors.New(seErrString(code)))
		} else {
			p.Fail(StageAuth, StateHandshakeFailed, errors.New(seErrString(code)))
		}
		return
	}
	if welcome.getInt("Redirect") != 0 {
		seWritePack(tc, hostHdr, &sePack{})
		p.Pass(StageAuth)
		p.Note("authenticated; redirected to cluster member")
		p.Connectable(rtt)
		return
	}
	if _, ok := welcome.getStr("session_name"); !ok {
		p.Fail(StageAuth, StateHandshakeFailed, errors.New("invalid welcome packet from server"))
		return
	}
	p.Pass(StageAuth)
	p.Note("session established (%s auth)", seAuthTypeName(a.AuthType))
	p.Connectable(rtt)
}

func seClean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80]
	}
	return strings.TrimSpace(s)
}
