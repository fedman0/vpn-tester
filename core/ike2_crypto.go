package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ike2TEncr  = 1
	ike2TPRF   = 2
	ike2TInteg = 3
	ike2TDH    = 4
	ike2TESN   = 5

	ike2EncrDES3     = 3
	ike2EncrAESCBC   = 12
	ike2EncrAESGCM12 = 19
	ike2EncrAESGCM16 = 20
	ike2EncrChaCha   = 28

	ike2PRFMD5    = 1
	ike2PRFSHA1   = 2
	ike2PRFSHA256 = 5
	ike2PRFSHA384 = 6
	ike2PRFSHA512 = 7

	ike2IntegNone   = 0
	ike2IntegMD5    = 1
	ike2IntegSHA1   = 2
	ike2IntegSHA256 = 12
	ike2IntegSHA384 = 13
	ike2IntegSHA512 = 14
)

const ike2ModpPrefix = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE"

const ike2Modp2048Body = "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA"

const ike2Modp4096Body = ike2Modp2048Body + "18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A9"

var ike2ModpHex = map[uint16]string{
	2:  ike2ModpPrefix + "65381FFFFFFFFFFFFFFFF",
	5:  ike2ModpPrefix + ike2Modp2048Body + "237327FFFFFFFFFFFFFFFF",
	14: ike2ModpPrefix + ike2Modp2048Body + "18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
	15: ike2ModpPrefix + ike2Modp4096Body + "3AD2CAFFFFFFFFFFFFFFFF",
	16: ike2ModpPrefix + ike2Modp4096Body + "2108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
}

var ike2ModpBits = map[uint16]int{2: 1024, 5: 1536, 14: 2048, 15: 3072, 16: 4096}

type ike2KE interface {
	Group() uint16
	Public() []byte
	Shared(peer []byte) ([]byte, error)
}

type ike2Modp struct {
	group uint16
	p     *big.Int
	x     *big.Int
	pub   []byte
}

func (m *ike2Modp) Group() uint16  { return m.group }
func (m *ike2Modp) Public() []byte { return m.pub }

func (m *ike2Modp) Shared(peer []byte) ([]byte, error) {
	n := (m.p.BitLen() + 7) / 8
	if len(peer) != n {
		return nil, fmt.Errorf("bad MODP public value length %d", len(peer))
	}
	y := new(big.Int).SetBytes(peer)
	pm1 := new(big.Int).Sub(m.p, big.NewInt(1))
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pm1) >= 0 {
		return nil, errors.New("invalid MODP public value")
	}
	z := new(big.Int).Exp(y, m.x, m.p)
	return z.FillBytes(make([]byte, n)), nil
}

type ike2EC struct {
	group uint16
	curve ecdh.Curve
	key   *ecdh.PrivateKey
	nist  bool
}

func (e *ike2EC) Group() uint16 { return e.group }

func (e *ike2EC) Public() []byte {
	b := e.key.PublicKey().Bytes()
	if e.nist {
		return b[1:]
	}
	return b
}

func (e *ike2EC) Shared(peer []byte) ([]byte, error) {
	if e.nist {
		peer = append([]byte{4}, peer...)
	}
	pk, err := e.curve.NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return e.key.ECDH(pk)
}

func ike2KESupported(g uint16) bool {
	switch g {
	case 2, 5, 14, 15, 16, 19, 20, 21, 31:
		return true
	}
	return false
}

func ike2NewKE(g uint16) (ike2KE, error) {
	switch g {
	case 19, 20, 21, 31:
		var c ecdh.Curve
		switch g {
		case 19:
			c = ecdh.P256()
		case 20:
			c = ecdh.P384()
		case 21:
			c = ecdh.P521()
		default:
			c = ecdh.X25519()
		}
		k, err := c.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &ike2EC{group: g, curve: c, key: k, nist: g != 31}, nil
	}
	h, ok := ike2ModpHex[g]
	if !ok {
		return nil, fmt.Errorf("DH group %d not supported", g)
	}
	p, _ := new(big.Int).SetString(h, 16)
	if p.BitLen() != ike2ModpBits[g] {
		return nil, fmt.Errorf("DH group %d prime corrupted", g)
	}
	xb := make([]byte, 64)
	if _, err := rand.Read(xb); err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xb)
	x.SetBit(x, 511, 1)
	y := new(big.Int).Exp(big.NewInt(2), x, p)
	n := (p.BitLen() + 7) / 8
	return &ike2Modp{group: g, p: p, x: x, pub: y.FillBytes(make([]byte, n))}, nil
}

func ike2PRFHash(id uint16) func() hash.Hash {
	switch id {
	case ike2PRFMD5:
		return md5.New
	case ike2PRFSHA1:
		return sha1.New
	case ike2PRFSHA256:
		return sha256.New
	case ike2PRFSHA384:
		return sha512.New384
	case ike2PRFSHA512:
		return sha512.New
	}
	return nil
}

func ike2IntegInfo(id uint16) (func() hash.Hash, int, int) {
	switch id {
	case ike2IntegMD5:
		return md5.New, 16, 12
	case ike2IntegSHA1:
		return sha1.New, 20, 12
	case ike2IntegSHA256:
		return sha256.New, 32, 16
	case ike2IntegSHA384:
		return sha512.New384, 48, 24
	case ike2IntegSHA512:
		return sha512.New, 64, 32
	}
	return nil, 0, 0
}

func ike2Mac(h func() hash.Hash, key []byte, data ...[]byte) []byte {
	m := hmac.New(h, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

func ike2PRFPlus(h func() hash.Hash, key, seed []byte, n int) []byte {
	var out, t []byte
	for i := 1; len(out) < n; i++ {
		t = ike2Mac(h, key, t, seed, []byte{byte(i)})
		out = append(out, t...)
	}
	return out[:n]
}

type ike2Suite struct {
	Encr    uint16
	KeyBits int
	Integ   uint16
	PRF     uint16
	DH      uint16
}

func (s ike2Suite) aead() bool {
	return s.Encr == ike2EncrAESGCM16 || s.Encr == ike2EncrAESGCM12 || s.Encr == ike2EncrChaCha
}

func (s ike2Suite) encKeyLen() int {
	switch s.Encr {
	case ike2EncrDES3:
		return 24
	case ike2EncrChaCha:
		return 36
	case ike2EncrAESGCM16, ike2EncrAESGCM12:
		return s.KeyBits/8 + 4
	}
	return s.KeyBits / 8
}

func (s ike2Suite) String() string {
	enc := map[uint16]string{ike2EncrDES3: "3DES", ike2EncrAESCBC: "AES_CBC", ike2EncrAESGCM16: "AES_GCM_16", ike2EncrAESGCM12: "AES_GCM_12", ike2EncrChaCha: "CHACHA20_POLY1305"}[s.Encr]
	if s.KeyBits > 0 && s.Encr != ike2EncrChaCha {
		enc += fmt.Sprintf("_%d", s.KeyBits)
	}
	integ := map[uint16]string{ike2IntegMD5: "/HMAC_MD5_96", ike2IntegSHA1: "/HMAC_SHA1_96", ike2IntegSHA256: "/HMAC_SHA2_256_128", ike2IntegSHA384: "/HMAC_SHA2_384_192", ike2IntegSHA512: "/HMAC_SHA2_512_256"}[s.Integ]
	prf := map[uint16]string{ike2PRFMD5: "PRF_HMAC_MD5", ike2PRFSHA1: "PRF_HMAC_SHA1", ike2PRFSHA256: "PRF_HMAC_SHA2_256", ike2PRFSHA384: "PRF_HMAC_SHA2_384", ike2PRFSHA512: "PRF_HMAC_SHA2_512"}[s.PRF]
	return fmt.Sprintf("%s%s/%s/%s", enc, integ, prf, ike2GroupName(s.DH))
}

func ike2GroupName(g uint16) string {
	switch g {
	case 2:
		return "MODP_1024"
	case 5:
		return "MODP_1536"
	case 14:
		return "MODP_2048"
	case 15:
		return "MODP_3072"
	case 16:
		return "MODP_4096"
	case 17:
		return "MODP_6144"
	case 18:
		return "MODP_8192"
	case 19:
		return "ECP_256"
	case 20:
		return "ECP_384"
	case 21:
		return "ECP_521"
	case 31:
		return "CURVE_25519"
	case 32:
		return "CURVE_448"
	}
	return fmt.Sprintf("DH_%d", g)
}

type ike2Dir struct {
	block  cipher.Block
	aead   cipher.AEAD
	salt   []byte
	integK []byte
}

type ike2Keys struct {
	suite           ike2Suite
	prf             func() hash.Hash
	integ           func() hash.Hash
	icvLen          int
	ivLen           int
	block           int
	skd, skpi, skpr []byte
	out, in         ike2Dir
}

func ike2Derive(s ike2Suite, ni, nr, gir []byte, spiI, spiR [8]byte) (*ike2Keys, error) {
	prf := ike2PRFHash(s.PRF)
	if prf == nil {
		return nil, fmt.Errorf("unsupported PRF %d", s.PRF)
	}
	k := &ike2Keys{suite: s, prf: prf}
	prfLen := prf().Size()
	integLen := 0
	if !s.aead() {
		var trunc int
		k.integ, integLen, trunc = ike2IntegInfo(s.Integ)
		if k.integ == nil {
			return nil, fmt.Errorf("unsupported integrity algorithm %d", s.Integ)
		}
		k.icvLen = trunc
	} else {
		k.icvLen = 16
		if s.Encr == ike2EncrAESGCM12 {
			k.icvLen = 12
		}
	}
	encLen := s.encKeyLen()
	if encLen <= 0 {
		return nil, fmt.Errorf("unsupported encryption algorithm %d", s.Encr)
	}
	skeyseed := ike2Mac(prf, append(append([]byte{}, ni...), nr...), gir)
	seed := append(append(append(append([]byte{}, ni...), nr...), spiI[:]...), spiR[:]...)
	km := ike2PRFPlus(prf, skeyseed, seed, 3*prfLen+2*integLen+2*encLen)
	take := func(n int) []byte {
		b := km[:n]
		km = km[n:]
		return b
	}
	k.skd = take(prfLen)
	ai := take(integLen)
	ar := take(integLen)
	ei := take(encLen)
	er := take(encLen)
	k.skpi = take(prfLen)
	k.skpr = take(prfLen)
	var err error
	if k.out, err = k.dir(ei, ai); err != nil {
		return nil, err
	}
	if k.in, err = k.dir(er, ar); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *ike2Keys) dir(ek, ak []byte) (ike2Dir, error) {
	d := ike2Dir{integK: ak}
	s := k.suite
	switch s.Encr {
	case ike2EncrAESCBC:
		b, err := aes.NewCipher(ek)
		if err != nil {
			return d, err
		}
		d.block = b
		k.ivLen, k.block = 16, 16
	case ike2EncrDES3:
		b, err := des.NewTripleDESCipher(ek)
		if err != nil {
			return d, err
		}
		d.block = b
		k.ivLen, k.block = 8, 8
	case ike2EncrAESGCM16, ike2EncrAESGCM12:
		b, err := aes.NewCipher(ek[:len(ek)-4])
		if err != nil {
			return d, err
		}
		a, err := cipher.NewGCMWithTagSize(b, k.icvLen)
		if err != nil {
			return d, err
		}
		d.aead, d.salt = a, ek[len(ek)-4:]
		k.ivLen, k.block = 8, 1
	case ike2EncrChaCha:
		a, err := chacha20poly1305.New(ek[:32])
		if err != nil {
			return d, err
		}
		d.aead, d.salt = a, ek[32:]
		k.ivLen, k.block = 8, 1
	default:
		return d, fmt.Errorf("unsupported encryption algorithm %d", s.Encr)
	}
	return d, nil
}

func (k *ike2Keys) sealedLen(plain int) int {
	if k.suite.aead() {
		return k.ivLen + plain + 1 + k.icvLen
	}
	n := plain + 1
	if r := n % k.block; r != 0 {
		n += k.block - r
	}
	return k.ivLen + n + k.icvLen
}

func (k *ike2Keys) seal(msg []byte, bodyOff int, plain []byte) error {
	d := k.out
	iv := msg[bodyOff : bodyOff+k.ivLen]
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	if k.suite.aead() {
		pt := append(append([]byte{}, plain...), 0)
		nonce := append(append([]byte{}, d.salt...), iv...)
		ct := d.aead.Seal(nil, nonce, pt, msg[:bodyOff])
		copy(msg[bodyOff+k.ivLen:], ct)
		return nil
	}
	n := len(msg) - bodyOff - k.ivLen - k.icvLen
	pad := n - len(plain) - 1
	pt := make([]byte, n)
	copy(pt, plain)
	pt[n-1] = byte(pad)
	cipher.NewCBCEncrypter(d.block, iv).CryptBlocks(msg[bodyOff+k.ivLen:bodyOff+k.ivLen+n], pt)
	icv := ike2Mac(k.integ, d.integK, msg[:len(msg)-k.icvLen])
	copy(msg[len(msg)-k.icvLen:], icv[:k.icvLen])
	return nil
}

func (k *ike2Keys) open(msg []byte, bodyOff int) ([]byte, error) {
	d := k.in
	if len(msg)-bodyOff < k.ivLen+k.icvLen+1 {
		return nil, errors.New("encrypted payload too short")
	}
	iv := msg[bodyOff : bodyOff+k.ivLen]
	var pt []byte
	if k.suite.aead() {
		nonce := append(append([]byte{}, d.salt...), iv...)
		var err error
		pt, err = d.aead.Open(nil, nonce, msg[bodyOff+k.ivLen:], msg[:bodyOff])
		if err != nil {
			return nil, errors.New("integrity check failed")
		}
	} else {
		icv := ike2Mac(k.integ, d.integK, msg[:len(msg)-k.icvLen])
		if !hmac.Equal(icv[:k.icvLen], msg[len(msg)-k.icvLen:]) {
			return nil, errors.New("integrity check failed")
		}
		ct := msg[bodyOff+k.ivLen : len(msg)-k.icvLen]
		if len(ct) == 0 || len(ct)%k.block != 0 {
			return nil, errors.New("bad ciphertext length")
		}
		pt = make([]byte, len(ct))
		cipher.NewCBCDecrypter(d.block, iv).CryptBlocks(pt, ct)
	}
	if len(pt) == 0 {
		return nil, errors.New("empty plaintext")
	}
	pad := int(pt[len(pt)-1])
	if pad+1 > len(pt) {
		return nil, errors.New("bad padding")
	}
	return pt[:len(pt)-1-pad], nil
}
