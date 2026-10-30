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
	"sync"
)

const (
	ike1EncDES     = 1
	ike1Enc3DES    = 5
	ike1EncAES     = 7
	ike1HashMD5    = 1
	ike1HashSHA1   = 2
	ike1HashSHA2   = 4
	ike1HashSHA3   = 5
	ike1HashSHA5   = 6
	ike1AuthPSK    = 1
	ike1AuthRSA    = 3
	ike1AuthHyb    = 64221
	ike1AuthXPSK   = 65001
	ike1AuthXRSA   = 65005
	ike1ModpG1     = 1
	ike1ModpG2     = 2
	ike1ModpG5     = 5
	ike1ModpG14    = 14
	ike1ModpG15    = 15
	ike1ModpG16    = 16
	ike1EcpG19     = 19
	ike1EcpG20     = 20
	ike1EcpG21     = 21
	ike1Curve25519 = 31
)

var ike1ModpHex = map[uint16]string{
	1:  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
	2:  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
	5:  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
	14: "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
	15: "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
	16: "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
}

var (
	ike1ModpOnce   sync.Once
	ike1ModpPrimes map[uint16]*big.Int
)

func ike1Modp(group uint16) *big.Int {
	ike1ModpOnce.Do(func() {
		ike1ModpPrimes = map[uint16]*big.Int{}
		for g, h := range ike1ModpHex {
			p, ok := new(big.Int).SetString(h, 16)
			if ok {
				ike1ModpPrimes[g] = p
			}
		}
	})
	return ike1ModpPrimes[group]
}

func ike1GroupSupported(group uint16) bool {
	switch group {
	case ike1EcpG19, ike1EcpG20, ike1EcpG21, ike1Curve25519:
		return true
	}
	_, ok := ike1ModpHex[group]
	return ok
}

func ike1GroupName(group uint16) string {
	switch group {
	case 1:
		return "modp768"
	case 2:
		return "modp1024"
	case 5:
		return "modp1536"
	case 14:
		return "modp2048"
	case 15:
		return "modp3072"
	case 16:
		return "modp4096"
	case 17:
		return "modp6144"
	case 18:
		return "modp8192"
	case 19:
		return "ecp256"
	case 20:
		return "ecp384"
	case 21:
		return "ecp521"
	case 31:
		return "curve25519"
	}
	return fmt.Sprintf("dh%d", group)
}

type ike1DH interface {
	Public() []byte
	Shared(peer []byte) ([]byte, error)
}

type ike1ModpDH struct {
	p   *big.Int
	x   *big.Int
	pub []byte
}

func (d *ike1ModpDH) Public() []byte { return d.pub }

func (d *ike1ModpDH) Shared(peer []byte) ([]byte, error) {
	n := (d.p.BitLen() + 7) / 8
	if len(peer) != n {
		return nil, fmt.Errorf("bad KE length %d for %d-bit group", len(peer), d.p.BitLen())
	}
	y := new(big.Int).SetBytes(peer)
	pm1 := new(big.Int).Sub(d.p, big.NewInt(1))
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pm1) >= 0 {
		return nil, errors.New("invalid peer DH public value")
	}
	z := new(big.Int).Exp(y, d.x, d.p)
	return z.FillBytes(make([]byte, n)), nil
}

type ike1EcDH struct {
	priv  *ecdh.PrivateKey
	pub   []byte
	plain bool
}

func (d *ike1EcDH) Public() []byte { return d.pub }

func (d *ike1EcDH) Shared(peer []byte) ([]byte, error) {
	b := peer
	if !d.plain {
		b = append([]byte{4}, peer...)
	}
	pk, err := d.priv.Curve().NewPublicKey(b)
	if err != nil {
		return nil, errors.New("invalid peer ECDH public value")
	}
	return d.priv.ECDH(pk)
}

func ike1NewDH(group uint16) (ike1DH, error) {
	var curve ecdh.Curve
	switch group {
	case ike1EcpG19:
		curve = ecdh.P256()
	case ike1EcpG20:
		curve = ecdh.P384()
	case ike1EcpG21:
		curve = ecdh.P521()
	case ike1Curve25519:
		curve = ecdh.X25519()
	}
	if curve != nil {
		k, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pub := k.PublicKey().Bytes()
		plain := group == ike1Curve25519
		if !plain {
			pub = pub[1:]
		}
		return &ike1EcDH{priv: k, pub: pub, plain: plain}, nil
	}
	p := ike1Modp(group)
	if p == nil {
		return nil, fmt.Errorf("unsupported DH group %d", group)
	}
	xb := make([]byte, 64)
	if _, err := rand.Read(xb); err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xb)
	x.SetBit(x, 511, 1)
	y := new(big.Int).Exp(big.NewInt(2), x, p)
	n := (p.BitLen() + 7) / 8
	return &ike1ModpDH{p: p, x: x, pub: y.FillBytes(make([]byte, n))}, nil
}

func ike1HashFn(id uint16) func() hash.Hash {
	switch id {
	case ike1HashMD5:
		return md5.New
	case ike1HashSHA1:
		return sha1.New
	case ike1HashSHA2:
		return sha256.New
	case ike1HashSHA3:
		return sha512.New384
	case ike1HashSHA5:
		return sha512.New
	}
	return nil
}

func ike1HashName(id uint16) string {
	switch id {
	case ike1HashMD5:
		return "md5"
	case ike1HashSHA1:
		return "sha1"
	case ike1HashSHA2:
		return "sha256"
	case ike1HashSHA3:
		return "sha384"
	case ike1HashSHA5:
		return "sha512"
	}
	return fmt.Sprintf("hash%d", id)
}

func ike1EncName(enc, keyLen uint16) string {
	switch enc {
	case ike1EncAES:
		if keyLen == 0 {
			keyLen = 128
		}
		return fmt.Sprintf("aes%d", keyLen)
	case ike1Enc3DES:
		return "3des"
	case ike1EncDES:
		return "des"
	}
	return fmt.Sprintf("enc%d", enc)
}

func ike1EncKeyBytes(enc, keyLen uint16) int {
	switch enc {
	case ike1EncAES:
		switch keyLen {
		case 0, 128:
			return 16
		case 192:
			return 24
		case 256:
			return 32
		}
	case ike1Enc3DES:
		return 24
	case ike1EncDES:
		return 8
	}
	return 0
}

func ike1NewCipher(enc uint16, key []byte) (cipher.Block, error) {
	switch enc {
	case ike1EncAES:
		return aes.NewCipher(key)
	case ike1Enc3DES:
		return des.NewTripleDESCipher(key)
	case ike1EncDES:
		return des.NewCipher(key)
	}
	return nil, fmt.Errorf("unsupported cipher %d", enc)
}

func ike1PRF(h func() hash.Hash, key []byte, data ...[]byte) []byte {
	m := hmac.New(h, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

func ike1Digest(h func() hash.Hash, data ...[]byte) []byte {
	m := h()
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

func ike1CBCEncrypt(b cipher.Block, iv, plain []byte) []byte {
	bs := b.BlockSize()
	n := len(plain)
	if n%bs != 0 {
		n += bs - n%bs
	}
	buf := make([]byte, n)
	copy(buf, plain)
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(buf, buf)
	return buf
}

func ike1CBCDecrypt(b cipher.Block, iv, ct []byte) ([]byte, error) {
	bs := b.BlockSize()
	if len(ct) == 0 || len(ct)%bs != 0 {
		return nil, fmt.Errorf("encrypted body length %d is not a multiple of the %d-byte block", len(ct), bs)
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, ct)
	return out, nil
}

func ike1Random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
