package c42_bleichenbacher_e3

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
	"github.com/vodafon/cryptopals/set5/c40_rsa_broadcast"
)

type SignSystem struct {
	rsa *c39_rsa.RSA
}

func NewSignSystem(bs int) *SignSystem {
	rsa, err := c39_rsa.Generate(bs)
	if err != nil {
		panic(err)
	}
	return &SignSystem{rsa}
}

func (obj *SignSystem) Sign(message []byte) ([]byte, error) {
	return obj.rsa.SignPKCS(message)
}

func (obj *SignSystem) Verify(message, signature []byte) bool {
	return vulnerableVerify(message, signature, obj.rsa.PublicKey())
}

func Exploit(message []byte, size int) []byte {
	hash := crypto.SHA256
	prefix := HashPrefixes[hash]
	hashed := sha256.Sum256(message)
	res := make([]byte, size)
	res[0] = 0x00
	res[1] = 0x01
	res[2] = 0x00
	tail := append(prefix, hashed[:]...)
	copy(res[3:], tail)
	rI := new(big.Int).SetBytes(res)
	r, _ := c40_rsa_broadcast.CbrtBinary(rI)
	return r.Bytes()
}

func vulnerableVerify(message, signature []byte, pub c39_rsa.PublicKey) bool {
	hash := crypto.SHA256
	prefix := HashPrefixes[hash]
	hashed := sha256.Sum256(message)
	m := c39_rsa.Encrypt(signature, pub)
	em := leftPad(m, pub.Size())
	start := []byte{0x00, 0x01}
	if !bytes.Equal(em[:2], start) {
		return false
	}
	pos := 2
forLoop:
	for pos < len(em) {
		switch em[pos] {
		case 0xff:
			pos += 1
			continue
		case 0x00:
			pos += 1
			break forLoop
		default:
			return false // invalid signature
		}
	}
	s := em[pos:]
	if !bytes.Equal(s[:len(prefix)], prefix) {
		return false
	}
	s = em[pos+len(prefix):]
	if !bytes.Equal(s[:len(hashed)], hashed[:]) {
		return false
	}
	return true
}

func leftPad(src []byte, k int) []byte {
	if len(src) >= k {
		return src
	}
	res := make([]byte, k)
	copy(res[k-len(src):], src)
	return res
}

// from crypto/rsa/pkcs1v15.go

var HashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}
