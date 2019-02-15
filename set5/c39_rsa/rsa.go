package c39_rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
)

var ErrMessageTooLong = errors.New("message too long for RSA public key size")

type RSA struct {
	privateKey *rsa.PrivateKey
}

type PublicKey struct {
	E *big.Int
	N *big.Int
}

func (pub PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

func (obj *RSA) PublicKey() PublicKey {
	pk := obj.RSAPublicKey()
	return PublicKey{
		E: big.NewInt(int64(pk.E)),
		N: pk.N,
	}
}

func (obj *RSA) RSAPublicKey() rsa.PublicKey {
	return obj.privateKey.PublicKey
}

type Key struct {
	Base   *big.Int
	Modulo *big.Int
}

func Generate(bits int) (*RSA, error) {
	priv := new(rsa.PrivateKey)
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	if p.Cmp(q) == 0 {
		// repeat if p == q
		return Generate(bits)
	}
	priv.Primes = append(priv.Primes, p)
	priv.Primes = append(priv.Primes, q)
	n := new(big.Int).Mul(p, q)
	priv.N = n
	one := big.NewInt(1)
	et := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	e := big.NewInt(3)
	priv.E = 3
	d := InvMod(e, et)
	if d == nil {
		return Generate(bits)
	}
	priv.D = d
	priv.Precompute()

	rsa := RSA{
		privateKey: priv,
	}
	return &rsa, nil
}

func Encrypt(plaintext []byte, pub PublicKey) []byte {
	m := new(big.Int).SetBytes(plaintext)
	if m.Cmp(pub.N) > 0 {
		panic(ErrMessageTooLong)
	}
	return m.Exp(m, pub.E, pub.N).Bytes()
}

func (obj *RSA) Decrypt(ciphertext []byte) []byte {
	c := new(big.Int).SetBytes(ciphertext)
	if c.Cmp(obj.privateKey.N) > 0 {
		panic(ErrMessageTooLong)
	}
	return c.Exp(c, obj.privateKey.D, obj.privateKey.N).Bytes()
}

func (obj *RSA) SignPKCS(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, obj.privateKey, crypto.SHA256, hashed[:])
}

func (obj *RSA) VerifyPKCS(message, signature []byte) (bool, error) {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(&obj.privateKey.PublicKey, crypto.SHA256, hashed[:], signature)

	if err != nil {
		return false, err
	}
	return true, nil
}
