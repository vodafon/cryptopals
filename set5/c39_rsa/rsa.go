package c39_rsa

import (
	"crypto/rand"
	"math/big"
)

type RSA struct {
	Pub  Key
	priv Key
}

type Key struct {
	Base   *big.Int
	Modulo *big.Int
}

func Generate(bits int) (*RSA, error) {
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	if p.Cmp(q) == 0 {
		// repeat if p == q
		return Generate(bits)
	}
	n := new(big.Int).Mul(p, q)
	one := big.NewInt(1)
	et := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	e := big.NewInt(3)
	d := InvMod(e, et)
	if d == nil {
		return Generate(bits)
	}

	rsa := RSA{
		Pub:  Key{e, n},
		priv: Key{d, n},
	}
	return &rsa, nil
}

func Encrypt(plaintext []byte, pub Key) []byte {
	m := new(big.Int).SetBytes(plaintext)
	return m.Exp(m, pub.Base, pub.Modulo).Bytes()
}

func (obj *RSA) Decrypt(ciphertext []byte) []byte {
	c := new(big.Int).SetBytes(ciphertext)
	return c.Exp(c, obj.priv.Base, obj.priv.Modulo).Bytes()
}
