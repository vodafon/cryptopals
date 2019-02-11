package c46_rsa_parity

import (
	"errors"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

type System struct {
	*c39_rsa.RSA
}

func NewSystem(bs int) System {
	rsa, err := c39_rsa.Generate(bs)
	if err != nil {
		panic(err)
	}
	return System{rsa}
}

func (obj System) IsEven(ciphertext []byte) bool {
	plaintext := obj.Decrypt(ciphertext)
	if len(plaintext) == 0 {
		panic("Invalid ciphertext")
	}
	return plaintext[len(plaintext)-1]%2 == 0
}

func Exploit(ciphertext []byte, s System) (*big.Int, error) {
	pubK := s.PublicKey()
	startN := big.NewInt(0)
	finN := new(big.Int).Set(pubK.N)
	c := new(big.Int).SetBytes(ciphertext)
	double := new(big.Int).Exp(big.NewInt(2), pubK.E, pubK.N)

	for startN.Cmp(new(big.Int).Sub(finN, big.NewInt(10))) <= 0 {
		c.Mul(c, double).Mod(c, pubK.N)
		sub := new(big.Int).Sub(finN, startN)
		sub.Div(sub, big.NewInt(2))
		if s.IsEven(c.Bytes()) {
			finN.Sub(finN, sub)
		} else {
			startN.Add(startN, sub)
		}
	}
	return bruteInterval(startN, finN, ciphertext, s)
}

func bruteInterval(startN, finN *big.Int, ciphertext []byte, s System) (*big.Int, error) {
	finN.Add(finN, big.NewInt(10))
	startN.Sub(startN, big.NewInt(10))
	pubK := s.PublicKey()
	c := new(big.Int).SetBytes(ciphertext)
	isEven := s.IsEven(c.Bytes())
	for finN.Cmp(startN) != 0 {
		if isEven != bigIsEven(startN) {
			startN.Add(startN, big.NewInt(1))
			continue
		}
		ciphertext1 := c39_rsa.Encrypt(startN.Bytes(), pubK)
		c1 := new(big.Int).SetBytes(ciphertext1)
		if c1.Cmp(c) == 0 {
			return startN, nil
		}
		startN.Add(startN, big.NewInt(1))
	}
	return nil, errors.New("not found")
}

func bigIsEven(b *big.Int) bool {
	bts := b.Bytes()
	return bts[len(bts)-1]%2 == 0
}
