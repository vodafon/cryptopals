package c40_rsa_broadcast

import (
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

type Broadcast struct {
	plaintext []byte
	keys      []*c39_rsa.RSA
}

func (obj *Broadcast) Capture() map[c39_rsa.PublicKey][]byte {
	capt := make(map[c39_rsa.PublicKey][]byte, len(obj.keys))
	for _, rsa := range obj.keys {
		capt[rsa.PublicKey()] = c39_rsa.Encrypt(obj.plaintext, rsa.PublicKey())
	}
	return capt
}

func NewBroadcast(plaintext []byte, n, bits int) *Broadcast {
	br := Broadcast{
		plaintext: plaintext,
	}

	for i := 0; i < n; i++ {
		rsa, err := c39_rsa.Generate(bits)
		if err != nil {
			panic(err)
		}
		br.keys = append(br.keys, rsa)
	}
	return &br
}

func Exploit(capt map[c39_rsa.PublicKey][]byte) *big.Int {
	NN := big.NewInt(1)
	res := new(big.Int)
	for k, c := range capt {
		cn := new(big.Int).SetBytes(c)
		msn := MSN(k, capt)
		im := c39_rsa.InvMod(msn, k.N)
		mul := new(big.Int).Mul(cn, msn)
		mul.Mul(mul, im)
		res.Add(res, mul)
		NN.Mul(NN, k.N)
	}
	res.Mod(res, NN)
	cb, _ := CbrtBinary(res)
	return cb
}

func MSN(k c39_rsa.PublicKey, capt map[c39_rsa.PublicKey][]byte) *big.Int {
	res := big.NewInt(1)
	for key := range capt {
		if key == k {
			continue
		}
		res.Mul(res, key.N)
	}
	return res
}

// from https://play.golang.org/p/uoEmxRK5jgs
func CbrtBinary(i *big.Int) (cbrt *big.Int, rem *big.Int) {
	n0 := big.NewInt(0)
	n1 := big.NewInt(1)
	n2 := big.NewInt(2)
	n3 := big.NewInt(3)
	guess := new(big.Int).Div(i, n2)
	dx := new(big.Int)
	absDx := new(big.Int)
	minDx := new(big.Int).Abs(i)
	step := new(big.Int).Abs(new(big.Int).Div(guess, n2))
	cube := new(big.Int)
	for {
		cube.Exp(guess, n3, nil)
		dx.Sub(i, cube)
		cmp := dx.Cmp(n0)
		if cmp == 0 {
			return guess, n0
		}

		absDx.Abs(dx)
		switch absDx.Cmp(minDx) {
		case -1:
			minDx.Set(absDx)
		case 0:
			return guess, dx
		}

		switch cmp {
		case -1:
			guess.Sub(guess, step)
		case +1:
			guess.Add(guess, step)
		}

		step.Div(step, n2)
		if step.Cmp(n0) == 0 {
			step.Set(n1)
		}
	}
}
