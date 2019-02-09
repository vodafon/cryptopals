package c43_dsa_from_nonce

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

var (
	p, _ = new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	q, _ = new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	g, _ = new(big.Int).SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
)

type DSA struct {
	P    *big.Int
	Q    *big.Int
	G    *big.Int
	x    *big.Int
	Y    *big.Int
	MaxK *big.Int
}

func NewDSA() *DSA {
	dsa := DSA{
		P: p,
		Q: q,
		G: g,
	}
	dsa.x, _ = rand.Int(rand.Reader, dsa.Q)
	dsa.Y = new(big.Int).Exp(dsa.G, dsa.x, dsa.P)
	dsa.MaxK = dsa.Q
	return &dsa
}

func (obj *DSA) Sign(msg []byte) (*big.Int, *big.Int) {
	r, s, _ := obj.signK(msg)
	return r, s
}

func (obj *DSA) Verify(msg []byte, r, s *big.Int) bool {
	if r.Cmp(big.NewInt(0)) == 0 || r.Cmp(obj.Q) != -1 {
		return false
	}
	if s.Cmp(big.NewInt(0)) == 0 || s.Cmp(obj.Q) != -1 {
		return false
	}
	w := c39_rsa.InvMod(s, obj.Q)
	hmH := sha1.Sum(msg)
	hm := new(big.Int).SetBytes(hmH[:])
	u1 := new(big.Int).Mul(hm, w)
	u1.Mod(u1, obj.Q)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, obj.Q)
	gu1 := new(big.Int).Exp(obj.G, u1, obj.P)
	yu2 := new(big.Int).Exp(obj.Y, u2, obj.P)
	v := gu1.Mul(gu1, yu2)
	v.Mod(v, obj.P)
	v.Mod(v, obj.Q)
	return v.Cmp(r) == 0
}

func RecoverX(hm, r, s, q, k *big.Int) *big.Int {
	rI := c39_rsa.InvMod(r, q)
	x := new(big.Int).Mul(s, k)
	x.Sub(x, hm).Mul(x, rI).Mod(x, q)
	return x
}

func (obj *DSA) BruteK(msg []byte, r, s *big.Int) (*big.Int, error) {
	hmH := sha1.Sum(msg)
	hm := new(big.Int).SetBytes(hmH[:])
	for i := 0; i <= 2<<15; i++ {
		k := big.NewInt(int64(i))
		x := RecoverX(hm, r, s, obj.Q, k)
		rY := new(big.Int).Exp(obj.G, x, obj.P)
		if rY.Cmp(obj.Y) == 0 {
			return x, nil
		}
	}
	return nil, errors.New("not found")
}

func (obj *DSA) signK(msg []byte) (*big.Int, *big.Int, *big.Int) {
	k, _ := rand.Int(rand.Reader, obj.MaxK)
	r := new(big.Int).Exp(obj.G, k, obj.P)
	r.Mod(r, obj.Q)
	if r.Cmp(big.NewInt(0)) == 0 {
		return obj.signK(msg)
	}
	hmH := sha1.Sum(msg)
	hm := new(big.Int).SetBytes(hmH[:])
	ki := c39_rsa.InvMod(k, obj.Q)
	s := new(big.Int).Mul(obj.x, r)
	s.Add(s, hm)
	s.Mul(s, ki)
	s.Mod(s, obj.Q)
	if s.Cmp(big.NewInt(0)) == 0 {
		return obj.signK(msg)
	}
	return r, s, k
}
