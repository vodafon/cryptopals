package c45_dsa_tampering

import (
	"math/big"

	"github.com/vodafon/cryptopals/set6/c43_dsa_from_nonce"
)

func ExploitG0(dsa *c43_dsa_from_nonce.DSA, msg []byte) (*big.Int, *big.Int) {
	dsa.G = big.NewInt(0)
	return big.NewInt(0), big.NewInt(1)
}

func ExploitGP1(dsa *c43_dsa_from_nonce.DSA, msg []byte) (*big.Int, *big.Int) {
	dsa.G.Add(dsa.P, big.NewInt(1))

	///// ver (g=p+1, r=y%q, s=y%q)
	// w = s**-1 % q = 1/y
	// u2 = r*w % q = y/y = 1
	// v = (y**u2) % p % q = y**1 = y
	// v == r

	yq := new(big.Int).Mod(dsa.Y, dsa.Q)
	return yq, yq
}
