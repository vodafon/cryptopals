package c41_unpadded_rsa

import (
	"crypto/rand"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

func Exploit(ciphertext []byte, server *Server) ([]byte, error) {
	var err error
	pk := server.PublicKey()
	s := big.NewInt(0)
	for s.Cmp(big.NewInt(0)) == 0 {
		s, err = rand.Int(rand.Reader, pk.Modulo)
		if err != nil {
			return nil, err
		}
	}
	c0 := new(big.Int).SetBytes(ciphertext)
	c1 := new(big.Int).Exp(s, pk.Base, pk.Modulo)
	c1.Mul(c1, c0)
	c1.Mod(c1, pk.Modulo)
	p1B, err := server.Decrypt(c1.Bytes())
	if err != nil {
		return nil, err
	}
	p1 := new(big.Int).SetBytes(p1B)
	p0 := new(big.Int).Mul(p1, c39_rsa.InvMod(s, pk.Modulo))
	p0.Mod(p0, pk.Modulo)
	return p0.Bytes(), nil
}
