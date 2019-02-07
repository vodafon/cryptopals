package c37_break_srp

import (
	"crypto/sha256"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c36_srp"
)

func Exploit(stream c36_srp.Stream, pk *big.Int) bool {
	stream.C.Pub = pk
	key := sha256.Sum256(big.NewInt(0).Bytes())
	stream.C.Key = key[:]
	stream.C.Password = []byte("wrongPass")
	return stream.Auth()
}
