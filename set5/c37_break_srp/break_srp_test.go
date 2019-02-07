package c37_break_srp

import (
	"math/big"
	"testing"

	"github.com/vodafon/cryptopals/set5/c36_srp"
)

func TestExploit(t *testing.T) {
	email := []byte("email@test.com")
	password := []byte("paSSw0rD")
	keys := []*big.Int{big.NewInt(0), c36_srp.N, new(big.Int).Mul(c36_srp.N, big.NewInt(2))}
	for i, pk := range keys {
		stream := c36_srp.Init(email, password)
		if !Exploit(stream, pk) {
			t.Errorf("Incorrect result (i: %d), Pub: %x.\n", i, pk)
		}
	}
}
