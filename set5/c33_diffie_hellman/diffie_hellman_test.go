package c33_diffie_hellman

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestGenerate(t *testing.T) {
	dh := NewDHSystem()
	sess := dh.SessionKeySHA256()
	sA := sha256.Sum256(new(big.Int).Exp(dh.PubKA, dh.b, dh.p).Bytes())
	sB := sha256.Sum256(new(big.Int).Exp(dh.PubKB, dh.a, dh.p).Bytes())

	if sess != sA || sess != sB {
		t.Errorf("Incorrect result. SessionKey %x, expected A: %x, B: %x\n", sess, sA, sB)
	}
}
