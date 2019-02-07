package c33_diffie_hellman

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	dh1 := NewDHSystem()
	dh2 := NewDHSystem()

	if dh1.Pub == dh2.Pub {
		t.Errorf("Public keys are equal")
	}

	if dh1.SessionKeySHA256(dh2.Pub) != dh2.SessionKeySHA256(dh1.Pub) {
		t.Errorf("Invalid session keys\n")
	}
}
