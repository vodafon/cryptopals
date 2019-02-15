package c45_dsa_tampering

import (
	"testing"

	"github.com/vodafon/cryptopals/set6/c43_dsa_from_nonce"
)

func TestExploitG0(t *testing.T) {
	dsa := c43_dsa_from_nonce.NewDSA()
	msg := []byte("Hello, world")
	r, s := ExploitG0(dsa, msg)
	if !dsa.Verify(msg, r, s) {
		t.Errorf("Incorrect result")
	}

	msg = []byte("Goodbye, world")
	r, s = ExploitG0(dsa, msg)
	if !dsa.Verify(msg, r, s) {
		t.Errorf("Incorrect result")
	}
}

func TestExploitGP1(t *testing.T) {
	dsa := c43_dsa_from_nonce.NewDSA()
	msg := []byte("Hello, world")
	r, s := ExploitGP1(dsa, msg)
	if !dsa.Verify(msg, r, s) {
		t.Errorf("Incorrect result")
	}

	msg = []byte("Goodbye, world")
	r, s = ExploitGP1(dsa, msg)
	if !dsa.Verify(msg, r, s) {
		t.Errorf("Incorrect result")
	}
}
