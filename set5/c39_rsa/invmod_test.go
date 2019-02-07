package c39_rsa

import (
	"math/big"
	"testing"
)

func TestInvMod(t *testing.T) {
	res := InvMod(big.NewInt(17), big.NewInt(3120))
	if res.Cmp(big.NewInt(2753)) != 0 {
		t.Errorf("Incorrect result. Expected 2753, got %d\n", res)
	}
}

func TestDivMod(t *testing.T) {
	x, y := DivMod(bi(17), bi(2))
	if x.Cmp(bi(8)) != 0 {
		t.Errorf("wrong x")
	}
	if y.Cmp(bi(1)) != 0 {
		t.Errorf("wrong y")
	}
}

func TestEGCD(t *testing.T) {
	x, y := EGCD(bi(1712), bi(2780))
	if x.Cmp(bi(4)) != 0 {
		t.Errorf("wrong x")
	}
	if y.Cmp(bi(177)) != 0 {
		t.Errorf("wrong y")
	}
}
