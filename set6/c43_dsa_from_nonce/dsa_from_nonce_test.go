package c43_dsa_from_nonce

import (
	"bytes"
	"crypto/sha1"
	"math/big"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestSing(t *testing.T) {
	dsa := NewDSA()
	msg := []byte("Some text")
	r, s := dsa.Sign(msg)
	ver := dsa.Verify(msg, r, s)
	if !ver {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}
	ver = dsa.Verify(msg[1:], r, s)
	if ver {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}

func TestRecoverX(t *testing.T) {
	dsa := NewDSA()
	msg := []byte("Some text")
	r, s, k := dsa.signK(msg)
	hmH := sha1.Sum(msg)
	hm := new(big.Int).SetBytes(hmH[:])
	x := RecoverX(hm, r, s, dsa.Q, k)
	if x.Cmp(dsa.x) != 0 {
		t.Errorf("Incorrect result. Expected %x, got %x\n", dsa.x, x)
	}
}

func TestBruteK1(t *testing.T) {
	dsa := NewDSA()
	dsa.MaxK = big.NewInt(2 << 15) // 2**16
	msg := []byte("Some text")
	r, s := dsa.Sign(msg)
	exp := dsa.x
	dsa.x = big.NewInt(0)
	x, err := dsa.BruteK(msg, r, s)
	if err != nil {
		t.Fatalf("BruteK error: %s\n", err)
	}
	if x.Cmp(exp) != 0 {
		t.Errorf("Incorrect result. Expected %x, got %x\n", exp, x)
	}
}

func TestBruteK2(t *testing.T) {
	dsa := NewDSA()
	dsa.MaxK = big.NewInt(2 << 15) // 2**16
	dsa.Y.SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	msg := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
	r, _ := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)
	dsa.x = big.NewInt(0)
	x, err := dsa.BruteK(msg, r, s)
	if err != nil {
		t.Fatalf("BruteK error: %s\n", err)
	}
	hex := c1_hex_to_base64.EncodeHex(x.Bytes())
	sum := sha1.Sum(hex)
	res := c1_hex_to_base64.EncodeHex(sum[:])
	exp := []byte("0954edd5e0afe5542a4adf012611a91912a3ec16")
	if !bytes.Equal(exp, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, res)
	}
}
