package c46_rsa_parity

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

func TestIsEven(t *testing.T) {
	s := NewSystem(1024)
	ciphertext := c39_rsa.Encrypt(big.NewInt(127832).Bytes(), s.PublicKey())
	res := s.IsEven(ciphertext)
	if !res {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}

	ciphertext = c39_rsa.Encrypt(big.NewInt(1289301).Bytes(), s.PublicKey())
	res = s.IsEven(ciphertext)
	if res {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}

func TestExploit1(t *testing.T) {
	s := NewSystem(1024)
	inp := []byte("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
	exp, err := c1_hex_to_base64.DecodeBase64(inp)
	if err != nil {
		t.Fatalf("DecodeBase64 error: %s\n", err)
	}
	ciphertext := c39_rsa.Encrypt(exp, s.PublicKey())
	//m := new(big.Int).SetBytes(exp)
	res, err := Exploit(ciphertext, s)
	if err != nil {
		t.Fatalf("Exploit error: %s\n", err)
	}
	if !bytes.Equal(exp, res.Bytes()) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, res.Bytes())
	}
}
