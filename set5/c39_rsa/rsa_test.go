package c39_rsa

import (
	"bytes"
	"testing"
)

func TestRSA(t *testing.T) {
	rsa, err := Generate(512)
	if err != nil {
		t.Fatalf("Generate error: %s\n", err)
	}
	inp := []byte("Some text")
	enc := Encrypt(inp, rsa.PublicKey())
	if bytes.Equal(enc, inp) {
		t.Errorf("Ciphertext same as plaintext\n")
	}
	res := rsa.Decrypt(enc)
	if !bytes.Equal(inp, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", inp, res)
	}
}

func TestSign(t *testing.T) {
	rsa, err := Generate(512)
	if err != nil {
		t.Fatalf("Generate error: %s\n", err)
	}
	msg := bytes.Repeat([]byte("A"), 20)
	sign, err := rsa.SignPKCS(msg)
	if err != nil {
		t.Errorf("Sign error: %s\n", err)
	}

	// valid
	ver, err := rsa.VerifyPKCS(msg, sign)
	if err != nil {
		t.Errorf("Sign error: %s\n", err)
	}
	if !ver {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}

	ver, _ = rsa.VerifyPKCS(msg[1:], sign)
	if ver {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}
