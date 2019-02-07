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
	enc := Encrypt(inp, rsa.Pub)
	if bytes.Equal(enc, inp) {
		t.Errorf("Ciphertext same as plaintext\n")
	}
	res := rsa.Decrypt(enc)
	if !bytes.Equal(inp, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", inp, res)
	}
}
