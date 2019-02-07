package c41_unpadded_rsa

import (
	"bytes"
	"testing"
)

func TestExploit(t *testing.T) {
	msg := bytes.Repeat([]byte("A"), 20)
	server := NewServer()
	ciphertext, err := server.Encrypt(msg)
	if err != nil {
		t.Errorf("Encrypt error: %s\n", err)
	}

	res, err := Exploit(ciphertext, server)
	if err != nil {
		t.Errorf("Exploit error: %s\n", err)
	}
	if !bytes.Equal(msg, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", msg, res)
	}
}
