package c41_unpadded_rsa

import (
	"bytes"
	"math/big"
	"testing"
)

func TestServer(t *testing.T) {
	msg := bytes.Repeat([]byte("A"), 20)
	server := NewServer()

	// first time encrypt - ALLOW
	ciphertext, err := server.Encrypt(msg)
	if err != nil {
		t.Errorf("Encrypt error: %s\n", err)
	}

	// second time encrypt - DENY
	_, err = server.Encrypt(msg)
	if err != AccessError {
		t.Errorf("Expected AccessError, got %s\n", err)
	}

	// first time decrypt same msg's ciphertext - DENY
	_, err = server.Decrypt(ciphertext)
	if err != AccessError {
		t.Errorf("Expected AccessError, got %s\n", err)
	}

	// first time decrypt another msg's ciphertext - ALLOW
	msgI := new(big.Int).SetBytes(msg)
	msgI.Sub(msgI, big.NewInt(1))
	_, err = server.Decrypt(msgI.Bytes())
	if err != nil {
		t.Errorf("Decrypt error: %s\n", err)
	}

	// second time decrypt msgI's ciphertext - DENY
	_, err = server.Decrypt(msgI.Bytes())
	if err != AccessError {
		t.Errorf("Expected AccessError, got %s\n", err)
	}
}
