package c47_c48_bb98

import (
	"bytes"
	"testing"
)

func TestValidPadding(t *testing.T) {
	bb := NewBB98(256)
	msg := []byte("kick it, CC")
	c, _ := bb.Encrypt(msg)
	if !bb.IsValidPKCS(c) {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}

	if bb.IsValidPKCS(c[3:]) {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}

func TestExploitC47(t *testing.T) {
	bb := NewBB98(256)
	msg := []byte("kick it, CC")
	c, _ := bb.Encrypt(msg)
	m := bb.Decrypt(c)
	res := Exploit(c, bb)
	if !bytes.Equal(m, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", m, res)
	}
}

func TestExploitC48(t *testing.T) {
	bb := NewBB98(768)
	if bb.rsa.PublicKey().N.BitLen() != 768 {
		t.Errorf("Incorrect modulo size. Expected 768, got %d\n", bb.rsa.PublicKey().N.BitLen())
	}
	msg := []byte("kick it, CC")
	c, _ := bb.Encrypt(msg)
	m := bb.Decrypt(c)
	res := Exploit(c, bb)
	if !bytes.Equal(m, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", m, res)
	}
}
