package c49_cbc_mac_forgery

import (
	"bytes"
	"testing"
)

func TestValidation(t *testing.T) {
	key := bytes.Repeat([]byte("K"), 16)
	msg := bytes.Repeat([]byte("M"), 24)
	cbc := NewCBCMAC(key)
	iv, mac := cbc.Sign(msg)
	if !cbc.Validation(msg, iv, mac) {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}

	mac[0] ^= 0x42
	if cbc.Validation(msg, iv, mac) {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}
