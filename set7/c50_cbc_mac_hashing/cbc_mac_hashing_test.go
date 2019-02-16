package c50_cbc_mac_hashing

import (
	"bytes"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestSign(t *testing.T) {
	inp := []byte("alert('MZA who was that?');\n")
	hm := NewHashCBC()
	exp := c1_hex_to_base64.ParseHex("296b8d7cb78a243dda4d0a61d33bbdd1")
	res := hm.Sign(inp)
	if !bytes.Equal(res, exp) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, res)
	}
}

func TestIsValid(t *testing.T) {
	inp := []byte("alert('MZA who was that?');\n")
	hm := NewHashCBC()
	if !hm.IsValid(inp) {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}
	targetMsg := []byte("alert('Ayo, the Wu is back!');\n")
	if hm.IsValid(targetMsg) {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}

func TestExploit(t *testing.T) {
	hm := NewHashCBC()
	inp := []byte("alert('MZA who was that?');\n")
	targetMac := c1_hex_to_base64.ParseHex("296b8d7cb78a243dda4d0a61d33bbdd1")
	targetMsg := []byte("alert('Ayo, the Wu is back!');\n")
	msg := Exploit(inp, targetMsg, targetMac, hm)
	if !bytes.HasPrefix(msg, targetMsg) {
		t.Errorf("Incorrect result. Expected %q starts with %q\n", msg, targetMsg)
	}
	if !hm.IsValid(msg) {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}
}
