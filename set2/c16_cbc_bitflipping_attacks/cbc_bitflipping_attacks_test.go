package c16_cbc_bitflipping_attacks

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

func TestToParams(t *testing.T) {
	key := make([]byte, 16)
	enc := DefaultEnc(key)
	inp := []byte(";admin=true")
	exp := []byte(`comment1=cooking%20MCs;userdata=";"admin"="true;comment2=%20like%20a%20pound%20of%20bacon`)
	res := enc.ToParams(inp)
	if !bytes.Equal(exp, res) {
		t.Errorf("Incorrect result. Expected: %q, got: %q\n", exp, res)
	}
}

func TestDecrypt(t *testing.T) {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	enc := DefaultEnc(key)
	inp := []byte(";admin=true")
	ciphertext, iv := enc.Encrypt(inp)
	res := enc.Decrypt(ciphertext, iv)
	exp := []byte(`comment1=cooking%20MCs;userdata=";"admin"="true;comment2=%20like%20a%20pound%20of%20bacon`)
	if !bytes.Equal(exp, res) {
		t.Errorf("Incorrect result. Expected: %q, got: %q\n", exp, res)
	}
}

func TestIsAdminTrue(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	rand.Read(iv)
	enc := DefaultEnc(key)
	plaintext := []byte(`comment1=cooking%20MCs;userdata=;admin=true;comment2=%20like%20a%20pound%20of%20bacon`)
	ciphertext := c10_implement_cbc_mode.Encrypt(plaintext, key, iv)
	if !enc.IsAdmin(ciphertext, iv) {
		t.Errorf("Incorrect result. Expected: true, got: false\n")
	}
}

func TestIsAdminFalse(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	rand.Read(iv)
	enc := DefaultEnc(key)
	plaintext := []byte(`comment1=cooking%20MCs;userdata=";"admin"="true";"comment2=%20like%20a%20pound%20of%20bacon`)
	ciphertext := c10_implement_cbc_mode.Encrypt(plaintext, key, iv)
	if enc.IsAdmin(ciphertext, iv) {
		t.Errorf("Incorrect result. Expected: false, got: true\n")
	}
}

func TestExploitAdmin(t *testing.T) {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	enc := DefaultEnc(key)
	if !ExploitAdmin(enc) {
		t.Errorf("Exploit don't work")
	}
}
