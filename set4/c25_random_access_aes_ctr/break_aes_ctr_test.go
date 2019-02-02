package c25_random_access_aes_ctr

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
	"github.com/vodafon/cryptopals/set3/c18_ctr_stream_mode"
)

func TestEdit(t *testing.T) {
	plaintext := loadPlaintext()
	key := make([]byte, 16)
	rand.Read(key)
	ctr := c18_ctr_stream_mode.NewCTRSystem(key)
	ciphertext, _ := ctr.Encrypt(plaintext, 0)
	c2, err := Edit(ciphertext, []byte("AAAA"), 0, 10, ctr)
	if err != nil {
		t.Fatalf("Edit error: %s\n", err)
	}
	p2, err := ctr.Decrypt(c2, 0)
	if err != nil {
		t.Fatalf("Decrypt error: %s\n", err)
	}
	exp := []byte("I'm back aAAAA'm ringin' the bell")
	if !bytes.Equal(p2[:len(exp)], exp) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, p2[:len(exp)])
	}
}

func TestRecover(t *testing.T) {
	plaintext := loadPlaintext()
	key := make([]byte, 16)
	rand.Read(key)
	ctr := c18_ctr_stream_mode.NewCTRSystem(key)
	ciphertext, _ := ctr.Encrypt(plaintext, 0)
	res, err := Recover(ciphertext, 0, ctr)
	if err != nil {
		t.Fatalf("Recover error: %s\n", err)
	}
	if !bytes.Equal(plaintext, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", plaintext, res)
	}
}

// From c7
func loadPlaintext() []byte {
	key := []byte("YELLOW SUBMARINE")
	srcfile, _ := ioutil.ReadFile("testdata/25.txt")
	enc, _ := c1_hex_to_base64.DecodeBase64(srcfile)
	return c7_aes_ecb.Decrypt(enc, key)
}
