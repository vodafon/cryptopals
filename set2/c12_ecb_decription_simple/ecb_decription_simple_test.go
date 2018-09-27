package c12_ecb_decription_simple

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set2/c11_ecb_cbc_detection"
)

func TestEncryptECBTail(t *testing.T) {
	add := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gb" +
		"XkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdm" +
		"luZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3Q" +
		"gZHJvdmUgYnkK"

	tail, err := c1_hex_to_base64.DecodeBase64([]byte(add))
	if err != nil {
		t.Error(err.Error())
	}

	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)

	e := NewEncryptor(key, tail)

	bs, err := BlockSizeDetect(e.Encrypt, 100)
	if err != nil {
		t.Error(err.Error())
	}

	src := bytes.Repeat([]byte("A"), bs*3)
	res := e.Encrypt(src)
	isEcb, err := c11_ecb_cbc_detection.IsECB(res, 0, bs)
	if !isEcb {
		t.Errorf("is not ECB encryption")
	}

	decr := e.BruteForce(bs)
	if !bytes.Contains(decr, []byte("rag-top down so my hair can blow\nThe girlies on standby waving just to say")) {
		t.Errorf("Invalid decryption")
	}
}
