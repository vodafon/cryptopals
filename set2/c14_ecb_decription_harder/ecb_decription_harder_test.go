package c14_ecb_decription_harder

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set2/c12_ecb_decription_simple"
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
	prefix := make([]byte, rand.Intn(50)+2)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	rand.Read(prefix)

	e := NewEnc(key, prefix, tail)

	bs, err := c12_ecb_decription_simple.BlockSizeDetect(e, 100)
	if err != nil {
		t.Error(err.Error())
	}

	ps, err := prefixSize(e, bs)
	if err != nil {
		t.Error(err)
	}
	if ps != len(prefix) {
		t.Errorf("Invalid prefix size. Expected: %d, got: %d\n", len(prefix), ps)
	}

	decr := e.BruteForce(bs, ps)
	if !bytes.Contains(decr, []byte("rag-top down so my hair can blow\nThe girlies on standby waving just to say")) {
		t.Errorf("Invalid decryption")
	}
}
