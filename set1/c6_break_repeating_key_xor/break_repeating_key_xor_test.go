package c6_break_repeating_key_xor

import (
	"io/ioutil"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestHammingDistance(t *testing.T) {
	s1 := []byte("this is a test")
	s2 := []byte("wokka wokka!!!")
	if HammingDistance(s1, s2) != 37 {
		t.Errorf("Incorrect result. Expected: %d, got: %d\n", 37, HammingDistance(s1, s2))
	}
}

func TestBreakKeyXOR(t *testing.T) {
	file, _ := ioutil.ReadFile("testdata/6.txt")
	exp := "Terminator X: Bring the noise"
	enc, _ := c1_hex_to_base64.DecodeBase64(file)
	keySize, _ := KeySizeDetect(enc)
	key := BreakKeyXOR(enc, keySize)

	if string(key) != exp {
		t.Errorf("Incorrect result. Expected: %s, got: %s\n", exp, key)
	}
}
