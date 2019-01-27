package c24_break_mt19937_stream_cipher

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestEncodeMT19937(t *testing.T) {
	plaintext := []byte("some text")
	seed := uint32(rand.Intn(maxSeed))
	ciphertext := EncodeMT19937(plaintext, seed)
	if bytes.Equal(plaintext, ciphertext) {
		t.Errorf("Incorrect encoding. ciphertext == plaintext\n")
	}
	res := DecodeMT19937(ciphertext, seed)
	if !bytes.Equal(res, plaintext) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", plaintext, res)
	}
}

func TestResetToken(t *testing.T) {
	token := ResetToken()
	isTime := IsTimeSeededToken(token)
	if !isTime {
		t.Errorf("Incorrect time seed detection. Expected true\n")
	}
	ciphertext := EncodeMT19937(bytes.Repeat([]byte("A"), 20), 100)
	token = c1_hex_to_base64.EncodeBase64(ciphertext)
	isTime = IsTimeSeededToken(token)
	if isTime {
		t.Errorf("Incorrect time seed detection. Expected false\n")
	}
}

func TestBruteForce(t *testing.T) {
	part := bytes.Repeat([]byte("A"), 14)
	plaintext := generatePlaintext(part)
	seed := uint32(rand.Intn(maxSeed))
	ciphertext := EncodeMT19937(plaintext, seed)
	bSeed, bP, err := BruteForce(ciphertext, part, uint32(maxSeed))
	if err != nil {
		t.Errorf("BruteForce error: %s\n", err)
	}
	if seed != bSeed {
		t.Errorf("Incorrect seed. Expected %d (%q), got %d (%q)", seed, plaintext, bSeed, bP)
	}
}

func generatePlaintext(part []byte) []byte {
	rand.Seed(time.Now().UnixNano())
	pref := make([]byte, 10+rand.Intn(20))
	suff := make([]byte, 10+rand.Intn(20))
	rand.Read(pref)
	rand.Read(suff)
	var buf bytes.Buffer
	buf.Write(pref)
	buf.Write(part)
	buf.Write(suff)
	return buf.Bytes()
}
