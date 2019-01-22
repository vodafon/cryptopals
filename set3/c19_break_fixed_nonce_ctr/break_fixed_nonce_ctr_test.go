package c19_break_fixed_nonce_ctr

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set3/c18_ctr_stream_mode"
)

func TestExploit(t *testing.T) {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	nonce := uint32(0)
	ctr := c18_ctr_stream_mode.NewCTRSystem(key)
	lines := [][]byte{}
	for _, l := range loadStrings("testdata/texts.txt") {
		enc, err := ctr.Encrypt(l, nonce)
		if err != nil {
			t.Fatalf("CTR Encrypt error: %s\n", err)
		}
		lines = append(lines, enc)
	}
	wrong := []string{}
	keystream, _ := Exploit(lines)
	for _, line := range lines {
		plain, _ := ctr.Decrypt(line, nonce)
		dec := c2_fixed_xor.SafeXORBytes(line, keystream[:len(line)])
		if !bytes.Equal(bytes.ToLower(plain), bytes.ToLower(dec)) {
			wrong = append(wrong, fmt.Sprintf("plain: %q, decrypted: %q", plain, dec))
		}
	}
	wrongP := float64(len(wrong)) / float64(len(lines)) * 100.0
	if wrongP > 10.0 {
		t.Errorf("Many incorrect results (%.2f%%): %+v\n", wrongP, wrong)
	}
}

func loadStrings(filepath string) [][]byte {
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	list := [][]byte{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, err := c1_hex_to_base64.DecodeBase64(scanner.Bytes())
		if err != nil {
			panic(err)
		}
		list = append(list, line)
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return list
}
