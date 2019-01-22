package c3_single_byte_xor

import (
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestSingleByteXOR(t *testing.T) {
	inp := c1_hex_to_base64.ParseHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	exp := "Cooking MC's like a pound of bacon"
	res := BruteForceBySingleByteBest(inp)
	if res.Key != 'X' || string(res.Bytes) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res.Bytes)
	}
}

func TestSingleByteXORByCorpus(t *testing.T) {
	inp := c1_hex_to_base64.ParseHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	exp := "Cooking MC's like a pound of bacon"
	res := BruteForceByCorpusBest(inp)
	if res.Key != 'X' || string(res.Bytes) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res.Bytes)
	}
}
