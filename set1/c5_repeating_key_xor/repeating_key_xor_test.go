package c5_repeating_key_xor

import (
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestXORByKey(t *testing.T) {
	inp := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	exp := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	res := c1_hex_to_base64.EncodeHex(XORByKey(inp, key))

	if string(res) != exp {
		t.Errorf("Incorrect result. Expected: %s, got: %s\n", exp, res)
	}
}
