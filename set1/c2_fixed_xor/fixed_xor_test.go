package c2_fixed_xor

import (
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestFixedXor(t *testing.T) {
	s1 := "1c0111001f010100061a024b53535009181c"
	s2 := "686974207468652062756c6c277320657965"
	exp := "746865206b696420646f6e277420706c6179"

	hex1Bytes := c1_hex_to_base64.ParseHex(s1)
	hex2Bytes := c1_hex_to_base64.ParseHex(s2)
	res := c1_hex_to_base64.EncodeHex(SafeXORBytes(hex1Bytes, hex2Bytes))

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}
