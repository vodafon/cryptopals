package c1_hex_to_base64

import "testing"

func TestHexToBase64(t *testing.T) {
	inp := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	exp := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if string(HexToBase64(inp)) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, HexToBase64(inp))
	}
}
