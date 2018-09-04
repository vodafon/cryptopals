package c1_hex_to_base64

import (
	"testing"
)

func TestHexToBase64(t *testing.T) {
	inp := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	exp := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if string(HexToBase64(inp)) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, HexToBase64(inp))
	}
}

func TestEncodeBase64(t *testing.T) {
	inp := []byte("abcd123 123 4a bcd123123")
	exp := "YWJjZDEyMyAxMjMgNGEgYmNkMTIzMTIz"
	res := EncodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}

func TestEncodeBase64Pad1(t *testing.T) {
	inp := []byte("abcd1231234")
	exp := "YWJjZDEyMzEyMzQ="
	res := EncodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}

func TestEncodeBase64Pad2(t *testing.T) {
	inp := []byte("abcd1231234abcd1231234")
	exp := "YWJjZDEyMzEyMzRhYmNkMTIzMTIzNA=="
	res := EncodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}

func TestDecodeBase64CRLF(t *testing.T) {
	inp := []byte("YWJjZDEyMzEyMzRh\nYmNkMTIzMTIz")
	exp := "abcd1231234abcd123123"
	res, _ := DecodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}

func TestDecodeBase64(t *testing.T) {
	inp := []byte("YWJjZDEyMyAxMjMgNGEgYmNkMTIzMTIz")
	exp := "abcd123 123 4a bcd123123"
	res, _ := DecodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}

func TestDecodeBase64Pad1(t *testing.T) {
	inp := []byte("YWJjZDEyMzEyMyA0YSBiY2QxMjMxMjM=")
	exp := "abcd123123 4a bcd123123"
	res, _ := DecodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}

func TestDecodeBase64Pad2(t *testing.T) {
	inp := []byte("YWJjZDEyMzEyMyA0YWJjZDEyMzEyMw==")
	exp := "abcd123123 4abcd123123"
	res, _ := DecodeBase64(inp)

	if string(res) != exp {
		t.Errorf("Incorrect encoding. Expected: %s, got: %s\n", exp, res)
	}
}
