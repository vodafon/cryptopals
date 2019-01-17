package c09_pkcs7_padding

import "testing"

func TestPadding(t *testing.T) {
	inp := []byte("YELLOW SUBMARINE")
	exp := "YELLOW SUBMARINE\x04\x04\x04\x04"
	res := Padding(inp, 20)
	if string(res) != exp {
		t.Errorf("Incorrect result. Expected: %s, got: %s\n", exp, res)
	}
}
