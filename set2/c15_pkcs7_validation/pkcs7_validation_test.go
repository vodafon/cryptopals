package c15_pkcs7_validation

import (
	"bytes"
	"testing"
)

func TestValidInput(t *testing.T) {
	inp := []byte("ICE ICE BABY\x04\x04\x04\x04")
	exp := []byte("ICE ICE BABY")
	res, err := Validation(inp)
	if err != nil || !bytes.Equal(res, exp) {
		t.Errorf("Incorrect result. Expected: (%s, nil), got: (%s, %s)\n", exp, res, err)
	}
}

func TestInvalidInput1(t *testing.T) {
	inp := []byte("ICE ICE BABY\x05\x05\x05\x05")
	res, err := Validation(inp)
	if err != ValidationError || !bytes.Equal(res, []byte{}) {
		t.Errorf("Incorrect result. Expected: ('', %s), got: (%s, %s)\n", ValidationError, res, err)
	}
}

func TestInvalidInput2(t *testing.T) {
	inp := []byte("ICE ICE BABY\x01\x02\x03\x04")
	res, err := Validation(inp)
	if err != ValidationError || !bytes.Equal(res, []byte{}) {
		t.Errorf("Incorrect result. Expected: ('', %s), got: (%s, %s)\n", ValidationError, res, err)
	}
}
