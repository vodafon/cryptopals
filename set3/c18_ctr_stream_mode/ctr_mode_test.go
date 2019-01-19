package c18_ctr_stream_mode

import (
	"bytes"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestCounterInc(t *testing.T) {
	ctr := NewCTRSystem(bytes.Repeat([]byte{0}, 16))
	c := ctr.NewCounter(3)
	exps := [][]byte{
		[]byte("\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"),
	}
	for idx, exp := range exps {
		if !bytes.Equal(c.Bytes(), exp) {
			t.Errorf("Incorrect result (step %d). Expected: %q, got: %q\n", idx, exp, c.Bytes())
		}
		c = c.Inc()
	}
}

func TestDecrypt(t *testing.T) {
	inp := []byte("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	exp := []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
	ciphertext, err := c1_hex_to_base64.DecodeBase64(inp)
	if err != nil {
		panic(err)
	}
	key := []byte("YELLOW SUBMARINE")
	ctr := NewCTRSystem(key)
	res, err := ctr.Decrypt(ciphertext, 0)
	if err != nil {
		t.Errorf("Decrypt error: %s\n", err)
	}
	if !bytes.Equal(res, exp) {
		t.Errorf("Incorrect result. Expected: %q, got %q\n", exp, res)
	}
}
