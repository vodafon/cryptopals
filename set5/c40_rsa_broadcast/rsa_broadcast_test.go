package c40_rsa_broadcast

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestBroadcast(t *testing.T) {
	bs := 1024
	ip, err := rand.Prime(rand.Reader, bs/2)
	if err != nil {
		t.Errorf("error: %s\n", err)
	}
	inp := ip.Bytes()
	br := NewBroadcast(inp, 3, bs)
	capt := br.Capture()
	crt := Exploit(capt)

	if !bytes.Equal(inp, crt.Bytes()) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", inp, crt.Bytes())
	}
}
