package c27_cbc_iv_equal_key

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestExploit(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	enc := DefaultEnc(key)
	rec := Exploit(enc)
	if !bytes.Equal(key, rec) {
		t.Errorf("Incorrect result. Expected key %q, got %q\n", key, rec)
	}
}
