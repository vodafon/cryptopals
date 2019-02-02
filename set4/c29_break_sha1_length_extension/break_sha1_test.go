package c29_break_sha1_length_extension

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/vodafon/cryptopals/set4/c28_sha1_key_mac"
)

func TestExploit(t *testing.T) {
	inp := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	key := make([]byte, 10+rand.Intn(40))
	rand.Read(key)
	sha1System := c28_sha1_key_mac.NewSHA1System(key)
	mac := sha1System.MAC(inp)
	if sha1System.Verify(mac, append(inp, []byte(";admin=true;")...)) {
		t.Errorf("Incorect verification. Expected false")
	}

	mac2, msg, err := Exploit(sha1System, inp, []byte(";admin=true;"), mac)
	if err != nil {
		t.Errorf("Exploit error: %s\n", err)
	}
	if !sha1System.Verify(mac2, msg) {
		t.Errorf("Incorect result\n")
	}
	if !bytes.Contains(msg, []byte(";admin=true;")) {
		t.Errorf("Not admin")
	}
}
