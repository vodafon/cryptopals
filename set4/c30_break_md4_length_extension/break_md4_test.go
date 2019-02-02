package c30_break_md4_length_extension

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestExploit(t *testing.T) {
	inp := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	key := make([]byte, 10+rand.Intn(40))
	rand.Read(key)
	md4System := NewMD4System(key)
	mac := md4System.MAC(inp)
	if md4System.Verify(mac, append(inp, []byte(";admin=true;")...)) {
		t.Errorf("Incorect verification. Expected false")
	}

	mac2, msg, err := Exploit(md4System, inp, []byte(";admin=true;"), mac)
	if err != nil {
		t.Errorf("Exploit error: %s\n", err)
	}
	if !md4System.Verify(mac2, msg) {
		t.Errorf("Incorect result\n")
	}
	if !bytes.Contains(msg, []byte(";admin=true;")) {
		t.Errorf("Not admin")
	}
}
