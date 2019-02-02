package c28_sha1_key_mac

import (
	"crypto/rand"
	"testing"
)

func TestSum(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	sha1 := NewSHA1System(key)
	message := []byte("Some text")
	mac := sha1.MAC(message)

	if !sha1.Verify(mac, message) {
		t.Errorf("Incorrect verification. Expected true")
	}
	if sha1.Verify(mac, message[:len(message)-3]) {
		t.Errorf("Incorrect verification. Expected false")
	}

	sha1 = NewSHA1System(key[:len(key)-3])
	if sha1.Verify(mac, message) {
		t.Errorf("Incorrect verification with another key. Expected false")
	}
}
