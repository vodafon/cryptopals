package c30_break_md4_length_extension

import (
	"crypto/rand"
	"testing"
)

func TestMD4System(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	s := NewMD4System(key)
	message := []byte("Some text")
	mac := s.MAC(message)

	if !s.Verify(mac, message) {
		t.Errorf("Incorrect verification. Expected true")
	}
	if s.Verify(mac, message[:len(message)-3]) {
		t.Errorf("Incorrect verification. Expected false")
	}

	s = NewMD4System(key[:len(key)-3])
	if s.Verify(mac, message) {
		t.Errorf("Incorrect verification with another key. Expected false")
	}
}
