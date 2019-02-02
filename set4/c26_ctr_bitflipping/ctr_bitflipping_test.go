package c26_ctr_bitflipping

import (
	"math/rand"
	"testing"
	"time"
)

func TestExploitAdmin(t *testing.T) {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	enc := DefaultEnc(key)
	isAdmin, err := ExploitAdmin(enc)
	if err != nil {
		t.Fatalf("Exploit error: %s\n", err)
	}
	if !isAdmin {
		t.Errorf("Exploit don't work")
	}
}
