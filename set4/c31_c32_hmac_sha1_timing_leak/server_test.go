package c31_hmac_sha1_timing_leak

import (
	"math/rand"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestServer(t *testing.T) {
	key := make([]byte, 20+rand.Intn(100))
	rand.Read(key)
	hs := NewHMACSystem(key)
	dur := 1 * time.Millisecond

	server := NewServer(hs, dur)
	fn := "foo"
	validHMAC := hs.HMAC([]byte(fn))
	sign := c1_hex_to_base64.EncodeHex(validHMAC)
	respCode := server.CheckFile("file=" + fn + "&signature=" + string(sign))
	if respCode != 200 {
		t.Errorf("Invalid CheckFile %q. Expected code 200, got %d\n", sign, respCode)
	}
}
