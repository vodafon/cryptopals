package c31_hmac_sha1_timing_leak

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

type TTable struct {
	key string
	exp string
}

func TestHMACImplementation(t *testing.T) {
	ttb := []TTable{
		{
			key: "KEY",
			exp: "c4473eba2b6e74a0adc0abbb4216676967626127",
		},
		{
			key: strings.Repeat("A", 64),
			exp: "3a40869699fafd80f32200a927481822ac57c962",
		},
		{
			key: strings.Repeat("B", 70),
			exp: "4bf35b5af0ea3f3b0dd5522d2ab09a690242d469",
		},
	}
	inp := []byte("Some text")
	for _, t := range ttb {
		key := []byte(t.key)
		exp := c1_hex_to_base64.ParseHex(t.exp)
		hs := NewHMACSystem(key)
		mac := hs.HMAC(inp)

		if !bytes.Equal(mac, exp) {
			fmt.Printf("Incorrect HMAC for %q:%q. Expected %x, got %x\n", key, inp, exp, mac)
		}
	}
}
