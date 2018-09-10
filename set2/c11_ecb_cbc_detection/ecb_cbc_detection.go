package c11_ecb_cbc_detection

import (
	"bytes"
	"math/rand"
	"time"

	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

func EncryptionOracle(src []byte) ([]byte, string) {
	var buf bytes.Buffer
	prefix := make([]byte, randomInt(5, 10))
	rand.Read(prefix)
	suffix := make([]byte, randomInt(5, 10))
	rand.Read(suffix)

	buf.Write(prefix)
	buf.Write(src)
	buf.Write(suffix)

	key := make([]byte, 16)
	rand.Read(key)

	if rand.Intn(2) == 0 {
		iv := make([]byte, 16)
		rand.Read(iv)

		return c10_implement_cbc_mode.CBCMode(buf.Bytes(), key, iv), "CBC"
	} else {
		return c7_aes_ecb.DecryptAes128Ecb(buf.Bytes(), key), "ECB"
	}
}

func randomInt(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
