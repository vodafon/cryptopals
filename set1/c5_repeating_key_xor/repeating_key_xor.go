package c5_repeating_key_xor

import (
	"bytes"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
)

func XORByKey(src []byte, key []byte) []byte {
	repT := len(src) / len(key)
	rep := bytes.Repeat(key, repT)
	rep = append(rep[:], key[:len(src)%len(key)]...)
	return c2_fixed_xor.SafeXORBytes(src, rep)
}
