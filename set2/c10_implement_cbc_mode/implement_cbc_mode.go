package c10_implement_cbc_mode

import (
	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
	"github.com/vodafon/cryptopals/set2/c9_pkcs7_padding"
)

func CBCMode(src, key, iv []byte) []byte {
	ciphertext := c9_pkcs7_padding.Padding(src, len(key))
	plaintext := []byte{}
	start := len(ciphertext) - len(key)
	prev := start - len(key)

	prevBlock := c7_aes_ecb.DecryptAes128Ecb(ciphertext[start:len(ciphertext)], key)
	for start > 0 {
		currentBlock := ciphertext[prev:start]
		plaintext = append(c2_fixed_xor.SafeXORBytes(prevBlock, currentBlock), plaintext...)
		prevBlock = c7_aes_ecb.DecryptAes128Ecb(currentBlock, key)
		start -= len(key)
		prev -= len(key)
	}
	return append(c2_fixed_xor.SafeXORBytes(prevBlock, iv), plaintext...)
}
