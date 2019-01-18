package c10_implement_cbc_mode

import (
	"crypto/aes"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set2/c09_pkcs7_padding"
	"github.com/vodafon/cryptopals/set2/c15_pkcs7_validation"
)

func Decrypt(ciphertext, key, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := []byte{}
	start := len(ciphertext) - block.BlockSize()
	prev := start - block.BlockSize()

	prevBlock := make([]byte, block.BlockSize())
	block.Decrypt(prevBlock, ciphertext[start:len(ciphertext)])
	for start > 0 {
		currentBlock := ciphertext[prev:start]
		plaintext = append(c2_fixed_xor.SafeXORBytes(prevBlock, currentBlock), plaintext...)
		block.Decrypt(prevBlock, currentBlock)
		start -= block.BlockSize()
		prev -= block.BlockSize()
	}
	plaintext = append(c2_fixed_xor.SafeXORBytes(prevBlock, iv), plaintext...)
	unpad, err := c15_pkcs7_validation.Validation(plaintext)
	if err != nil {
		return []byte{}
	}

	return unpad
}

func Encrypt(src, key, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	plaintext := c09_pkcs7_padding.Padding(src, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	start := 0
	end := block.BlockSize()
	xorBlock := iv

	for start < len(plaintext) {
		currentBlock := c2_fixed_xor.SafeXORBytes(plaintext[start:end], xorBlock)
		block.Encrypt(ciphertext[start:end], currentBlock)
		xorBlock = ciphertext[start:end]
		start += block.BlockSize()
		end += block.BlockSize()
	}
	return ciphertext
}
