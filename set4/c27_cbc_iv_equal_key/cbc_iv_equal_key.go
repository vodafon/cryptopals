package c27_cbc_iv_equal_key

import (
	"bytes"
	"crypto/aes"
	"errors"
	"unicode"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set2/c09_pkcs7_padding"
	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

type Enc struct {
	key  []byte
	head []byte
	tail []byte
}

func DefaultEnc(key []byte) Enc {
	return Enc{
		key:  key,
		head: []byte("comment1=cooking%20MCs;userdata="),
		tail: []byte(";comment2=%20like%20a%20pound%20of%20bacon"),
	}
}

func (e Enc) ToParams(payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write(e.head)
	buf.Write(payload)
	buf.Write(e.tail)
	return buf.Bytes()
}

func (obj Enc) Encrypt(plaintext []byte) []byte {
	return c10_implement_cbc_mode.Encrypt(plaintext, obj.key, obj.key)
}

func (obj Enc) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext := obj.cbcDecrypt(ciphertext)
	if invalidSymbols(plaintext) {
		return plaintext, errors.New("Invalid text")
	}
	return []byte{}, nil
}

func (obj Enc) cbcDecrypt(ciphertext []byte) []byte {
	block, _ := aes.NewCipher(obj.key)
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
	plaintext = append(c2_fixed_xor.SafeXORBytes(prevBlock, obj.key), plaintext...)
	return c09_pkcs7_padding.Unpad(plaintext)
}

func Exploit(enc Enc) []byte {
	plaintext := enc.ToParams([]byte("AAA"))
	ciphertext := enc.Encrypt(plaintext)
	c1 := make([]byte, len(ciphertext)) // C_1, C_2, C_3
	copy(c1[:16], ciphertext[:16])      // C_1
	copy(c1[16:32], make([]byte, 16))   // 0
	copy(c1[32:], ciphertext[:16])      // C_1
	p1, _ := enc.Decrypt(c1)
	return c2_fixed_xor.SafeXORBytes(p1[:16], p1[32:48]) // KEY = P'_1 XOR P'_3
}

func invalidSymbols(src []byte) bool {
	for _, v := range src {
		if !unicode.IsPrint(rune(v)) {
			return true
		}
	}
	return false
}
