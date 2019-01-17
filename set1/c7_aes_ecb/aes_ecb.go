package c7_aes_ecb

import (
	"crypto/aes"

	"github.com/vodafon/cryptopals/set2/c09_pkcs7_padding"
	"github.com/vodafon/cryptopals/set2/c15_pkcs7_validation"
)

type CryptFunc func([]byte, []byte)

func Decrypt(src, key []byte) []byte {
	block, _ := aes.NewCipher([]byte(key))
	data := crypt(src, key, block.BlockSize(), block.Decrypt)
	dec, err := c15_pkcs7_validation.Validation(data)
	if err != nil {
		return data
	}
	return dec
}

func Encrypt(src, key []byte) []byte {
	block, _ := aes.NewCipher([]byte(key))
	data := c09_pkcs7_padding.Padding(src, block.BlockSize())
	return crypt(data, key, block.BlockSize(), block.Encrypt)
}

func crypt(data, key []byte, size int, cipherFunc CryptFunc) []byte {
	dst := make([]byte, len(data))

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipherFunc(dst[bs:be], data[bs:be])
	}

	return dst
}
