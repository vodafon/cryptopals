package c7_aes_ecb

import (
	"crypto/aes"

	"github.com/vodafon/cryptopals/set2/c9_pkcs7_padding"
)

type CryptFunc func([]byte, []byte)

func Decrypt(src, key []byte) []byte {
	block, _ := aes.NewCipher([]byte(key))
	data := crypt(src, key, block.BlockSize(), block.Decrypt)
	return c9_pkcs7_padding.UnPadding(data, block.BlockSize())
}

func Encrypt(src, key []byte) []byte {
	block, _ := aes.NewCipher([]byte(key))
	data := c9_pkcs7_padding.Padding(src, block.BlockSize())
	return crypt(data, key, block.BlockSize(), block.Encrypt)
}

func crypt(data, key []byte, size int, cipherFunc CryptFunc) []byte {
	dst := make([]byte, len(data))

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipherFunc(dst[bs:be], data[bs:be])
	}

	return dst
}
