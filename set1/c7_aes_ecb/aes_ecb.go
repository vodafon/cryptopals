package c7_aes_ecb

import (
	"crypto/aes"

	"github.com/vodafon/cryptopals/set2/c9_pkcs7_padding"
)

func DecryptAes128Ecb(src, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	size := 16
	data := c9_pkcs7_padding.Padding(src, size)
	decrypted := make([]byte, len(data))

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}
