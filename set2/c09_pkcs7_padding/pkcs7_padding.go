package c09_pkcs7_padding

import "bytes"

func Padding(data []byte, size int) []byte {
	padLen := size - len(data)%size
	if padLen == 0 {
		padLen = size
	}
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padText...)
}

func Unpad(plaintext []byte) []byte {
	length := len(plaintext)
	n := int(plaintext[length-1])
	if n == 0 || n >= length {
		return plaintext
	}

	for i := 2; i <= n; i++ {
		if int(plaintext[length-i]) != n {
			return plaintext
		}
	}

	return plaintext[:length-n]
}
