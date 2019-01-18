package c15_pkcs7_validation

import (
	"errors"
)

var ValidationError = errors.New("Invalid PKCS#7 padding")

func Validation(plaintext []byte) ([]byte, error) {
	length := len(plaintext)
	n := int(plaintext[length-1])
	if n == 0 || n >= length {
		return []byte{}, ValidationError
	}

	for i := 2; i <= n; i++ {
		if int(plaintext[length-i]) != n {
			return []byte{}, ValidationError
		}
	}

	return plaintext[:length-n], nil
}
