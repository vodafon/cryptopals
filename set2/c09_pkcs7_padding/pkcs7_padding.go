package c09_pkcs7_padding

import "bytes"

func Padding(data []byte, size int) []byte {
	padLen := size - len(data)%size
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padText...)
}
