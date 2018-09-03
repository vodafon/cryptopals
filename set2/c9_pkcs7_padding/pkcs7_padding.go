package c9_pkcs7_padding

import "bytes"

func Padding(data []byte, size int) []byte {
	if len(data)%size == 0 {
		return data
	}
	padLen := size - len(data)%size
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padText...)
}
