package c09_pkcs7_padding

import "bytes"

func Padding(data []byte, size int) []byte {
	if len(data)%size == 0 {
		return data
	}
	padLen := size - len(data)%size
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padText...)
}

func UnPadding(data []byte, size int) []byte {
	length := len(data)
	n := int(data[length-1])
	if n == 0 || n >= size {
		return data
	}

	for i := 2; i < n; i++ {
		if int(data[length-i]) != n {
			return data
		}
	}
	return data[:length-n]
}
