package c1_hex_to_base64

import (
	"bytes"
	"errors"
)

var (
	base64Std = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	hextable  = []byte("0123456789abcdef")
)

func HexToBase64(hexString string) []byte {
	hexData := ParseHex(hexString)
	return EncodeBase64(hexData)
}

func ParseHex(hexString string) []byte {
	src := []byte(hexString)
	res, _ := DecodeHex(src)
	return res
}

func DecodeHex(src []byte) ([]byte, error) {
	if len(src)%2 == 1 {
		return []byte{}, errors.New("Invalid source")
	}
	var dst bytes.Buffer
	for i := 0; i < len(src)/2; i++ {
		a, ok := fromHexChar(src[i*2])
		if !ok {
			return []byte{}, errors.New("Invalid byte")
		}
		b, ok := fromHexChar(src[i*2+1])
		if !ok {
			return []byte{}, errors.New("Invalid byte")
		}
		r := (a << 4) | b
		dst.WriteByte(r)
	}
	return dst.Bytes(), nil
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}

	return 0, false
}

func EncodeBase64(src []byte) []byte {
	var dst bytes.Buffer
	si := 0
	n := (len(src) / 3) * 3
	for si < n {
		// Convert 3x 8bit source bytes into 4 bytes
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])

		dst.WriteByte(base64Std[val>>18&0x3F])
		dst.WriteByte(base64Std[val>>12&0x3F])
		dst.WriteByte(base64Std[val>>6&0x3F])
		dst.WriteByte(base64Std[val&0x3F])

		si += 3
	}

	remain := len(src) - si

	if remain == 0 {
		return dst.Bytes()
	}

	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst.WriteByte(base64Std[val>>18&0x3F])
	dst.WriteByte(base64Std[val>>12&0x3F])

	switch remain {
	case 2:
		dst.WriteByte(base64Std[val>>6&0x3F])
		dst.WriteByte('=')

	case 1:
		dst.WriteByte('=')
		dst.WriteByte('=')
	}
	return dst.Bytes()
}

func removeSpaces(src []byte) []byte {
	var dst bytes.Buffer
	for i := 0; i < len(src); i++ {
		if src[i] != 10 {
			dst.WriteByte(src[i])
		}
	}
	return dst.Bytes()
}

func DecodeBase64(src []byte) ([]byte, error) {
	src = removeSpaces(src)
	if len(src)%4 != 0 {
		return []byte{}, errors.New("Invalid source")
	}
	var dst bytes.Buffer
	si := 0
	n := len(src)
	if src[len(src)-1] == '=' {
		n -= 4
	}
	for si < n {
		val := bIndex(src[si+0])<<18 | bIndex(src[si+1])<<12 | bIndex(src[si+2])<<6 | bIndex(src[si+3])
		dst.WriteByte(byte(val >> 16))
		dst.WriteByte(byte(val >> 8 & 0xff))
		dst.WriteByte(byte(val & 0xff))
		si += 4
	}
	if si == len(src) {
		return dst.Bytes(), nil
	}
	if src[len(src)-2] == '=' {
		val := bIndex(src[si+0])<<18 | bIndex(src[si+1])<<12
		dst.WriteByte(byte(val >> 16))
	} else {
		val := bIndex(src[si+0])<<18 | bIndex(src[si+1])<<12 | bIndex(src[si+2])<<6
		dst.WriteByte(byte(val >> 16))
		dst.WriteByte(byte(val >> 8 & 0xff))
	}
	return dst.Bytes(), nil
}

func bIndex(b byte) int {
	return bytes.IndexByte(base64Std, b)
}

func EncodeHex(src []byte) []byte {
	dst := make([]byte, len(src)*2)
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return dst
}
