package c1_hex_to_base64

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
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
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	return dst, err
}

func EncodeBase64(src []byte) []byte {
	var b bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &b)
	encoder.Write(src)
	encoder.Close()
	return b.Bytes()
}

func DecodeBase64(src []byte) ([]byte, error) {
	b := bytes.NewBuffer(src)
	decoder := base64.NewDecoder(base64.StdEncoding, b)
	return ioutil.ReadAll(decoder)
}

func EncodeHex(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}
