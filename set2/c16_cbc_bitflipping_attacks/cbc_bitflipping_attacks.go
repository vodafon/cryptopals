package c16_cbc_bitflipping_attacks

import (
	"bytes"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

type Enc struct {
	key  []byte
	head []byte
	tail []byte
}

func DefaultEnc(key []byte) Enc {
	return Enc{
		key:  key,
		head: []byte("comment1=cooking%20MCs;userdata="),
		tail: []byte(";comment2=%20like%20a%20pound%20of%20bacon"),
	}
}

func (e Enc) Encrypt(payload []byte) ([]byte, []byte) {
	src := e.ToParams(payload)
	iv := make([]byte, 16)
	return c10_implement_cbc_mode.Encrypt(src, e.key, iv), iv
}

func (e Enc) Decrypt(ciphertext, iv []byte) []byte {
	return c10_implement_cbc_mode.Decrypt(ciphertext, e.key, iv)
}

func (e Enc) IsAdmin(ciphertext, iv []byte) bool {
	plaintext := e.Decrypt(ciphertext, iv)
	return bytes.Contains(plaintext, []byte(";admin=true;"))
}

func (e Enc) ToParams(payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write(e.head)
	buf.Write(encode(payload))
	buf.Write(e.tail)
	return buf.Bytes()
}

func Flip(ciphertext []byte, pos int, value byte) []byte {
	ciphertext[pos] = ciphertext[pos] ^ value
	return ciphertext
}

func ExploitAdmin(enc Enc) bool {
	payload := []byte("?admin?true")
	ciphertext, iv := enc.Encrypt(payload)
	ciphertext = Flip(ciphertext, 16, '?'^';')
	ciphertext = Flip(ciphertext, 22, '?'^'=')
	return enc.IsAdmin(ciphertext, iv)
}

func encode(payload []byte) []byte {
	var buf bytes.Buffer
	quote := []byte("\"")

	for _, char := range payload {
		if char == ';' || char == '=' {
			buf.Write(quote)
			buf.WriteByte(char)
			buf.Write(quote)
		} else {
			buf.WriteByte(char)
		}
	}
	return buf.Bytes()
}
