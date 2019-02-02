package c26_ctr_bitflipping

import (
	"bytes"
	"math/rand"

	"github.com/vodafon/cryptopals/set3/c18_ctr_stream_mode"
)

type Enc struct {
	ctr  c18_ctr_stream_mode.CTRSystem
	head []byte
	tail []byte
}

func DefaultEnc(key []byte) Enc {
	return Enc{
		ctr:  c18_ctr_stream_mode.NewCTRSystem(key),
		head: []byte("comment1=cooking%20MCs;userdata="),
		tail: []byte(";comment2=%20like%20a%20pound%20of%20bacon"),
	}
}

func (e Enc) Encrypt(payload []byte) ([]byte, uint32, error) {
	src := e.ToParams(payload)
	nonce := rand.Uint32()
	enc, err := e.ctr.Encrypt(src, nonce)
	return enc, nonce, err
}

func (e Enc) Decrypt(ciphertext []byte, nonce uint32) ([]byte, error) {
	return e.ctr.Decrypt(ciphertext, nonce)
}

func (e Enc) IsAdmin(ciphertext []byte, nonce uint32) (bool, error) {
	plaintext, err := e.Decrypt(ciphertext, nonce)
	if err != nil {
		return false, err
	}
	return bytes.Contains(plaintext, []byte(";admin=true;")), nil
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

func ExploitAdmin(enc Enc) (bool, error) {
	payload := []byte("?admin?true")
	ciphertext, nonce, err := enc.Encrypt(payload)
	if err != nil {
		return false, err
	}
	ciphertext = Flip(ciphertext, 32, '?'^';')
	ciphertext = Flip(ciphertext, 38, '?'^'=')
	return enc.IsAdmin(ciphertext, nonce)
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
