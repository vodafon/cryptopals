package c12_ecb_decription_simple

import (
	"bytes"
	"errors"

	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
)

type Enc struct {
	key  []byte
	tail []byte
}

type Encryptor interface {
	Encrypt([]byte) []byte
}

func NewEnc(key, tail []byte) Enc {
	return Enc{
		key:  key,
		tail: tail,
	}
}

func (e Enc) Encrypt(src []byte) []byte {
	var buf bytes.Buffer

	buf.Write(src)
	buf.Write(e.tail)

	return c7_aes_ecb.Encrypt(buf.Bytes(), e.key)
}

func (e Enc) BruteForce(blockSize int) []byte {
	decr := []byte{}
	for i := 0; i < len(e.tail); i++ {
		decr = append(decr, findByte(decr, blockSize, e))
	}
	return decr
}

func findByte(decr []byte, bs int, enc Encryptor) byte {
	size := (len(decr)/bs + 1) * bs
	prefix := bytes.Repeat([]byte("A"), size-len(decr)-1)
	target := enc.Encrypt(prefix)[0:size]
	for i := 0; i < 255; i++ {
		input := append(prefix, decr...)
		input = append(input, byte(i))
		output := enc.Encrypt(input)
		if bytes.Equal(output[0:size], target) {
			return byte(i)
		}
	}
	return byte(0)
}

func BlockSizeDetect(enc Encryptor, maxLen int) (int, error) {
	var src bytes.Buffer
	// padding
	i, err := lenChangeIteration(src, enc, maxLen, 1)
	if err != nil {
		return 0, err
	}

	// new block
	i, err = lenChangeIteration(src, enc, maxLen, i+1)
	if err != nil {
		return 0, err
	}
	return i, err
}

func lenChangeIteration(src bytes.Buffer, enc Encryptor, maxLen, startPos int) (int, error) {
	src.Write(bytes.Repeat([]byte("A"), startPos))
	l := len(enc.Encrypt(src.Bytes()))
	for i := 2; i < maxLen; i++ {
		src.Write([]byte("A"))
		l1 := len(enc.Encrypt(src.Bytes()))
		if l1 < l {
			return 0, errors.New("not ECB")
		}
		if l1 > l {
			return i, nil
		}
	}
	return 0, errors.New("not found")
}
