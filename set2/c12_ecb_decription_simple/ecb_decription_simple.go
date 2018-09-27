package c12_ecb_decription_simple

import (
	"bytes"
	"errors"

	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
)

type Encryptor struct {
	key  []byte
	tail []byte
}

type EncryptFunc func([]byte) []byte

func NewEncryptor(key, tail []byte) Encryptor {
	return Encryptor{
		key:  key,
		tail: tail,
	}
}

func (e Encryptor) Encrypt(src []byte) []byte {
	var buf bytes.Buffer

	buf.Write(src)
	buf.Write(e.tail)

	return c7_aes_ecb.DecryptAes128Ecb(buf.Bytes(), e.key)
}

func (e Encryptor) BruteForce(blockSize int) []byte {
	decr := []byte{}
	for i := 0; i < len(e.Encrypt([]byte{})); i++ {
		decr = append(decr, findByte(decr, blockSize, e.Encrypt))
	}
	return decr
}

func findByte(decr []byte, bs int, encryptFunc EncryptFunc) byte {
	size := (len(decr)/bs + 1) * bs
	prefix := bytes.Repeat([]byte("A"), size-len(decr)-1)
	target := encryptFunc(prefix)[0:size]
	for i := 0; i < 255; i++ {
		input := append(prefix, decr...)
		input = append(input, byte(i))
		output := encryptFunc(input)
		if bytes.Equal(output[0:size], target) {
			return byte(i)
		}
	}
	return byte(0)
}

func BlockSizeDetect(encryptFunc EncryptFunc, maxLen int) (int, error) {
	var src bytes.Buffer
	// padding
	i, err := lenChangeIteration(src, encryptFunc, maxLen, 1)
	if err != nil {
		return 0, err
	}

	// new block
	i, err = lenChangeIteration(src, encryptFunc, maxLen, i+1)
	if err != nil {
		return 0, err
	}
	return i, err
}

func lenChangeIteration(src bytes.Buffer, encryptFunc EncryptFunc, maxLen, startPos int) (int, error) {
	src.Write(bytes.Repeat([]byte("A"), startPos))
	l := len(encryptFunc(src.Bytes()))
	for i := 2; i < maxLen; i++ {
		src.Write([]byte("A"))
		l1 := len(encryptFunc(src.Bytes()))
		if l1 < l {
			return 0, errors.New("not ECB")
		}
		if l1 > l {
			return i, nil
		}
	}
	return 0, errors.New("not found")
}
