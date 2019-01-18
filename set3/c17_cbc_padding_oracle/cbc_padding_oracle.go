package c17_cbc_padding_oracle

import (
	"bytes"
	"errors"
	"math/rand"
	"time"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
	"github.com/vodafon/cryptopals/set2/c15_pkcs7_validation"
)

type CBCSystem struct {
	key       []byte
	list      [][]byte
	blockSize int
	rand      *rand.Rand
}

var SmallListError = errors.New("List must have more then 1 element")

func NewCBCSystem(list [][]byte) (CBCSystem, error) {
	if len(list) < 1 {
		return CBCSystem{}, SmallListError
	}
	ri := time.Now().UnixNano()
	s := rand.NewSource(ri)
	cbc := CBCSystem{
		list:      list,
		blockSize: 16,
		rand:      rand.New(s),
	}
	return cbc.keyGeneration(), nil
}

func (obj CBCSystem) RandomCiphertext() ([]byte, []byte, error) {
	if len(obj.list) < 1 {
		return []byte{}, []byte{}, SmallListError
	}
	plaintext := obj.list[obj.rand.Intn(len(obj.list))]
	iv := make([]byte, obj.blockSize)
	obj.rand.Read(iv)
	ciphertext := c10_implement_cbc_mode.Encrypt(plaintext, obj.key, iv)
	return ciphertext, iv, nil
}

func (obj CBCSystem) IsPaddingValid(ciphertext, iv []byte) bool {
	plaintext := c10_implement_cbc_mode.Decrypt(ciphertext, obj.key, iv)
	if len(plaintext) == 0 {
		return false
	}
	return true
}

func (obj CBCSystem) Exploit(ciphertext, iv []byte) ([]byte, error) {
	start := 0
	block1 := iv
	plaintext := []byte{}
	attempts := 10

	for start < len(ciphertext) {
		block2 := ciphertext[start : start+obj.blockSize]
		p2, err := obj.exploitBlocks(block1, block2, iv)
		if err != nil {
			if attempts == 0 {
				return []byte{}, err
			}
			attempts -= 1
			continue
		}
		plaintext = append(plaintext, p2...)
		start += obj.blockSize
		block1 = block2
	}
	return c15_pkcs7_validation.Validation(plaintext)
}

func (obj CBCSystem) isInList(plaintext []byte) bool {
	for _, v := range obj.list {
		if bytes.Equal(v, plaintext) {
			return true
		}
	}
	return false
}

func (obj CBCSystem) exploitBlocks(block1, block2, iv []byte) ([]byte, error) {
	c1 := make([]byte, obj.blockSize)
	obj.rand.Read(c1)
	i2 := append(bytes.Repeat([]byte{0}, 16))
	p2 := make([]byte, obj.blockSize)

	for i := 1; i < obj.blockSize+1; i++ {
		pos := obj.blockSize - i
		if i > 1 {
			tail := make([]byte, i)
			for idx, _ := range tail {
				tail[idx] = i2[pos+idx] ^ byte(i)
				copy(c1, append(c1[:pos], tail...))
			}
		}
		b, err := obj.findByte(c1, block2, iv, pos)
		// case if first padding is not 01.
		// just retry with new random 'c1'
		if err != nil {
			return nil, err
		}
		i2[pos] = b ^ byte(i)
		p2[pos] = block1[pos] ^ i2[pos]
	}
	return p2, nil
}

func (obj CBCSystem) findByte(block1, block2, iv []byte, pos int) (byte, error) {
	for i := 0; i < 256; i++ {
		block1[pos] = byte(i)
		if obj.IsPaddingValid(append(block1, block2...), iv) {
			return byte(i), nil
		}
	}
	return byte(0), errors.New("Not found")
}

func splitBytes(text []byte, size int) ([][]byte, error) {
	start := 0
	end := size
	list := [][]byte{}
	if size < 1 || len(text)%size != 0 {
		return list, errors.New("Invalid inputs")
	}
	for start < len(text) {
		list = append(list, text[start:end])
		start += size
		end += size
	}
	return list, nil
}

func joinBytes(list [][]byte) []byte {
	text := []byte{}
	for _, v := range list {
		text = append(text, v...)
	}
	return text
}

func (obj CBCSystem) keyGeneration() CBCSystem {
	if obj.blockSize == 0 {
		obj.blockSize = 16
	}
	obj.key = make([]byte, obj.blockSize)
	obj.rand.Read(obj.key)
	return obj
}
