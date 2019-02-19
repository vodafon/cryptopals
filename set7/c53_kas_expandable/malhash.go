package c53_kas_expandable

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
)

type MalHash struct {
	state     []byte
	size      int
	blockSize int
	block     cipher.Block
}

func NewMalHash(size int) *MalHash {
	block, err := aes.NewCipher(bytes.Repeat([]byte("K"), 16))
	if err != nil {
		panic(err)
	}
	return &MalHash{
		state:     bytes.Repeat([]byte("S"), size),
		size:      size,
		blockSize: 16,
		block:     block,
	}
}

func (obj *MalHash) Sum(text []byte) []byte {
	obj.Write(text)
	return obj.state
}

func (obj *MalHash) Reset() {
	obj.state = bytes.Repeat([]byte("S"), obj.size)
}

func (obj *MalHash) SetState(state []byte) {
	if len(state) == 0 {
		obj.Reset()
	} else {
		obj.state = state
	}
}

func (obj *MalHash) Size() int {
	return obj.size
}

func (obj *MalHash) BlockSize() int {
	return obj.blockSize
}

func (obj *MalHash) Write(text []byte) (int, error) {
	nn := len(text)
	text = leftPad(text, obj.blockSize)
	start, finish := 0, obj.blockSize
	for finish < len(text)+1 {
		cip := make([]byte, obj.blockSize)
		obj.block.Encrypt(cip, leftPad(text[start:finish], obj.blockSize))
		cip = c2_fixed_xor.SafeXORBytes(cip, leftPad(obj.state, obj.blockSize))
		obj.state = cip[len(cip)-obj.size:]
		start += obj.blockSize
		finish += obj.blockSize
	}
	return nn, nil
}

func leftPad(src []byte, k int) []byte {
	if len(src) >= k {
		return src
	}
	dst := make([]byte, k)
	copy(dst[k-len(src):], src)
	return dst
}
