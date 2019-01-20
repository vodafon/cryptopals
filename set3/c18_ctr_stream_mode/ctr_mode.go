package c18_ctr_stream_mode

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
)

type CTRSystem struct {
	block cipher.Block
}

type Counter struct {
	nonceB []byte
	countB []byte
	count  uint32
}

func NewCTRSystem(key []byte) CTRSystem {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return CTRSystem{
		block: block,
	}
}

func (obj CTRSystem) KeyStream(counter Counter) ([]byte, error) {
	ks := make([]byte, obj.block.BlockSize())
	cBytes := counter.Bytes()
	obj.block.Encrypt(ks, cBytes)
	return ks, nil
}

func (obj CTRSystem) NewCounter(nonce uint32) Counter {
	c := Counter{}
	c.nonceB = make([]byte, obj.block.BlockSize()/2)
	c.countB = make([]byte, obj.block.BlockSize()/2)
	binary.LittleEndian.PutUint32(c.nonceB, nonce)
	return c
}

func (obj Counter) Inc() Counter {
	obj.count += 1
	binary.LittleEndian.PutUint32(obj.countB, obj.count)
	return obj
}

func (obj Counter) Bytes() []byte {
	return append(obj.nonceB, obj.countB...)
}

func (obj CTRSystem) Decrypt(ciphertext []byte, nonce uint32) ([]byte, error) {
	counter := obj.NewCounter(nonce)
	start := 0
	plaintext := []byte{}
	for start < len(ciphertext) {
		ks, err := obj.KeyStream(counter)
		if err != nil {
			return nil, err
		}
		end := start + obj.block.BlockSize()
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		xr := c2_fixed_xor.SafeXORBytes(ks[:len(ciphertext[start:end])], ciphertext[start:end])
		plaintext = append(plaintext, xr...)
		counter = counter.Inc()
		start += obj.block.BlockSize()
	}
	return plaintext, nil
}

func (obj CTRSystem) Encrypt(plaintext []byte, nonce uint32) ([]byte, error) {
	return obj.Decrypt(plaintext, nonce)
}
