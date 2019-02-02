package c31_hmac_sha1_timing_leak

import (
	"bytes"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set4/c28_sha1_key_mac"
)

const (
	blockSize  = 64
	outputSize = 20
)

type HMACSystem struct {
	key  []byte
	hash *c28_sha1_key_mac.SHA1
}

func NewHMACSystem(key []byte) HMACSystem {
	return HMACSystem{
		key:  key,
		hash: &c28_sha1_key_mac.SHA1{},
	}
}

func (obj HMACSystem) HMAC(message []byte) []byte {
	key := []byte{}
	switch {
	case len(obj.key) > blockSize:
		key = pad(obj.newHash(obj.key), blockSize)
	case len(obj.key) < blockSize:
		key = pad(obj.key, blockSize)
	default:
		key = obj.key
	}
	oKeyPad := c2_fixed_xor.SafeXORBytes(key, bytes.Repeat([]byte{0x5c}, blockSize))
	iKeyPad := c2_fixed_xor.SafeXORBytes(key, bytes.Repeat([]byte{0x36}, blockSize))
	iHash := obj.newHash(append(iKeyPad, message...))
	return obj.newHash(append(oKeyPad, iHash...))
}

func pad(src []byte, size int) []byte {
	return append(src, make([]byte, size-len(src))...)
}

func (obj HMACSystem) newHash(src []byte) []byte {
	obj.hash.Reset()
	obj.hash.Write(src)
	mac := obj.hash.CheckSum()
	return mac[:]
}
