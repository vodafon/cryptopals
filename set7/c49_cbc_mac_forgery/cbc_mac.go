package c49_cbc_mac_forgery

import (
	"bytes"
	"crypto/rand"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

type CBCMAC struct {
	key       []byte
	blockSize int
	randIV    bool
	iv        []byte
}

func NewCBCMAC(key []byte) CBCMAC {
	bs := 16
	if len(key) != bs {
		panic("Invalid key size")
	}
	return CBCMAC{
		key:       key,
		blockSize: bs,
		randIV:    true,
	}
}

func NewCBCMACFixedIV(key, iv []byte) CBCMAC {
	bs := 16
	if len(key) != bs {
		panic("Invalid key size")
	}
	return CBCMAC{
		key:       key,
		blockSize: bs,
		randIV:    false,
		iv:        iv,
	}
}

func (obj CBCMAC) Sign(message []byte) ([]byte, []byte) {
	iv := make([]byte, obj.blockSize)
	if obj.randIV {
		rand.Read(iv)
	} else {
		iv = obj.iv
	}
	ciphertext := c10_implement_cbc_mode.Encrypt(message, obj.key, iv)
	mac := ciphertext[len(ciphertext)-obj.blockSize:]
	return iv, mac
}

func (obj CBCMAC) Validation(message, iv, mac []byte) bool {
	if !obj.randIV {
		iv = obj.iv
	}
	ciphertext := c10_implement_cbc_mode.Encrypt(message, obj.key, iv)
	return bytes.Equal(ciphertext[len(ciphertext)-obj.blockSize:], mac)
}
