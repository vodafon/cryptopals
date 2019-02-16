package c50_cbc_mac_hashing

import (
	"bytes"
	"crypto/aes"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set2/c09_pkcs7_padding"
	"github.com/vodafon/cryptopals/set7/c49_cbc_mac_forgery"
)

type HashCBC struct {
	cbc c49_cbc_mac_forgery.CBCMAC
	Key []byte
}

func NewHashCBC() HashCBC {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	cbc := c49_cbc_mac_forgery.NewCBCMACFixedIV(key, iv)
	return HashCBC{
		Key: key,
		cbc: cbc,
	}
}

func (obj HashCBC) Sign(msg []byte) []byte {
	_, mac := obj.cbc.Sign(msg)
	return mac
}

func (obj HashCBC) IsValid(msg []byte) bool {
	validMac := c1_hex_to_base64.ParseHex("296b8d7cb78a243dda4d0a61d33bbdd1")
	mac := obj.Sign(msg)
	return bytes.Equal(mac, validMac)
}

// original message - "alert('MZA who was that?');\n"
// original MAC hex - "296b8d7cb78a243dda4d0a61d33bbdd1"
// target 	message - "alert('Ayo, the Wu is back!');\n"
func Exploit(inp, targetMsg, targetMac []byte, hm HashCBC) []byte {
	block, err := aes.NewCipher(hm.Key)
	if err != nil {
		panic(err)
	}
	X1_2 := make([]byte, block.BlockSize())
	block.Decrypt(X1_2, targetMac)

	// result message with 4 blocks
	// |alert('Ayo, the |Wu is back!');\n0x01|TRASH BYTES|0x10...0x10(padding)|
	pad := bytes.Repeat([]byte{0x10}, block.BlockSize())
	C2_3 := c2_fixed_xor.SafeXORBytes(pad, X1_2)
	X2_3 := make([]byte, block.BlockSize())
	block.Decrypt(X2_3, C2_3)
	C2_2 := hm.Sign(targetMsg)
	B2_3 := c2_fixed_xor.SafeXORBytes(C2_2, X2_3)
	msg := append(c09_pkcs7_padding.Padding(targetMsg, block.BlockSize()), B2_3...)

	// debug print
	// inpPad := c09_pkcs7_padding.Padding(inp, block.BlockSize())
	// msgPad := c09_pkcs7_padding.Padding(msg, block.BlockSize())
	// fmt.Printf("\n\ninpPad:\n")
	// printMsg(inpPad, block)
	// fmt.Printf("\n\nmsgPad:\n")
	// printMsg(msgPad, block)

	return msg
}

// func printMsg(msgPad []byte, block cipher.Block) {
// 	start := 0
// 	finish := block.BlockSize()
// 	iv := make([]byte, block.BlockSize())
// 	i := 1
// 	for finish < len(msgPad)+1 {
// 		bl := msgPad[start:finish]
// 		fmt.Printf("B%d:\t%q\n", i, bl)
// 		x := c2_fixed_xor.SafeXORBytes(bl, iv)
// 		fmt.Printf("X%d:\t%x\n", i, x)
// 		c := make([]byte, block.BlockSize())
// 		block.Encrypt(c, x)
// 		fmt.Printf("C%d:\t%x\n", i, c)
// 		iv = c
// 		start += block.BlockSize()
// 		finish += block.BlockSize()
// 		i += 1
// 	}
// }
