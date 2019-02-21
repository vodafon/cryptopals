package c56_rc4_biases

import (
	"bytes"
	"crypto/rc4"
	"fmt"
	"math/rand"
)

type RC4System struct {
	cookie []byte
}

func NewRC4System(cookie []byte) RC4System {
	return RC4System{cookie}
}

func (obj RC4System) Req(req []byte) []byte {
	msg := append(req, obj.cookie...)
	key := make([]byte, 16)
	rand.Read(key)
	rc, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, len(msg))
	rc.XORKeyStream(dst, msg)
	return dst
}

// z16:
// 0: 240
// A: 177 = 177 XOR 240 = 65
// B: 178
//
// z32:
// 0: 224
// A: 161
// B: 162
func Exploit(rc RC4System) []byte {
	l := len(rc.Req([]byte("/"))) - 1
	if l > 31 {
		panic("too long cookie")
	}
	req := append([]byte("/"), bytes.Repeat([]byte("A"), 32-l-1)...)
	res := []byte{}
	for len(res) < l {
		res = append(res, findByte(req, 31, 224, rc))
		req = append(req, 'A')
		fmt.Printf("%q\n", reverseBytes(res))
	}
	return reverseBytes(res)
}

func reverseBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	for i, b := range src {
		dst[len(src)-i-1] = b
	}
	return dst
}

func findByte(req []byte, pos, bias int, rc RC4System) byte {
	mp := make(map[byte]uint64)
	for i := 0; i < 1<<24; i++ {
		dst := rc.Req(req)
		mp[dst[pos]] += 1
	}
	maxN := uint64(0)
	maxS := byte(0)
	for bt, count := range mp {
		if count <= maxN {
			continue
		}
		maxN = count
		maxS = bt
	}

	return byte(int(maxS) ^ bias)
}
