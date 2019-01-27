package c24_break_mt19937_stream_cipher

import (
	"bytes"
	"errors"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set3/c21_mt19937"
)

const (
	maxSeed   = 65535
	tokenSize = 20
)

type prng interface {
	ExtractNumber() uint32
}

type ByteStream struct {
	rng prng
}

func (obj ByteStream) Next() byte {
	return byte(obj.rng.ExtractNumber())
}

func Encode(src []byte, rng prng) []byte {
	bs := ByteStream{
		rng: rng,
	}
	dst := make([]byte, len(src))
	for i, v := range src {
		dst[i] = v ^ bs.Next()
	}
	return dst
}

func Decode(src []byte, rng prng) []byte {
	return Encode(src, rng)
}

func EncodeMT19937(src []byte, seed uint32) []byte {
	mt := c21_mt19937.NewMT19937(seed)
	return Encode(src, mt)
}

func DecodeMT19937(src []byte, seed uint32) []byte {
	return EncodeMT19937(src, seed)
}

func BruteForce(ciphertext, partPlaintext []byte, maxSeed uint32) (uint32, []byte, error) {
	for i := uint32(0); i < maxSeed; i++ {
		dec := DecodeMT19937(ciphertext, i)
		if bytes.Contains(dec, partPlaintext) {
			return i, dec, nil
		}
	}
	return 0, nil, errors.New("Not found")
}

func ResetToken() []byte {
	dst := make([]byte, tokenSize)
	seed := uint32(time.Now().Unix())
	mt := c21_mt19937.NewMT19937(seed)
	bs := ByteStream{mt}
	for i := 0; i < len(dst); i++ {
		dst[i] = bs.Next()
	}
	return c1_hex_to_base64.EncodeBase64(dst)
}

func IsTimeSeededToken(token []byte) bool {
	t := time.Now().Unix()
	for i := t - 10; i < t+1; i++ {
		dst := make([]byte, tokenSize)
		mt := c21_mt19937.NewMT19937(uint32(i))
		bs := ByteStream{mt}
		for i := 0; i < len(dst); i++ {
			dst[i] = bs.Next()
		}
		if bytes.Equal(c1_hex_to_base64.EncodeBase64(dst), token) {
			return true
		}
	}
	return false
}
