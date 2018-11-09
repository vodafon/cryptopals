package c14_ecb_decription_harder

import (
	"bytes"
	"errors"

	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
	"github.com/vodafon/cryptopals/set2/c12_ecb_decription_simple"
)

func NewEnc(key, prefix, tail []byte) Enc {
	return Enc{
		key:    key,
		tail:   tail,
		prefix: prefix,
	}
}

type Enc struct {
	key    []byte
	tail   []byte
	prefix []byte
}

func (e Enc) Encrypt(src []byte) []byte {
	var buf bytes.Buffer

	buf.Write(e.prefix)
	buf.Write(src)
	buf.Write(e.tail)

	return c7_aes_ecb.Encrypt(buf.Bytes(), e.key)
}

func prefixSize(enc c12_ecb_decription_simple.Encryptor, bs int) (int, error) {
	inp := bytes.Repeat([]byte("A"), bs*2)
	for {
		slice, err := BytesToSlice(enc.Encrypt(inp), bs)
		if err != nil {
			return 0, err
		}

		dupi, err := duplicateIndex(slice)
		if err == nil {
			res := (dupi+2)*bs - len(inp)
			return res, nil
		}

		inp = append(inp, 'A')
	}
	return 0, nil
}

func (e Enc) BruteForce(bs, prefixLen int) []byte {
	decr := []byte{}
	for i := 0; i < len(e.tail); i++ {
		decr = append(decr, findByte(decr, bs, prefixLen, e))
	}
	return decr
}

func findByte(decr []byte, bs, prefixLen int, enc c12_ecb_decription_simple.Encryptor) byte {
	appendPrefixLen := bs - prefixLen%bs
	size := (len(decr)/bs + 1) * bs
	base := bytes.Repeat([]byte("A"), size+appendPrefixLen-len(decr)-1)
	cut := prefixLen + appendPrefixLen
	target := enc.Encrypt(base)[cut : cut+size]
	for i := 0; i < 255; i++ {
		input := append(base, decr...)
		input = append(input, byte(i))
		output := enc.Encrypt(input)[cut : cut+size]
		if bytes.Equal(output, target) {
			return byte(i)
		}
	}
	return byte(0)
}

func duplicateIndex(chunks [][]byte) (int, error) {
	mp := make(map[string]int)
	for i, chunk := range chunks {
		str := string(chunk)
		idx, ok := mp[str]
		if ok {
			return idx, nil
		}
		mp[str] = i
	}
	return 0, errors.New("Duplicates not found")
}

func BytesToSlice(src []byte, size int) ([][]byte, error) {
	if len(src)%size != 0 {
		return [][]byte{}, errors.New("Invalid size")
	}
	var res [][]byte
	r := bytes.NewReader(src)
	for i := 0; i < len(src)/size; i++ {
		chunk := make([]byte, size)
		r.Read(chunk)
		res = append(res, chunk)
	}
	return res, nil
}
