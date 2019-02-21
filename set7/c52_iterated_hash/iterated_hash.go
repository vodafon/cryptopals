package c52_iterated_hash

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
)

const encSize = 16

type MalHash struct {
	state []byte
	size  int
}

func NewMalHash(size int) *MalHash {
	state := bytes.Repeat([]byte("S"), size)
	return &MalHash{
		size:  size,
		state: state,
	}
}

func (obj *MalHash) Size() int {
	return obj.size
}

func (obj *MalHash) Sum(text []byte) []byte {
	obj.reset()
	_, err := obj.write(text)
	if err != nil {
		panic(err)
	}
	return obj.state
}

func (obj *MalHash) write(text []byte) (int, error) {
	nn := len(text)
	text = leftPad(text, encSize)
	start, finish := 0, encSize
	for finish < len(text)+1 {
		block, err := aes.NewCipher(leftPad(obj.state, encSize))
		if err != nil {
			return 0, err
		}
		cip := make([]byte, encSize)
		block.Encrypt(cip, leftPad(text[start:finish], encSize))
		obj.state = cip[len(cip)-obj.size:]
		start += encSize
		finish += encSize
	}
	return nn, nil
}

func (obj *MalHash) reset() {
	obj.state = bytes.Repeat([]byte("S"), obj.size)
}

func Exploit(f, g *MalHash) (Collision, error) {
	b2 := 2 << uint(g.Size()*8/2)
	cols := FindNCollisions(b2, f)
	for _, col := range cols {
		s1 := g.Sum(col.B1)
		s2 := g.Sum(col.B2)
		if bytes.Equal(s1, s2) {
			col.Sum = s1
			return col, nil
		}
	}
	return Collision{}, errors.New("not found")
}

type Collision struct {
	B1  []byte
	B2  []byte
	Sum []byte
}

func FindNCollisions(n int, mh *MalHash) []Collision {
	hmap := make(map[string][]byte)
	inp := make([]byte, mh.Size())
	rand.Read(inp)
	res := []Collision{}
	for len(res) < n {
		col := findOneCollision(inp, hmap, mh)
		inp = append(inp, col.Sum...)
		res = append(res, col)
	}

	return res
}

func findOneCollision(inp []byte, hmap map[string][]byte, mh *MalHash) Collision {
	nn := 1
	add := make([]byte, 1)
	rand.Read(add)
	base := append(inp, add...)
	for {
		tmp := make([]byte, len(base))
		copy(tmp, base)
		sum := mh.Sum(tmp)

		b1, ok := hmap[string(sum)]
		if ok && !bytes.Equal(b1, tmp) {
			//fmt.Printf("collision sum %x for (%x %x). Iteration: %d\n", sum, b1, tmp, nn)
			return Collision{
				B1:  b1,
				B2:  tmp,
				Sum: sum,
			}
		}
		hmap[string(sum)] = tmp
		base = append(inp, sum...)

		nn += 1
	}
	return Collision{}
}

func leftPad(src []byte, k int) []byte {
	if len(src) >= k {
		return src
	}
	dst := make([]byte, k)
	copy(dst[k-len(src):], src)
	return dst
}
