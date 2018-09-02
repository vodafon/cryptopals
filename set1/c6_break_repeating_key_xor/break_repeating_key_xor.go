package c6_break_repeating_key_xor

import (
	"errors"
	"sort"

	"github.com/vodafon/cryptopals/set1/c3_single_byte_xor"
)

type keyElem struct {
	pos   int
	value byte
}

func HammingDistance(s1, s2 []byte) int {
	if len(s1) != len(s2) {
		panic(errors.New("sources are not the same length"))
	}

	diff := 0
	for i := 0; i < len(s1); i++ {
		b1 := s1[i]
		b2 := s2[i]
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint(j))
			if (b1 & mask) != (b2 & mask) {
				diff++
			}
		}
	}
	return diff
}

func KeySizeDetect(src []byte) (int, float64) {
	dist := 1000.0
	kSize := 0
	for i := 2; i < 41; i++ {
		pos := 0
		iter := 0
		sumDiff := 0
		for {
			if (pos + i*2) >= len(src)-1 {
				break
			}
			b1 := src[pos:(pos + i)]
			b2 := src[(pos + i):(pos + i*2)]
			diff := HammingDistance(b1, b2)
			iter++
			sumDiff += diff
			pos += i
		}
		avgDiff := float64(sumDiff) / float64(iter) / float64(i)
		if dist > avgDiff {
			dist = avgDiff
			kSize = i
		}
	}
	return kSize, dist
}

func BreakKeyXOR(src []byte, keySize int) []byte {
	blocks := createBlocks(src, keySize)
	keys := bruteBlocks(blocks)
	res := []byte{}
	for _, v := range keys {
		res = append(res, v.value)
	}
	return res
}

func bruteBlocks(blocks map[int][]byte) []keyElem {
	keys := []keyElem{}
	for k, v := range blocks {
		sr := c3_single_byte_xor.BruteForceBySingleByteBest(v)
		key := keyElem{pos: k, value: sr.Key}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].pos < keys[j].pos
	})
	return keys
}

func createBlocks(src []byte, keySize int) map[int][]byte {
	blocks := make(map[int][]byte)
	for k, v := range src {
		i := k % keySize
		blocks[i] = append(blocks[i], v)
	}
	return blocks
}
