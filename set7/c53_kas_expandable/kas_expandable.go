package c53_kas_expandable

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
)

type Pair struct {
	m0 []byte
	m1 []byte
}

func Exploit(msg []byte, mh *MalHash) []byte {
	bs := len(msg) / mh.BlockSize()
	bigBS := big.NewInt(int64(bs))
	k := bigBS.BitLen() - 1
	c, hexp := expendableMessage([]byte{}, k, mh)
	mStates := intermediateStates(msg, k, mh)
	bridge, iM := findBridge(hexp, mStates, mh)
	iM += 1
	prefix := findPrefix(c, iM, k, bs)
	msg2 := append(prefix, bridge...)
	msg2 = append(msg2, msg[iM*mh.BlockSize():]...)

	return msg2
}

func findPrefix(c []Pair, iM, k int, bs int) []byte {
	l := bs - (bs - iM) - 1

	if l < k || l > (1<<uint(k))+k-1 {
		panic("invalid L")
	}
	s := binaryArray(l-k, len(c))
	prefix := []byte{}
	for i, pair := range c {
		if s[i] == 0 {
			prefix = append(prefix, pair.m0...)
		} else {
			prefix = append(prefix, pair.m1...)
		}
	}
	return prefix
}

func binaryArray(src, size int) []int {
	bsrc := strconv.FormatInt(int64(src), 2)
	if len(bsrc) < size {
		bsrc = strings.Repeat("0", size-len(bsrc)) + bsrc
	}
	res := make([]int, len(bsrc))
	for i := 0; i < len(bsrc); i++ {
		if bsrc[i] == '0' {
			res[i] = 0
		} else {
			res[i] = 1
		}
	}
	return res
}

func findBridge(state []byte, mStates map[string]int, mh *MalHash) ([]byte, int) {
	for {
		block := make([]byte, mh.BlockSize())
		rand.Read(block)
		mh.SetState(state)
		h := mh.Sum(block)
		i, ok := mStates[toHex(h)]
		if ok {
			return block, i
		}
	}
	return nil, 0
}

func intermediateStates(msg []byte, k int, mh *MalHash) map[string]int {
	res := make(map[string]int)
	state := []byte{}
	for i := 0; i < len(msg)/mh.BlockSize(); i++ {
		mh.SetState(state)
		h := mh.Sum(msg[i*mh.BlockSize() : (i+1)*mh.BlockSize()])
		if i > k {
			res[toHex(h)] = i
		}
		state = h
	}
	return res
}

func toHex(src []byte) string {
	return hex.EncodeToString(src)
}

func expendableMessage(state []byte, k int, mh *MalHash) ([]Pair, []byte) {
	res := make([]Pair, k)
	pair, htmp := Pair{}, state
	for i := 1; i <= k; i++ {
		pair, htmp = findCollisionPair((1<<uint(k-i))+1, htmp, mh)
		res[i-1] = pair
	}
	return res, htmp
}

func findCollisionPair(a int, state []byte, mh *MalHash) (Pair, []byte) {
	prefix := make([]byte, mh.BlockSize()*(a-1))
	rand.Read(prefix)
	mh.SetState(state)
	prefixState := mh.Sum(prefix)

	hmap := make(map[string][]byte)
	for {
		block := make([]byte, mh.BlockSize())
		rand.Read(block)
		mh.SetState(state)
		h1 := mh.Sum(block)
		hnP, ok := hmap[toHex(h1)]
		if ok {
			return Pair{block, append(prefix, hnP...)}, h1
		}
		mh.SetState(prefixState)
		hn := mh.Sum(block)
		hmap[toHex(hn)] = block
	}
	return Pair{}, nil
}
