package c54_nostradamus_attack

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"

	"github.com/vodafon/cryptopals/set7/c53_kas_expandable"
)

type Pair struct {
	bls1, bls2 BlockState
	colState   []byte
}

type BlockState struct {
	block, state []byte
}

func Exploit(prefix1, prefix2 []byte, k, lBytes int, mh *c53_kas_expandable.MalHash) ([]byte, []byte) {
	iStates := initialStates(k, mh)
	d := buildDiamand(iStates, k, mh)
	if lBytes < (len(d)*mh.BlockSize()+len(prefix1)+16) || lBytes < (len(d)*mh.BlockSize()+len(prefix2)+16) {
		panic("lBytes too small")
	}
	if len(prefix1)%mh.BlockSize() != 0 || len(prefix2)%mh.BlockSize() != 0 || lBytes%mh.BlockSize() != 0 {
		panic("wrong size") // for simplicity, attacker chose this parameters
	}

	msg1 := prefixMessage(prefix1, iStates, lBytes, d, mh)
	msg2 := prefixMessage(prefix2, iStates, lBytes, d, mh)

	return msg1, msg2
}

func prefixMessage(prefix []byte, iStates [][]byte, lBytes int, d [][]Pair, mh *c53_kas_expandable.MalHash) []byte {
	prefix = prefixPad(prefix, lBytes-len(d)*mh.BlockSize()-16)
	bridge := findBridge(prefix, iStates, mh)
	prefix = append(prefix, bridge...)
	return fullMessage(prefix, d, mh)
}

func fullMessage(prefix []byte, d [][]Pair, mh *c53_kas_expandable.MalHash) []byte {
	mh.Reset()
	state := mh.Sum(prefix)
	for i := 0; i < len(d); i++ {
		msg, blsState := nextPair(state, d[i])
		prefix = append(prefix, msg...)
		state = blsState
	}
	return prefix
}

func nextPair(state []byte, dl []Pair) ([]byte, []byte) {
	for _, pair := range dl {
		if bytes.Equal(pair.bls1.state, state) {
			return pair.bls1.block, pair.colState
		}
		if bytes.Equal(pair.bls2.state, state) {
			return pair.bls2.block, pair.colState
		}
	}
	panic("nextPair not found")
	return nil, nil
}

func findBridge(prefix []byte, iStates [][]byte, mh *c53_kas_expandable.MalHash) []byte {
	iStatesMap := make(map[string][]byte)
	for _, iState := range iStates {
		iStatesMap[toHex(iState)] = iState
	}

	mh.Reset()
	state := mh.Sum(prefix)

	for {
		block := make([]byte, mh.BlockSize())
		rand.Read(block)
		mh.SetState(state)
		h := mh.Sum(block)
		if _, ok := iStatesMap[toHex(h)]; ok {
			return block
		}
	}
	return nil
}
func prefixPad(prefix []byte, l int) []byte {
	pad := make([]byte, l-len(prefix))
	rand.Read(pad)
	return append(prefix, pad...)
}

func buildDiamand(iStates [][]byte, k int, mh *c53_kas_expandable.MalHash) [][]Pair {
	n := mh.Size() * 8
	size := 1 << uint(n/2+1)
	res := [][]Pair{}
	blocks := randomBlocks(size, mh.BlockSize())
	states := iStates
	for len(states) > 1 {
		pairs, tmpStates := statesToPair(states, blocks, mh)
		if len(pairs) == len(states)/2 {
			res = append(res, pairs)
			states = tmpStates
		} else {
			blocks = randomBlocks(size, mh.BlockSize())
		}
	}
	return res
}

func statesToPair(states, blocks [][]byte, mh *c53_kas_expandable.MalHash) ([]Pair, [][]byte) {
	pairs := []Pair{}
	tmpMap := make(map[string]BlockState)
	foundPairs := make(map[string]int)
	colStates := [][]byte{}
	for _, state := range states {
		for _, block := range blocks {
			mh.SetState(state)
			h := mh.Sum(block)
			bs1 := BlockState{block, state}
			bs2, ok1 := tmpMap[toHex(h)]
			tmpMap[toHex(h)] = bs1
			_, ok2 := foundPairs[toHex(bs2.state)]
			if ok2 || bytes.Equal(state, bs2.state) {
				continue
			}
			if ok1 {
				pair := Pair{
					bls1:     bs1,
					bls2:     bs2,
					colState: h,
				}
				pairs = append(pairs, pair)
				colStates = append(colStates, h)
				foundPairs[toHex(state)] = 1
				foundPairs[toHex(bs2.state)] = 1
				break
			}
		}
	}
	return pairs, colStates
}

func randomBlocks(size, blockSize int) [][]byte {
	res := [][]byte{}
	tmpMap := make(map[string]int)
	for len(res) < size {
		block := make([]byte, blockSize)
		rand.Read(block)
		if _, ok := tmpMap[toHex(block)]; ok {
			continue
		}
		res = append(res, block)
		tmpMap[toHex(block)] = 1
	}
	return res
}

func initialStates(k int, mh *c53_kas_expandable.MalHash) [][]byte {
	res := [][]byte{}
	tmpMap := make(map[string]int)
	for len(res) < 1<<uint(k) {
		block := make([]byte, mh.BlockSize())
		rand.Read(block)
		mh.Reset()
		h := mh.Sum(block)
		if _, ok := tmpMap[toHex(h)]; ok {
			continue
		}
		res = append(res, h)
		tmpMap[toHex(h)] = 1
	}
	return res
}

func toHex(src []byte) string {
	return hex.EncodeToString(src)
}
