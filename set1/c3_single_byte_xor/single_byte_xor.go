package c3_single_byte_xor

import (
	"bytes"
	"sort"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set1/scoring_text"
)

type ScoreResult struct {
	Score  float64
	Key    byte
	Bytes  []byte
	Source string
}

func BruteForceBySingleByte(src []byte, topLen int) []ScoreResult {
	results := []ScoreResult{}
	for i := 0; i < 255; i++ {
		symb := byte(i)
		rep := bytes.Repeat([]byte{symb}, len(src))
		dst := c2_fixed_xor.SafeXORBytes(src, rep)
		score := scoring_text.EnScoreBytes(dst)
		results = append(results, ScoreResult{Score: score, Key: symb, Bytes: dst})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	return results[0:topLen]
}

func BruteForceBySingleByteBest(src []byte) ScoreResult {
	return BruteForceBySingleByte(src, 1)[0]
}
