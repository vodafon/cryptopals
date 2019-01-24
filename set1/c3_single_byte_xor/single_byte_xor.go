package c3_single_byte_xor

import (
	"bytes"
	"fmt"
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

func (obj ScoreResult) String() string {
	return fmt.Sprintf("Score: %.5f, Key: %x, Bytes: %q", obj.Score, obj.Key, obj.Bytes)
}

func BruteForceBySingleByte(src []byte, topLen int) []ScoreResult {
	fun := scoring_text.EnScoreBytes
	return bruteForceFun(src, topLen, fun)
}

func BruteForceBySingleByteBest(src []byte) ScoreResult {
	return BruteForceBySingleByte(src, 1)[0]
}

func BruteForceByCorpus(src []byte, topLen int) []ScoreResult {
	fun := scoring_text.EnScoreCorpus
	return bruteForceFun(src, topLen, fun)
}

func BruteForceByCorpusBest(src []byte) ScoreResult {
	return BruteForceByCorpus(src, 1)[0]
}

func bruteForceFun(src []byte, topLen int, fun func([]byte) float64) []ScoreResult {
	results := []ScoreResult{}
	for i := 0; i < 256; i++ {
		symb := byte(i)
		rep := bytes.Repeat([]byte{symb}, len(src))
		dst := c2_fixed_xor.SafeXORBytes(src, rep)
		score := fun(dst)
		results = append(results, ScoreResult{Score: score, Key: symb, Bytes: dst})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	return results[0:topLen]
}
