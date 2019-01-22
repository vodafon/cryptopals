package c19_break_fixed_nonce_ctr

import (
	"bytes"
	"sort"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set1/scoring_text"
)

type wordScore struct {
	key           []byte
	startPosition int
	score         float64
	word          string
}

var words = []string{"e", "the", "end", "and", "he", "she", "his", "have", "has", "or", "of", "head", "at", "head", "in", "so", ".", ",", " "}

func Exploit(lines [][]byte) ([]byte, error) {
	maxSize := 0
	for _, line := range lines {
		if len(line) > maxSize {
			maxSize = len(line)
		}
	}
	scores := []wordScore{}
	for _, word := range words {
		scores = append(scores, wordScores([]byte(word), lines, maxSize)...)
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})
	keystream := keystreamFromScores(scores, maxSize)
	return keystream, nil
}

func keystreamFromScores(scores []wordScore, maxSize int) []byte {
	keystream := make([]byte, maxSize)
	filledPositions := []int{}

loopScore:
	for _, score := range scores {
		for i := score.startPosition; i < score.startPosition+len(score.key); i++ {
			for _, pos := range filledPositions {
				if pos == i {
					continue loopScore
				}
			}
		}
		for i, v := range score.key {
			keystream[i+score.startPosition] = v
			filledPositions = append(filledPositions, i+score.startPosition)
		}
	}
	return keystream
}

func wordScores(word []byte, lines [][]byte, maxSize int) []wordScore {
	scores := []wordScore{}
	for i := 0; i < maxSize-len(word); i++ {
		cWord := bytes.ToLower(word)
		if i == 0 {
			cWord = bytes.Title(cWord)
		}
		scores = append(scores, wordScorePosition(cWord, lines, i))
	}
	return scores
}

func wordScorePosition(word []byte, lines [][]byte, pos int) wordScore {
	ws := wordScore{
		startPosition: pos,
		key:           make([]byte, len(word)),
		score:         -1000.0,
		word:          string(word),
	}
	for idx1, l1 := range lines {
		if pos+len(word) > len(l1) {
			continue
		}
		score := 0.0
		key := c2_fixed_xor.SafeXORBytes(l1[pos:pos+len(word)], word)
		for idx2, l2 := range lines {
			if idx1 == idx2 || pos+len(word) > len(l2) {
				continue
			}
			plain := c2_fixed_xor.SafeXORBytes(l2[pos:pos+len(word)], key)
			score += scoring_text.EnScoreCorpus(plain)
		}
		if score > ws.score {
			ws.score = score
			ws.key = key
		}
	}
	return ws
}
