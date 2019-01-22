package scoring_text

import (
	"bytes"
)

func EnScoreCorpus(text []byte) float64 {
	text = bytes.ToLower(text)
	score := 0.0
	for _, b := range text {
		score += EnCorpus[b]
	}
	return score / float64(len(text))
}

func EnScoreBytes(text []byte) float64 {
	score := 0.0
	for _, v := range text {
		if IsValidByte(v) {
			score += 0.1
		} else {
			score -= 0.5
		}
	}
	return score
}

func IsValidByte(v byte) bool {
	if (v <= 'Z' && v >= 'A') || (v <= 'z' && v >= 'a') || v == ' ' || v == ',' || v == '.' || v == '!' || v == ':' || v == 10 || v == '?' || v == ';' {
		return true
	}
	return false
}
