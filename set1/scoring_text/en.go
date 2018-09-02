package scoring_text

func EnScoreBytes(text []byte) float64 {
	score := 0.0
	for _, v := range text {
		if (v <= 'z' && v >= 'a') || (v <= 'Z' && v >= 'A') || v == ' ' || v == ',' || v == '.' || v == '!' || v == ':' || v == 10 {
			score += 0.1
		} else {
			score -= 0.5
		}
	}
	return score
}
