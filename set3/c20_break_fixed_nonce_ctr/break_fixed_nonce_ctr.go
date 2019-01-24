package c19_break_fixed_nonce_ctr

import (
	"github.com/vodafon/cryptopals/set1/c3_single_byte_xor"
)

func Exploit(lines [][]byte) ([]byte, int, error) {
	minSize := 100
	for _, line := range lines {
		if len(line) < minSize {
			minSize = len(line)
		}
	}

	columns := columnsFromLines(lines, minSize)
	keystream := make([]byte, minSize)
	for i, col := range columns {
		sr := c3_single_byte_xor.BruteForceByCorpusBest(col)
		keystream[i] = sr.Key
	}
	return keystream, minSize, nil
}

func columnsFromLines(lines [][]byte, minSize int) [][]byte {
	columns := make([][]byte, minSize)
	for _, line := range lines {
		for i := 0; i < minSize; i++ {
			columns[i] = append(columns[i], line[i])
		}
	}
	return columns
}
