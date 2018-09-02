package c4_detect_single_character_xor

import (
	"bufio"
	"os"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set1/c3_single_byte_xor"
)

func DetectBest(file *os.File) (string, []byte) {
	scanner := bufio.NewScanner(file)
	result := c3_single_byte_xor.ScoreResult{Score: -100.0}
	for scanner.Scan() {
		text := scanner.Text()
		src := c1_hex_to_base64.ParseHex(text)
		res := c3_single_byte_xor.BruteForceBySingleByteBest(src)
		res.Source = text
		if res.Score > result.Score {
			result = res
		}
	}
	return result.Source, result.Bytes
}
