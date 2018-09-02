package c4_detect_single_character_xor

import (
	"os"
	"testing"
)

func TestDetectBest(t *testing.T) {
	file, _ := os.Open("testdata/4.txt")
	src, dec := DetectBest(file)
	expSrc := "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
	expDec := "Now that the party is jumping\n"
	if src != expSrc || string(dec) != expDec {
		t.Errorf("Incorrect result. Expected: %s, got: %s\n", expSrc, src)
	}
}
