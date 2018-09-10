package c11_ecb_cbc_detection

import (
	"bytes"
	"testing"
)

func TestEncriptionOracle(t *testing.T) {
	src := bytes.Repeat([]byte{'A'}, 100)
	cbcCount := 0
	ecbCount := 0

	for cbcCount < 50 {
		res, algo := EncryptionOracle(src)
		if bytes.Equal(res[16:32], res[32:48]) {
			if algo != "ECB" {
				t.Errorf("Incorrect CBC/ECB detection: %q %s", res, algo)
			}
			ecbCount += 1
		} else {
			if algo != "CBC" {
				t.Errorf("Incorrect CBC/ECB detection: %q %s", res, algo)
			}
			cbcCount += 1
		}
	}

	if ecbCount < 10 {
		t.Errorf("Incorrect randomization. ECB: %d, CBC %d", ecbCount, cbcCount)
	}
}
