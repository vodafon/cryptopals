package c8_detect_aes_ecb

import (
	"bufio"
	"os"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestDetectAes(t *testing.T) {
	file, _ := os.Open("testdata/8.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	aeses := [][]byte{}
	for scanner.Scan() {
		hex := scanner.Bytes()
		enc, _ := c1_hex_to_base64.DecodeHex(hex)
		isAes := IsAesEcb(enc)
		if isAes {
			aeses = append(aeses, hex)
		}
	}
	esp := []byte("e8ed25e6f2b5cd72277cff0831b34d9980566aa183ec0e171ee3539bcdd70c831154e2c415c0a4dbba166cedb8ff10e677546845f85c081aed78a280fde896eab49ee37f88afb3e85676bcaf4cdb8acdf528ee703dd5ec05d7290ec200bbda77df57251e31ea70c6785c72c9a4b19439fa6f45f1713ba7890d983dedd45e2cf05f07606db3000dd60b69c3363efa71f9a6ee1dd8fdbb15b15257ef8b8754e349")
	if len(aeses) != 1 || !BytesEqual(aeses[0], esp) {
		t.Error("Detect AES ECB failed.\n")
	}
}
