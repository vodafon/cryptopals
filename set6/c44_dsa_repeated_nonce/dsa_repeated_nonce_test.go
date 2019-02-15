package c44_dsa_repeated_nonce

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
	"github.com/vodafon/cryptopals/set6/c43_dsa_from_nonce"
)

func TestExploit(t *testing.T) {
	texts := loadTexts("./testdata/44.txt")
	dsa := c43_dsa_from_nonce.NewDSA()
	exp := []byte("ca8f6f7c66fa362d40760d135b763eb8527d3d52")
	x, err := Exploit(dsa, texts)
	if err != nil {
		t.Fatalf("Exploit error: %s\n", err)
	}
	hex := c1_hex_to_base64.EncodeHex(x.Bytes())
	sum := sha1.Sum(hex)
	res := c1_hex_to_base64.EncodeHex(sum[:])
	if !bytes.Equal(exp, res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", exp, res)
	}
}

func loadTexts(filepath string) []Text {
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	texts := []Text{}

	i := 1
	text := Text{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		bline := scanner.Text()
		switch i % 4 {
		case 1:
			text.Msg = []byte(bline[5:])
		case 2:
			text.S = stringToBig(bline[3:], 10)
		case 3:
			text.R = stringToBig(bline[3:], 10)
		case 0:
			text.M = stringToBig(bline[3:], 16)
			texts = append(texts, text)
			text = Text{}
		}
		i += 1
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return texts
}

func stringToBig(src string, base int) *big.Int {
	src = strings.TrimSpace(src)
	r, ok := new(big.Int).SetString(src, base)
	if !ok {
		panic("bytesToBig failed")
	}
	return r
}
