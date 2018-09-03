package c10_implement_cbc_mode

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestCBCMode(t *testing.T) {
	file, _ := ioutil.ReadFile("testdata/10.txt")

	src, _ := c1_hex_to_base64.DecodeBase64(file)
	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{byte(0)}, len(key))
	res := CBCMode(src, key, iv)

	exp := "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them"
	if !strings.Contains(string(res), exp) {
		t.Errorf("Incorrect result. Expect %s contain %s\n", res, exp)
	}
}
