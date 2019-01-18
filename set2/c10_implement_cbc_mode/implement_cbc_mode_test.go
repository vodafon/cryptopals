package c10_implement_cbc_mode

import (
	"bytes"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c1_hex_to_base64"
)

func TestDecrypt(t *testing.T) {
	file, _ := ioutil.ReadFile("testdata/10.txt")

	src, _ := c1_hex_to_base64.DecodeBase64(file)
	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{byte(0)}, len(key))
	res := Decrypt(src, key, iv)

	exp := "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them"
	if !strings.Contains(string(res), exp) {
		t.Errorf("Incorrect result. Expect %s contain %s\n", res, exp)
	}
}

func TestEncrypt(t *testing.T) {
	plaintext := []byte("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me")
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	rand.Read(iv)

	ciphertext := Encrypt(plaintext, key, iv)
	res := Decrypt(ciphertext, key, iv)
	if !bytes.Equal(res, plaintext) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", plaintext, res)
	}
}
