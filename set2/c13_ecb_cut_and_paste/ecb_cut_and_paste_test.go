package c13_ecb_cut_and_paste

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/vodafon/cryptopals/set1/c7_aes_ecb"
)

func TestParseQuery(t *testing.T) {
	inp := "foo=bar&baz=qux&zap=zazzle"
	mp := ParseQuery(inp)

	if len(mp) != 3 {
		t.Errorf("invalid length for result ParseQuery. Expected 3, got %d\n", len(mp))
	}
	if mp["foo"] != "bar" || mp["baz"] != "qux" || mp["zap"] != "zazzle" {
		t.Errorf("invalid result %v for %s in ParseQuery\n", mp, inp)
	}
}

func TestProfileFor(t *testing.T) {
	pr := ProfileFor("a@email.com")
	if pr.Email != "a@email.com" || pr.UID != 10 || pr.Role != "user" {
		t.Errorf("invalid result in ProfileFor: %v\n", pr)
	}

	emails := []string{"a@email.com&role=admin", "role=admin&a@email.com", "a@email.com&role=admin&role=admin"}
	for _, email := range emails {
		q := ProfileFor(email).ToQuery()
		if strings.Contains(q, "role=admin") {
			t.Errorf("invalid quoting parameters in ProfileFor. For %s result %s\n", email, q)
		}
	}
}

func TestAttackProfile(t *testing.T) {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)

	padding := 11
	// user@emai.admin\v\v\v\v\v\v\v\v\v\v\vcom
	email := fmt.Sprintf("user@emai.admin%scom", bytes.Repeat([]byte{byte(padding)}, padding))
	inp := ProfileFor(email).ToQuery()
	// "email=user@emai."|"admin\v\v\v\v\v\v\v\v\v\v\v"|"com&uid=10&role="
	ciphertext := c7_aes_ecb.Encrypt([]byte(inp), key)
	size := 16
	var payload bytes.Buffer
	payload.Write(ciphertext[0:size])
	payload.Write(ciphertext[size*2 : size*3])
	payload.Write(ciphertext[size : size*2])
	// email=user@emai.com&uid=10&role=admin
	res := c7_aes_ecb.Decrypt(payload.Bytes(), key)

	mp := ParseQuery(string(res))
	if mp["role"] != "admin" || mp["email"] != "user@emai.com" || mp["uid"] != "10" {
		t.Errorf("Invalid result: %v\n", mp)
	}
}
