package c22_crack_mt19937_seed

import (
	"testing"
	"time"
)

func TestExploit(t *testing.T) {
	seed := uint32(time.Now().Unix())
	num := Number(seed)
	res := Exploit(num)
	if res != seed {
		t.Errorf("Incorrect seed for number %d. Expected %d, got %d\n", num, seed, res)
	}
}
