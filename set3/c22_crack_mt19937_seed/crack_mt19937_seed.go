package c22_crack_mt19937_seed

import (
	"math/rand"
	"time"

	"github.com/vodafon/cryptopals/set3/c21_mt19937"
)

func Number(seed uint32) uint32 {
	mt := c21_mt19937.NewMT19937(seed)
	waitRandom()
	return mt.ExtractNumber()
}

func Exploit(num uint32) uint32 {
	seed := uint32(time.Now().Unix())
	for seed >= 0 {
		if c21_mt19937.NewMT19937(seed).ExtractNumber() == num {
			return seed
		}
		seed -= 1
	}
	return seed
}

func waitRandom() {
	t := rand.Intn(5) + 1
	time.Sleep(time.Duration(t) * time.Second)
}
