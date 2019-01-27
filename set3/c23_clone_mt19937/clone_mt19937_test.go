package clone_mt19937

import (
	"math/rand"
	"testing"

	"github.com/vodafon/cryptopals/set3/c21_mt19937"
)

func TestUntemper(t *testing.T) {
	for i := 0; i < 100; i++ {
		num := rand.Uint32()
		tm := c21_mt19937.Temper(num)
		utm := Untemper(tm)
		if num != utm {
			t.Fatalf("Incorrect untemper (iter: %d). Expected: %d, got %d\n", i, num, utm)
		}
	}
}

func TestClone(t *testing.T) {
	mt := [624]uint32{}
	seed := rand.Uint32()
	orig := c21_mt19937.NewMT19937(seed)
	clone := c21_mt19937.NewMT19937(0)
	for i := 0; i < 624; i++ {
		mt[i] = Untemper(orig.ExtractNumber())
	}
	clone.Update(mt, 624)
	for i := 0; i < 1300; i++ {
		oV := orig.ExtractNumber()
		cV := clone.ExtractNumber()
		if oV != cV {
			t.Fatalf("Invalid result (iter: %d). Orig: %d, Clone: %d\n", i, oV, cV)
		}
	}
}
