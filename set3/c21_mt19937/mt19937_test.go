package c21_mt19937

import (
	"testing"
)

func TestMT19937(t *testing.T) {
	mt := NewMT19937(10)

	for _, exp := range expected {
		res := mt.ExtractNumber()
		if res != exp {
			t.Errorf("Incorrect number. Expected %d, got %d\n", exp, res)
		}
	}
}

// from https://codepen.io/telinc1/pen/kkVaNB
var expected = []uint32{
	3312796937,
	1283169405,
	89128932,
	2124247567,
	2721498432,
	1902734705,
	3216088187,
	3573032092,
	2141071321,
	2505347805,
	965494256,
	108111773,
	850673521,
	3046025210,
	3266454536,
	1140597833,
	726325504,
	1132165610,
	379416616,
	645868022,
}
