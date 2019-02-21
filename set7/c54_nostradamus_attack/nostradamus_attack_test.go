package c54_nostradamus_attack

import (
	"bytes"
	"testing"

	"github.com/vodafon/cryptopals/set7/c53_kas_expandable"
)

func TestInitialStates(t *testing.T) {
	mh := c53_kas_expandable.NewMalHash(2)
	k := 4
	iStates := initialStates(k, mh)
	if len(iStates) != 16 {
		t.Errorf("Incorrect result. Expected %d, got %d\n", 16, len(iStates))
	}
}

func TestExploit(t *testing.T) {
	mh := c53_kas_expandable.NewMalHash(2)
	lBytes := 16 * 8
	k := 4
	pref1 := bytes.Repeat([]byte("A"), 16)
	pref2 := bytes.Repeat([]byte("B"), 32)
	msg1, msg2 := Exploit(pref1, pref2, k, lBytes, mh)

	if len(msg1) != len(msg2) || len(msg1) != lBytes {
		t.Errorf("Wrong result size. Expected %d, msg1: %d msg2: %d\n", lBytes, len(msg1), len(msg2))
	}

	if !bytes.Contains(msg1, pref1) {
		t.Errorf("Incorrect result. Expected %q contains %q\n", msg1, pref1)
	}
	if !bytes.Contains(msg2, pref2) {
		t.Errorf("Incorrect result. Expected %q contains %q\n", msg2, pref2)
	}

	mh.Reset()
	h1 := mh.Sum(msg1)
	mh.Reset()
	h2 := mh.Sum(msg2)

	if !bytes.Equal(h1, h2) {
		t.Errorf("Different sums %x %x\n", h1, h2)
	}
}
