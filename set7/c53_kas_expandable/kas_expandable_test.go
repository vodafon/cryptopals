package c53_kas_expandable

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestExploit(t *testing.T) {
	mh := NewMalHash(3)
	msg := make([]byte, (1<<10)+11)
	rand.Read(msg)
	msg2 := Exploit(msg, mh)

	if len(msg) != len(msg2) {
		t.Errorf("Incorrect size. Expected %d, got %d\n", len(msg), len(msg2))
	}

	mh.Reset()
	msgH := mh.Sum(msg)
	mh.Reset()
	msg2H := mh.Sum(msg2)

	if !bytes.Equal(msgH, msg2H) {
		t.Errorf("Incorrect Hash. Expected %x, got %x\n", msgH, msg2H)
	}
}

func TestFindCollision(t *testing.T) {
	mh := NewMalHash(4)
	n := 10
	pair, state := findCollisionPair(n, []byte{}, mh)
	checkPair(pair, n, []byte{}, state, mh, t)
	pair, state2 := findCollisionPair(n, state, mh)
	checkPair(pair, n, state, state2, mh, t)
}

func checkPair(pair Pair, n int, state, state2 []byte, mh *MalHash, t *testing.T) {
	if len(pair.m0) != mh.BlockSize() {
		t.Errorf("Incorrect result. Expected %d, got %d\n", mh.BlockSize(), len(pair.m0))
	}
	if len(pair.m1) != mh.BlockSize()*n {
		t.Errorf("Incorrect result. Expected %d, got %d\n", mh.BlockSize()*n, len(pair.m1))
	}
	mh.SetState(state)
	h0 := mh.Sum(pair.m0)
	mh.SetState(state)
	h1 := mh.Sum(pair.m1)
	if !bytes.Equal(h0, h1) {
		t.Errorf("Incorrect result. Expected %x, got %x\n", h1, h0)
	}
	if !bytes.Equal(h0, state2) {
		t.Errorf("Incorrect state. Expected %x, got %x\n", h0, state2)
	}
}
