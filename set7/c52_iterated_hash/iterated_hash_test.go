package c52_iterated_hash

import (
	"bytes"
	"testing"
)

func TestMalHash(t *testing.T) {
	mh := NewMalHash(2)
	s1 := mh.Sum(bytes.Repeat([]byte("A"), 20))
	s2 := mh.Sum(bytes.Repeat([]byte("A"), 20))
	if !bytes.Equal(s1, s2) {
		t.Errorf("Different sum for same text\n")
	}
	s3 := mh.Sum(bytes.Repeat([]byte("B"), 20))
	if bytes.Equal(s1, s3) {
		t.Errorf("Same checksum for different texts\n")
	}
}

func TestCollisions(t *testing.T) {
	mh := NewMalHash(2)
	cols := FindNCollisions(10, mh)
	for i, col := range cols {
		checkCollision(col, mh, i, t)
	}
}

func TestExploit(t *testing.T) {
	f := NewMalHash(2)
	g := NewMalHash(3)
	col, err := Exploit(f, g)
	if err != nil {
		t.Fatalf("Exploit error: %s\n", err)
	}
	checkCollision(col, g, 0, t)
}

func checkCollision(col Collision, mh *MalHash, i int, t *testing.T) {
	if bytes.Equal(col.B1, col.B2) {
		t.Errorf("%d: B1 and B2 is equal\n", i)
	}
	s1 := mh.Sum(col.B1)
	if !bytes.Equal(s1, col.Sum) {
		t.Errorf("%d: Incorrect result for B1. Expected %x, got %x\n", i, s1, col.Sum)
	}

	s1 = mh.Sum(col.B2)
	if !bytes.Equal(s1, col.Sum) {
		t.Errorf("%d: Incorrect result for B1. Expected %x, got %x\n", i, s1, col.Sum)
	}
}
