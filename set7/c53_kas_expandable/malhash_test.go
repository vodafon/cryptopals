package c53_kas_expandable

import (
	"bytes"
	"testing"
)

func TestMalHash(t *testing.T) {
	mh := NewMalHash(4)
	s1 := mh.Sum(bytes.Repeat([]byte("A"), 20))
	mh.Reset()
	s2 := mh.Sum(bytes.Repeat([]byte("A"), 20))
	if !bytes.Equal(s1, s2) {
		t.Errorf("Different sum for same text\n")
	}
	s3 := mh.Sum(bytes.Repeat([]byte("B"), 20))
	if bytes.Equal(s1, s3) {
		t.Errorf("Same checksum for different texts\n")
	}
}

func TestState(t *testing.T) {
	mh := NewMalHash(4)
	s1 := mh.Sum(bytes.Repeat([]byte("A"), mh.BlockSize()*2))
	mh.Reset()
	mh.Write(bytes.Repeat([]byte("A"), mh.BlockSize()))
	s2 := mh.Sum(bytes.Repeat([]byte("A"), mh.BlockSize()))
	if !bytes.Equal(s1, s2) {
		t.Errorf("Incorrect addidtional Write\n")
	}

	mh.Reset()
	s2 = mh.Sum(bytes.Repeat([]byte("A"), mh.BlockSize()))
	mh.SetState(s2)
	s3 := mh.Sum(bytes.Repeat([]byte("A"), mh.BlockSize()))
	if !bytes.Equal(s1, s3) {
		t.Errorf("Incorrect SetState\n")
	}
}
