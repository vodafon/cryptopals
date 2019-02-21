package c51_compression_ratio

import (
	"testing"
)

func TestExploitCTR(t *testing.T) {
	sid := "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
	cs := NewCompressSystem(sid, CTRMode)
	res := ExploitCTR(cs)

	if sid != string(res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", sid, res)
	}
}

func TestExploitCBC(t *testing.T) {
	sid := "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
	cs := NewCompressSystem(sid, CBCMode)
	res := ExploitCBC(cs)

	if sid != string(res) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", sid, res)
	}
}
