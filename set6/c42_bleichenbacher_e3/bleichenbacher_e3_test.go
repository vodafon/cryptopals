package c42_bleichenbacher_e3

import (
	"bytes"
	"testing"
)

func TestSign(t *testing.T) {
	ss := NewSignSystem(1024)
	msg := bytes.Repeat([]byte("A"), 20)
	sign, err := ss.Sign(msg)
	if err != nil {
		t.Errorf("Sign error: %s\n", err)
	}

	// valid
	ver := ss.Verify(msg, sign)
	if !ver {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}

	ver = ss.Verify(msg[1:], sign)
	if ver {
		t.Errorf("Incorrect result. Expected false, got true\n")
	}
}

func TestExploit(t *testing.T) {
	ss := NewSignSystem(2048)
	msg := []byte("hi mom")
	sign := Exploit(msg, 256)
	ver := ss.Verify(msg, sign)
	if !ver {
		t.Errorf("Incorrect result. Expected true, got false\n")
	}
}
