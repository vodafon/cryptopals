package c38_simplified_srp

import (
	"bytes"
	"testing"
)

func TestSimplifiedSRP(t *testing.T) {
	email := []byte("email@test.com")
	password := []byte("paSSw0rD")
	stream := Init(email, password)
	auth := stream.Auth()
	if !auth {
		t.Errorf("Unauthorized with valid credentials")
	}
}

func TestMITMSimplifiedSRP(t *testing.T) {
	email := []byte("email@test.com")
	password := []byte("paSSw0rD")
	wordlist := [][]byte{
		[]byte("password"),
		[]byte("12345678"),
		password,
		email,
	}
	stream := Init(email, password)
	mitm := initMITMServer(wordlist)
	stream.S = mitm
	stream.Auth()
	if !bytes.Equal(password, mitm.Password) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", password, mitm.Password)
	}

	// wrong list
	stream = Init(email, password)
	mitm = initMITMServer(wordlist[:2])
	stream.S = mitm
	stream.Auth()
	if bytes.Equal(password, mitm.Password) {
		t.Errorf("Incorrect result. Expected %q, got %q\n", "", mitm.Password)
	}
}
