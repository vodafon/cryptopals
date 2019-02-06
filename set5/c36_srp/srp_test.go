package c36_srp

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSRP(t *testing.T) {
	email := []byte("email@test.com")
	password := []byte("paSSw0rD")
	stream := Init(email, password)
	auth := stream.Auth()
	uHC := sha256.Sum256(append(stream.C.Pub.Bytes(), stream.C.sPub.Bytes()...))
	uHS := sha256.Sum256(append(stream.S.cPub.Bytes(), stream.S.Pub.Bytes()...))
	if uHC != uHS {
		t.Errorf("Incorrect 'u' calculations. Must be equal\n")
	}
	if !bytes.Equal(stream.C.key, stream.S.key) {
		t.Errorf("Incorrect 'key' calculations. Must be equal\n")
	}
	if !auth {
		t.Errorf("Unauthorized with valid credentials")
	}

	stream = Init(email, password)
	stream.C.password = []byte("wrongPass")
	auth = stream.Auth()
	if auth {
		t.Errorf("Authorized with invalid credentials")
	}
}
