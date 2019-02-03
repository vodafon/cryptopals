package c34_mitm_diffie_hellman

import (
	"bytes"
	"testing"
)

func TestEchoStream(t *testing.T) {
	uA := NewUser("A")
	uB := NewUser("B")
	msg := []byte("secret text")
	EchoStream(uA, uB, msg)
	if !bytes.Equal(uB.lastReceivedMessage, msg) || !bytes.Equal(uA.lastReceivedMessage, uB.lastReceivedMessage) {
		t.Errorf("Incorrect EchoStream\n")
	}
}

func TestEchoMITMStream(t *testing.T) {
	uA := NewUser("A")
	uM := NewMITM("M")
	uB := NewUser("B")
	msg := []byte("secret text")
	EchoMITMStream(uA, uM, uB, msg)
	if !bytes.Equal(uM.decryptedMessage, msg) {
		t.Errorf("Incorrect EchoMITMStream\n")
	}
}
