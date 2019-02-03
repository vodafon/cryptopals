package c35_mitm_diffie_hellman

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

func TestEchoMITMStreamGEqualOne(t *testing.T) {
	mitm(t, gEqualOne, 0)
}

func TestEchoMITMStreamGEqualP(t *testing.T) {
	mitm(t, gEqualP, 0)
}

func TestEchoMITMStreamGPMinusOne(t *testing.T) {
	mitm(t, gPMinusOne, 5)
}

func mitm(t *testing.T, gType, retry int) {
	uA := NewUser("A")
	uM := NewMITM("M")
	uM.gType = gType
	uB := NewUser("B")
	msg := []byte("secret text")
	EchoMITMStream(uA, uM, uB, msg)
	if !bytes.Equal(uM.decryptedMessage, msg) {
		if retry == 0 {
			t.Fatalf("Incorrect EchoMITMStream\n")
		} else {
			mitm(t, gType, retry-1)
		}
	}
	if !bytes.Equal(uB.lastReceivedMessage, msg) || !bytes.Equal(uA.lastReceivedMessage, uB.lastReceivedMessage) {
		if retry == 0 {
			t.Fatalf("Incorrect EchoStream\n")
		} else {
			mitm(t, gType, retry-1)
		}
	}
}
