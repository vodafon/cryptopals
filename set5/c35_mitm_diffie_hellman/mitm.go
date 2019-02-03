package c35_mitm_diffie_hellman

import (
	"crypto/sha1"
	"math/big"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

const (
	gOrigin = iota
	gEqualOne
	gEqualP
	gPMinusOne
)

type MITM struct {
	name             string
	P                *big.Int
	G                *big.Int
	receiverA        Point
	receiverB        Point
	receiverN        int
	side             int
	gType            int
	decryptedMessage []byte
}

func NewMITM(name string) *MITM {
	return &MITM{
		name: name,
	}
}

func (obj *MITM) SetReceiver(p Point) {
	if obj.receiverN == 0 {
		obj.receiverA = p
		obj.receiverN = 1
		return
	}
	obj.receiverB = p
	obj.receiverN = 0
}

func (obj *MITM) ReceivePG(p, g *big.Int) {
	obj.P = p
	g1 := new(big.Int)
	switch obj.gType {
	case gOrigin:
		g1 = g
	case gEqualOne:
		g1 = big.NewInt(1)
	case gEqualP:
		g1 = p
	case gPMinusOne:
		g1.Add(p, big.NewInt(-1))
	}
	obj.G = g1
	obj.receiverB.ReceivePG(p, g1)
}

func (obj *MITM) ReceiveACK() {
	obj.receiverA.ReceiveACK()
}

func (obj *MITM) SendACK() {}

func (obj *MITM) ReceiveK(pK *big.Int) {
	if obj.side == 0 {
		obj.receiverB.ReceiveK(obj.G)
		obj.side = 1
		return
	}
	obj.receiverA.ReceiveK(pK)
	obj.side = 0
}

func (obj *MITM) ReceiveMessage(ciphertext []byte) {
	obj.decrypt(ciphertext)
	if obj.side == 0 {
		obj.receiverB.ReceiveMessage(ciphertext)
		obj.side = 1
		return
	}
	obj.receiverA.ReceiveMessage(ciphertext)
	obj.side = 0
}

func (obj *MITM) decrypt(ciphertext []byte) {
	if len(obj.decryptedMessage) != 0 {
		return
	}

	iv := ciphertext[len(ciphertext)-16:]
	enc := ciphertext[:len(ciphertext)-16]
	key := [20]byte{}
	switch obj.gType {
	case gEqualOne:
		key = sha1.Sum(big.NewInt(1).Bytes())
	case gEqualP:
		key = sha1.Sum(big.NewInt(0).Bytes())
	case gPMinusOne:
		key = sha1.Sum(big.NewInt(0).Add(obj.P, big.NewInt(-1)).Bytes())
		if len(c10_implement_cbc_mode.Decrypt(enc, key[:16], iv)) == 0 {
			key = sha1.Sum(big.NewInt(1).Bytes())
		}
	}
	msg := c10_implement_cbc_mode.Decrypt(enc, key[:16], iv)
	obj.decryptedMessage = msg
}

func (obj *MITM) SendPG()                {}
func (obj *MITM) SendK()                 {}
func (obj *MITM) SendMessage(msg []byte) {}
func (obj *MITM) ReturnMessage()         {}
