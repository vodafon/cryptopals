package c34_mitm_diffie_hellman

import (
	"crypto/sha1"
	"math/big"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
)

type MITM struct {
	name             string
	P                *big.Int
	receiverA        Point
	receiverB        Point
	receiverN        int
	side             int
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

func (obj *MITM) ReceivePGK(p, g, pK *big.Int) {
	obj.P = p
	obj.receiverB.ReceivePGK(p, g, p)
}

func (obj *MITM) ReceiveK(pK *big.Int) {
	obj.receiverA.ReceiveK(obj.P)
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
	key := sha1.Sum(big.NewInt(0).Bytes())
	iv := ciphertext[len(ciphertext)-16:]
	enc := ciphertext[:len(ciphertext)-16]
	msg := c10_implement_cbc_mode.Decrypt(enc, key[:16], iv)
	obj.decryptedMessage = msg
}

func (obj *MITM) SendPGK()               {}
func (obj *MITM) SendK()                 {}
func (obj *MITM) SendMessage(msg []byte) {}
func (obj *MITM) ReturnMessage()         {}
