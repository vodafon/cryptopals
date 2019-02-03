package c34_mitm_diffie_hellman

import (
	"math/big"
)

type Point interface {
	SetReceiver(p Point)
	SendPGK()
	ReceivePGK(p, g, pKA *big.Int)
	SendK()
	ReceiveK(pKB *big.Int)
	SendMessage([]byte)
	ReceiveMessage([]byte)
	ReturnMessage()
}

func EchoStream(uA, uB Point, msg []byte) {
	uA.SetReceiver(uB)
	uB.SetReceiver(uA)
	uA.SendPGK()
	uB.SendK()
	uA.SendMessage(msg)
	uB.ReturnMessage()
}

func EchoMITMStream(uA, uM, uB Point, msg []byte) {
	uA.SetReceiver(uM)
	uM.SetReceiver(uA)
	uM.SetReceiver(uB)
	uB.SetReceiver(uM)
	uA.SendPGK()
	uB.SendK()
	uA.SendMessage(msg)
	uB.ReturnMessage()
}
