package c34_mitm_diffie_hellman

import (
	"crypto/rand"
	"crypto/sha1"
	"math/big"

	"github.com/vodafon/cryptopals/set2/c10_implement_cbc_mode"
	"github.com/vodafon/cryptopals/set5/c33_diffie_hellman"
)

type User struct {
	name                string
	dh                  *c33_diffie_hellman.DHSystem
	sessionKey          *big.Int
	receiver            Point
	lastSentMessage     []byte
	lastReceivedMessage []byte
}

func NewUser(name string) *User {
	return &User{
		name: name,
		dh:   c33_diffie_hellman.NewDHSystem(),
	}
}

func (obj *User) SetReceiver(p Point) {
	obj.receiver = p
}

func (obj *User) SendPGK() {
	obj.receiver.ReceivePGK(obj.dh.P, obj.dh.G, obj.dh.Pub)
}

func (obj *User) ReceivePGK(p, g, pK *big.Int) {
	obj.dh.Change(p, g)
	obj.sessionKey = obj.dh.SessionKey(pK)
}

func (obj *User) SendK() {
	obj.receiver.ReceiveK(obj.dh.Pub)
}

func (obj *User) ReceiveK(pK *big.Int) {
	obj.sessionKey = obj.dh.SessionKey(pK)
}

func (obj *User) SendMessage(msg []byte) {
	key := sha1.Sum(obj.sessionKey.Bytes())
	iv := make([]byte, 16)
	rand.Read(iv)
	enc := c10_implement_cbc_mode.Encrypt(msg, key[:16], iv)
	obj.lastSentMessage = msg
	obj.receiver.ReceiveMessage(append(enc, iv...))
}

func (obj *User) ReceiveMessage(ciphertext []byte) {
	key := sha1.Sum(obj.sessionKey.Bytes())
	iv := ciphertext[len(ciphertext)-16:]
	enc := ciphertext[:len(ciphertext)-16]
	msg := c10_implement_cbc_mode.Decrypt(enc, key[:16], iv)
	obj.lastReceivedMessage = msg
}

func (obj *User) ReturnMessage() {
	obj.SendMessage(obj.lastReceivedMessage)
}
