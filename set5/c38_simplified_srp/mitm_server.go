package c38_simplified_srp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type MITMServer struct {
	Password []byte
	wl       [][]byte
	*Server
}

func (obj *MITMServer) computeK() {}

func (obj *MITMServer) validHMAC(hmac []byte) bool {
	obj.Password = obj.crackHMAC(hmac)
	return false
}

func (obj *MITMServer) crackHMAC(hmac []byte) []byte {
	for _, password := range obj.wl {
		// v = g ** x
		// S = (A * v ** u)**b % n = A * V % n (b=1; u=1)
		xH := sha256.Sum256(append(obj.salt, password...))
		x := new(big.Int).SetBytes(xH[:])
		v := new(big.Int).Exp(g, x, N)
		S := new(big.Int).Mul(obj.cPub, v)
		S.Mod(S, N)
		key := sha256.Sum256(S.Bytes())
		sHMAC := hmac256(obj.salt, key[:])
		if bytes.Equal(sHMAC, hmac) {
			return password
		}
	}
	return nil
}

func (obj *MITMServer) sendPub(c *Client) {
	obj.Pub = g
	obj.u = big.NewInt(1)
	c.receivePub(obj.salt, obj.Pub, obj.u)
}

func (obj *MITMServer) receivePub(email []byte, pk *big.Int) {
	obj.email = email
	obj.cPub = pk
}

func initMITMServer(words [][]byte) *MITMServer {
	salt := make([]byte, 10)
	rand.Read(salt)
	server := Server{
		salt: salt,
		priv: big.NewInt(1),
	}
	return &MITMServer{
		wl:     words,
		Server: &server,
	}
}
