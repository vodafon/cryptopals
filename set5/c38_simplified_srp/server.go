package c38_simplified_srp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type Server struct {
	email []byte
	salt  []byte
	key   []byte
	u     *big.Int
	v     *big.Int
	priv  *big.Int
	Pub   *big.Int
	cPub  *big.Int
}

func (obj *Server) computeK() {
	// S = (A * v**u) ** b % N
	s1 := new(big.Int).Exp(obj.v, obj.u, N)
	s2 := new(big.Int).Mul(obj.cPub, s1)
	s := new(big.Int).Exp(s2, obj.priv, N)
	key := sha256.Sum256(s.Bytes())
	obj.key = key[:]
}

func (obj *Server) sendPub(c *Client) {
	obj.Pub = new(big.Int).Exp(g, obj.priv, N)
	uB := make([]byte, 16)
	rand.Read(uB)
	obj.u = new(big.Int).SetBytes(uB)
	c.receivePub(obj.salt, obj.Pub, obj.u)
}

func (obj *Server) validHMAC(hmac []byte) bool {
	sHMAC := hmac256(obj.salt, obj.key)
	return bytes.Equal(sHMAC, hmac)
}

func (obj *Server) receivePub(email []byte, pk *big.Int) {
	obj.email = email
	obj.cPub = pk
}

func initServer(password []byte) Server {
	salt := make([]byte, 10)
	rand.Read(salt)
	xH := sha256.Sum256(append(salt, password...))
	x := new(big.Int).SetBytes(xH[:])
	v := new(big.Int).Exp(g, x, N)
	return Server{
		salt: salt,
		v:    v,
		priv: privKey(),
	}
}
