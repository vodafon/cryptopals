package c36_srp

import (
	"crypto/sha256"
	"math/big"
)

type Client struct {
	Email    []byte
	Password []byte
	salt     []byte
	Key      []byte
	u        *big.Int
	priv     *big.Int
	Pub      *big.Int
	sPub     *big.Int
}

func (obj *Client) computeK() {
	if len(obj.Key) != 0 {
		return
	}
	xH := sha256.Sum256(append(obj.salt, obj.Password...))
	x := new(big.Int).SetBytes(xH[:])
	// S = (B - k*g**x)**(a + u*x) % N
	s1 := new(big.Int).Exp(g, x, N)
	s2 := new(big.Int).Sub(obj.sPub, new(big.Int).Mul(k, s1))
	s3 := new(big.Int).Add(obj.priv, new(big.Int).Mul(obj.u, x))
	s := new(big.Int).Exp(s2, s3, N)
	key := sha256.Sum256(s.Bytes())
	obj.Key = key[:]
}

func (obj *Client) sendPub(s *Server) {
	if obj.Pub == nil {
		obj.Pub = new(big.Int).Exp(g, obj.priv, N)
	}
	s.receivePub(obj.Email, obj.Pub)
}

func (obj *Client) receivePub(salt []byte, pk *big.Int) {
	obj.salt = salt
	obj.sPub = pk
}

func initClient(email, password []byte) Client {
	return Client{
		Email:    email,
		Password: password,
		priv:     privKey(),
	}
}
