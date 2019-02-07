package c38_simplified_srp

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
	xH := sha256.Sum256(append(obj.salt, obj.Password...))
	x := new(big.Int).SetBytes(xH[:])
	// S = B**(a + ux) % n
	s := new(big.Int).Mul(obj.u, x)
	s.Add(obj.priv, s)
	s.Exp(obj.sPub, s, N)
	key := sha256.Sum256(s.Bytes())
	obj.Key = key[:]
}

func (obj *Client) sendPub(s auther) {
	if obj.Pub == nil {
		obj.Pub = new(big.Int).Exp(g, obj.priv, N)
	}
	s.receivePub(obj.Email, obj.Pub)
}

func (obj *Client) receivePub(salt []byte, pk, u *big.Int) {
	obj.salt = salt
	obj.sPub = pk
	obj.u = u
}

func initClient(email, password []byte) Client {
	return Client{
		Email:    email,
		Password: password,
		priv:     privKey(),
	}
}
