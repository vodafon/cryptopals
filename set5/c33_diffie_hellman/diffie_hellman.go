package c33_diffie_hellman

import (
	"crypto/rand"
	"crypto/sha256"
	"math"
	"math/big"
)

const (
	pStr = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
)

type DHSystem struct {
	P    *big.Int
	G    *big.Int
	priv *big.Int
	Pub  *big.Int
}

func NewDHSystem() *DHSystem {
	p := new(big.Int)
	p.SetString(pStr, 16)
	g := big.NewInt(2)
	dh := DHSystem{
		P: p,
		G: g,
	}
	dh.priv, dh.Pub = generateKeys(p, g)
	return &dh
}

func (obj *DHSystem) Change(p, g *big.Int) {
	obj.P = p
	obj.G = g
	obj.priv, obj.Pub = generateKeys(p, g)
}

func (obj *DHSystem) SessionKey(pubB *big.Int) *big.Int {
	s := new(big.Int)
	s.Exp(pubB, obj.priv, obj.P)
	return s
}

func (obj *DHSystem) SessionKeySHA256(pubB *big.Int) [32]byte {
	return sha256.Sum256(obj.SessionKey(pubB).Bytes())
}

func generateKeys(p, g *big.Int) (*big.Int, *big.Int) {
	a, err := rand.Int(rand.Reader, p)
	if err != nil {
		panic(err)
	}
	pk := new(big.Int)
	pk.Exp(g, a, p)
	return a, pk
}

func pow(a, b uint64) uint64 {
	return uint64(math.Pow(float64(a), float64(b)))
}
