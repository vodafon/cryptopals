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
	p     *big.Int
	g     *big.Int
	a     *big.Int
	b     *big.Int
	PubKA *big.Int
	PubKB *big.Int
}

func NewDHSystem() DHSystem {
	p := new(big.Int)
	p.SetString(pStr, 16)
	g := big.NewInt(2)
	dh := DHSystem{
		p: p,
		g: g,
	}
	dh.a, dh.PubKA = generateKeys(p, g)
	dh.b, dh.PubKB = generateKeys(p, g)
	return dh
}

func (obj DHSystem) SessionKey() *big.Int {
	s := new(big.Int)
	s.Exp(obj.PubKB, obj.a, obj.p)
	return s
}

func (obj DHSystem) SessionKeySHA256() [32]byte {
	return sha256.Sum256(obj.SessionKey().Bytes())
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
