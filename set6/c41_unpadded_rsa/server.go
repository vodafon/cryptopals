package c41_unpadded_rsa

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

var AccessError = errors.New("Access denied")

type Server struct {
	rsa *c39_rsa.RSA
	db  map[[32]byte]time.Time
}

func NewServer() *Server {
	rsa, err := c39_rsa.Generate(1024)
	if err != nil {
		panic(err)
	}
	return &Server{
		rsa: rsa,
		db:  make(map[[32]byte]time.Time),
	}
}

func (obj *Server) PublicKey() c39_rsa.Key {
	return obj.rsa.Pub
}

func (obj *Server) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext := c39_rsa.Encrypt(plaintext, obj.rsa.Pub)
	sha := sha256.Sum256(ciphertext)
	if !obj.valid(sha) {
		return nil, AccessError
	}
	return ciphertext, nil
}

func (obj *Server) Decrypt(ciphertext []byte) ([]byte, error) {
	sha := sha256.Sum256(ciphertext)
	if !obj.valid(sha) {
		return nil, AccessError
	}
	plaintext := obj.rsa.Decrypt(ciphertext)
	return plaintext, nil
}

func (obj *Server) valid(sha [32]byte) bool {
	t, ok := obj.db[sha]
	valid := true
	if ok {
		if t.After(time.Now()) {
			valid = false
		}
	}
	obj.db[sha] = time.Now().Add(1 * time.Hour)
	return valid
}
