package c36_srp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var (
	// openssl dhparam -text 1024
	N, _ = new(big.Int).SetString("a560171ebf031fc1234c7680d52616501d56375645150c6816ab7a27c257442a2d21bb9cc566077b55626a405cb52ffaa32cf52bbdaa227bd7f275651d29686d9518ff291f3686e4a7222abb2774d2b23a5be3130fca506ade3cecac23fabf2a5edad7b63e0e27885c75eb090b06e0fa7e6d1f5cb7ede62d2d6b396dafb7bcd3", 16)
	g    = big.NewInt(2)
	k    = big.NewInt(3)
)

type Stream struct {
	C *Client
	S *Server
}

func Init(email, password []byte) Stream {
	server := initServer(password)
	client := initClient(email, password)
	return Stream{
		C: &client,
		S: &server,
	}
}

func (obj Stream) Auth() bool {
	obj.C.sendPub(obj.S)
	obj.S.sendPub(obj.C)
	obj.computeU()
	obj.C.computeK()
	obj.S.computeK()
	cHMAC := hmac256(obj.C.salt, obj.C.key)
	sHMAC := hmac256(obj.S.salt, obj.S.key)
	return bytes.Equal(cHMAC, sHMAC)
}

func hmac256(salt, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(salt)
	return h.Sum(nil)
}

func (obj Stream) computeU() {
	uHC := sha256.Sum256(append(obj.C.Pub.Bytes(), obj.C.sPub.Bytes()...))
	u := new(big.Int).SetBytes(uHC[:])
	obj.C.u = u
	obj.S.u = u
}

func privKey() *big.Int {
	a, err := rand.Int(rand.Reader, N)
	if err != nil {
		panic(err)
	}
	return a
}
