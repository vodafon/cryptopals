package c44_dsa_repeated_nonce

import (
	"errors"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
	"github.com/vodafon/cryptopals/set6/c43_dsa_from_nonce"
)

type Text struct {
	Msg     []byte
	S, R, M *big.Int
}

func Exploit(dsa *c43_dsa_from_nonce.DSA, texts []Text) (*big.Int, error) {
	t1, t2, err := findPair(texts)
	if err != nil {
		return nil, err
	}
	sInv := new(big.Int).Sub(t1.S, t2.S)
	sInv = c39_rsa.InvMod(sInv, dsa.Q)
	k := new(big.Int).Sub(t1.M, t2.M)
	k.Mul(k, sInv).Mod(k, dsa.Q)
	x := c43_dsa_from_nonce.RecoverX(t1.M, t1.R, t1.S, dsa.Q, k)
	return x, nil
}

func findPair(texts []Text) (Text, Text, error) {
	mp := make(map[string]Text)
	for _, text := range texts {
		t, ok := mp[text.R.String()]
		if ok {
			return text, t, nil
		}
		mp[text.R.String()] = text
	}
	return Text{}, Text{}, errors.New("not found")
}
