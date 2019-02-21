package c49_cbc_mac_forgery

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
)

type BankIV struct {
	sync.Mutex
	accounts map[string]uint64
	cbcmac   CBCMAC
	attacker string
}

func NewBankIV(attacker string) *BankIV {
	accounts := make(map[string]uint64)
	accounts["client1"] = 20000000000
	accounts["client2"] = 200000
	accounts[attacker] = 200

	key := make([]byte, 16)
	rand.Read(key)
	cbc := NewCBCMAC(key)
	return &BankIV{
		accounts: accounts,
		cbcmac:   cbc,
		attacker: attacker,
	}
}

func (obj *BankIV) Balance(id string) uint64 {
	return obj.accounts[id]
}

func (obj *BankIV) Send(to string, amount uint64) error {
	query := []byte(fmt.Sprintf("from=%s&to=%s&amount=%d", obj.attacker, to, amount))
	iv, mac := obj.cbcmac.Sign(query)
	return obj.Transaction(query, iv, mac)
}

func (obj *BankIV) Capture(to string, amount uint64) ([]byte, []byte, []byte) {
	query := []byte(fmt.Sprintf("from=%s&to=%s&amount=%d", obj.attacker, to, amount))
	iv, mac := obj.cbcmac.Sign(query)
	return query, iv, mac
}

// from=#{from_id}&to=#{to_id}&amount=#{amount}
func (obj *BankIV) Transaction(query, iv, mac []byte) error {
	if !obj.cbcmac.Validation(query, iv, mac) {
		return errors.New("Invalid signature")
	}
	vals, err := url.ParseQuery(string(query))
	if err != nil {
		return err
	}
	sender := vals.Get("from")
	receiver := vals.Get("to")
	amount, err := strconv.ParseUint(vals.Get("amount"), 10, 64)
	if err != nil {
		return err
	}

	if obj.accounts[sender] < amount {
		return errors.New("amount to big")
	}
	if _, ok := obj.accounts[receiver]; !ok {
		return errors.New("receiver not found")
	}
	obj.Lock()
	defer obj.Unlock()
	obj.accounts[sender] -= amount
	obj.accounts[receiver] += amount
	return nil
}

func ExploitIV(att, vic string, amount uint64, bank *BankIV) error {
	if len(att) != 7 {
		return errors.New("IDs size != 7")
	}

	query, iv, mac := bank.Capture(vic, amount)
	block1 := query[:16] // from=clientA&to=
	target := c2_fixed_xor.SafeXORBytes(block1, iv)
	blockA := []byte(fmt.Sprintf("to=%s&from=", att))
	ivA := c2_fixed_xor.SafeXORBytes(blockA, target)
	copy(query[:16], blockA)

	return bank.Transaction(query, ivA, mac)
}
