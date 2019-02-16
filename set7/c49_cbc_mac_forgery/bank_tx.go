package c49_cbc_mac_forgery

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
)

type TX struct {
	To     string
	Amount uint64
}

func ParseTXs(list string) ([]TX, error) {
	txs := []TX{}
	for _, str := range strings.Split(list, ";") {
		idAm := strings.Split(str, ":")
		if len(idAm) != 2 {
			continue
		}
		amount, err := strconv.ParseUint(idAm[1], 10, 64)
		if err != nil {
			return nil, err
		}
		txs = append(txs, TX{idAm[0], amount})
	}
	return txs, nil
}

type BankTX struct {
	sync.Mutex
	accounts map[string]uint64
	cbcmac   CBCMAC
	attacker string
	iv       []byte
}

func NewBankTX(attacker string) *BankTX {
	accounts := make(map[string]uint64)
	accounts["client1"] = 20000000000
	accounts["client2"] = 200000
	accounts[attacker] = 200

	key := make([]byte, 16)
	rand.Read(key)
	iv := make([]byte, 16)
	cbc := NewCBCMACFixedIV(key, iv)
	return &BankTX{
		accounts: accounts,
		cbcmac:   cbc,
		attacker: attacker,
	}
}

func (obj *BankTX) Balance(id string) uint64 {
	return obj.accounts[id]
}

func (obj *BankTX) Send(txs []TX) error {
	query, mac := obj.Capture(txs)
	return obj.Transaction(query, mac)
}

func (obj *BankTX) Capture(txs []TX) ([]byte, []byte) {
	txList := ""
	for _, tx := range txs {
		txList += fmt.Sprintf("%s:%d;", tx.To, tx.Amount)
	}
	query := []byte(fmt.Sprintf("from=%s&tx_list=%s", obj.attacker, txList))
	_, mac := obj.cbcmac.Sign(query)
	return query, mac
}

// from=#{from_id}&tx_list=#{transactions}
// transactions - to:amount(;to:amount)*
func (obj *BankTX) Transaction(query, mac []byte) error {
	if !obj.cbcmac.Validation(query, []byte{}, mac) {
		return errors.New("Invalid signature")
	}
	vals, err := url.ParseQuery(string(query))
	if err != nil {
		return err
	}
	sender := vals.Get("from")
	txs, err := ParseTXs(vals.Get("tx_list"))
	if err != nil {
		return err
	}
	for _, tx := range txs {
		err = obj.doTransaction(sender, tx.To, tx.Amount)
		if err != nil {
			return err
		}
	}

	return nil
}

func (obj *BankTX) doTransaction(sender, receiver string, amount uint64) error {
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

func ExploitTX(att, vic string, amount uint64, bank *BankTX) error {
	// Assume the IDs have same byte sizes for simplicity
	// att = clientA
	// vic = client1
	if len(att) != 7 || len(vic) != 7 {
		return errors.New("IDs size != 7")
	}

	// P - is the padding = 0x01
	_, mac0 := bank.Capture([]TX{{vic, 1}}) // query = 'from=clientA&tx_list=client1:1;P'
	//
	// In next query B3^C2(mac0) = 'from=client1&tx_' and ciphertext (C3) for this block
	// is equal for B3('from=client1&tx_')^IV(000...) and MAC(B1,B2,B3...BN) == MAC(B3...BN)
	//
	// from=clientA&tx_list=client1:1;P + mac ^ 'from=client1&tx_' + 'list=clientA:10000;'
	tb1 := []byte(fmt.Sprintf("from=%s&tx_", vic))
	tb1x := c2_fixed_xor.SafeXORBytes(mac0, tb1)
	client := "\x01" + string(tb1x) + "list=" + att // 0x01from=client1&tx_list=clientA
	_, mac1 := bank.Capture([]TX{{vic, 1}, {client, amount}})

	q2 := []byte(fmt.Sprintf("from=%s&tx_list=%s:%d;", vic, att, amount))

	return bank.Transaction(q2, mac1)
}
