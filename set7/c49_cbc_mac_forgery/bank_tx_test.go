package c49_cbc_mac_forgery

import (
	"testing"
)

func TestSendTX(t *testing.T) {
	attacker := "clientA"
	bank := NewBankTX(attacker)
	c1b := bank.Balance("client1")
	if c1b != 20000000000 {
		t.Errorf("Incorrect result. Expected %d, got %d\n", 20000000000, c1b)
	}
	a1b := bank.Balance("clientA")
	if a1b != 200 {
		t.Errorf("Incorrect result. Expected %d, got %d\n", 200, a1b)
	}

	err := bank.Send(toTxs("client1", 300))
	if err == nil {
		t.Errorf("sent more then balance")
	}
	err = bank.Send(toTxs("invalid", 100))
	if err == nil {
		t.Errorf("sent to unknown client")
	}

	err = bank.Send(toTxs("client1", 100))
	if err != nil {
		t.Fatalf("Send error: %s\n", err)
	}

	c1b = bank.Balance("client1")
	if c1b != 20000000100 {
		t.Errorf("Incorrect result. Expected %d, got %d\n", 20000000100, c1b)
	}
	a1b = bank.Balance(attacker)
	if a1b != 100 {
		t.Errorf("Incorrect result. Expected %d, got %d\n", 100, a1b)
	}
}

func TestCaptureTX(t *testing.T) {
	attacker := "clientA"
	bank := NewBankTX(attacker)
	txs := []TX{{"client1", 1}, {"client2", 100}}
	query, mac := bank.Capture(txs)
	err := bank.Transaction(query, mac)
	if err != nil {
		t.Fatalf("Transaction error: %s\n", err)
	}
}

func TestExploitTX(t *testing.T) {
	attacker := "clientA"
	bank := NewBankTX(attacker)
	err := ExploitTX(attacker, "client1", 1000000, bank)
	if err != nil {
		t.Fatalf("Exploit error: %s\n", err)
	}

	a1b := bank.Balance(attacker)
	if a1b != 1000200 {
		t.Errorf("Incorrect result. Expected %d, got %d\n", 1000200, a1b)
	}
}

func toTxs(to string, amount uint64) []TX {
	return []TX{{to, amount}}
}
