package c17_cbc_padding_oracle

import (
	"bufio"
	"bytes"
	"os"
	"testing"
)

func TestRandomCiphertext(t *testing.T) {
	cbc := cbcSystem()
	c1, iv1, err := cbc.RandomCiphertext()
	if err != nil {
		t.Errorf("Error: %s\n", err)
	}
	c2, iv2, _ := cbc.RandomCiphertext()
	c3, iv3, _ := cbc.RandomCiphertext()
	if sameBytes(c1, c2, c3) {
		t.Errorf("Ciphertext randomization broken: %q %q %q\n", c1, c2, c3)
	}
	if sameBytes(iv1, iv2, iv3) {
		t.Errorf("IV randomization broken: %q %q %q\n", iv1, iv2, iv3)
	}
}

func TestIsPaddingValid(t *testing.T) {
	cbc := cbcSystem()
	c1, iv1, _ := cbc.RandomCiphertext()
	valid := cbc.IsPaddingValid(c1, iv1)
	if !valid {
		t.Errorf("Incorrect result. Expected: true, got: false\n")
	}
	block := append(bytes.Repeat([]byte{0}, 15), byte(1))
	c1 = append(c1, block...)
	valid = cbc.IsPaddingValid(c1, iv1)
	if valid {
		t.Errorf("Incorrect result. Expected: false, got: true\n")
	}
}

func TestExploit(t *testing.T) {
	cbc := cbcSystem()
	ciphertext, iv, _ := cbc.RandomCiphertext()
	plaintext, err := cbc.Exploit(ciphertext, iv)
	if err != nil {
		t.Errorf("Error: %s\n", err)
	}
	if !cbc.isInList(plaintext) {
		t.Errorf("Incorect result. %q (%v %v) not found\n", plaintext, ciphertext, iv)
	}
}

func cbcSystem() CBCSystem {
	list := loadStrings("./testdata/strings.txt")
	cbc, err := NewCBCSystem(list)
	if err != nil {
		panic(err)
	}
	return cbc
}

func loadStrings(filepath string) [][]byte {
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	list := [][]byte{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		list = append(list, scanner.Bytes())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return list
}

func sameBytes(args ...[]byte) bool {
	if len(args) < 1 {
		return true
	}
	for i := 1; i < len(args); i++ {
		if !bytes.Equal(args[0], args[i]) {
			return false
		}
	}
	return true
}
