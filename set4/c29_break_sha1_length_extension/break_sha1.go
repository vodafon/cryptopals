package c29_break_sha1_length_extension

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/vodafon/cryptopals/set4/c28_sha1_key_mac"
)

func MDPad(l uint64) []byte {
	var buf bytes.Buffer
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if l%64 < 56 {
		buf.Write(tmp[0 : 56-l%64])
	} else {
		buf.Write(tmp[0 : 64+56-l%64])
	}

	// Length in bits.
	l <<= 3
	putUint64(tmp[:], l)
	buf.Write(tmp[0:8])
	return buf.Bytes()
}

func Exploit(sha1System c28_sha1_key_mac.SHA1System, msg, addMsg []byte, mac [20]byte) ([20]byte, []byte, error) {
	h0 := binary.BigEndian.Uint32(mac[:4])
	h1 := binary.BigEndian.Uint32(mac[4:8])
	h2 := binary.BigEndian.Uint32(mac[8:12])
	h3 := binary.BigEndian.Uint32(mac[12:16])
	h4 := binary.BigEndian.Uint32(mac[16:])
	sha1 := &c28_sha1_key_mac.SHA1{}

	for i := 0; i < 64; i++ {
		mdp := MDPad(uint64(i + len(msg)))
		l := len(msg) + i + len(mdp)
		sha1.SetState(h0, h1, h2, h3, h4)
		sha1.SetLen(uint64(l))
		sha1.Write(addMsg)
		mac2 := sha1.CheckSum()
		inp := append(msg, mdp...)
		inp = append(inp, addMsg...)
		if sha1System.Verify(mac2, inp) {
			return mac2, inp, nil
		}
	}
	return [20]byte{}, nil, errors.New("Not Found")
}

func putUint64(x []byte, s uint64) {
	_ = x[7]
	x[0] = byte(s >> 56)
	x[1] = byte(s >> 48)
	x[2] = byte(s >> 40)
	x[3] = byte(s >> 32)
	x[4] = byte(s >> 24)
	x[5] = byte(s >> 16)
	x[6] = byte(s >> 8)
	x[7] = byte(s)
}
