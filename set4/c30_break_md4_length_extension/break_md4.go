package c30_break_md4_length_extension

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func MDPad(l uint64) []byte {
	var buf bytes.Buffer
	var tmp [64]byte
	tmp[0] = 0x80
	if l%64 < 56 {
		buf.Write(tmp[0 : 56-l%64])
	} else {
		buf.Write(tmp[0 : 64+56-l%64])
	}

	// Length in bits.
	l <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(l >> (8 * i))
	}
	buf.Write(tmp[0:8])
	return buf.Bytes()
}

func Exploit(md4System MD4System, msg, addMsg, mac []byte) ([]byte, []byte, error) {
	h0 := binary.LittleEndian.Uint32(mac[:4])
	h1 := binary.LittleEndian.Uint32(mac[4:8])
	h2 := binary.LittleEndian.Uint32(mac[8:12])
	h3 := binary.LittleEndian.Uint32(mac[12:])
	md4 := &MD4{}

	for i := 0; i < 64; i++ {
		mdp := MDPad(uint64(i + len(msg)))
		l := len(msg) + i + len(mdp)
		md4.Reset()
		md4.SetState(h0, h1, h2, h3)
		md4.SetLen(uint64(l))
		md4.Write(addMsg)
		in := []byte{}
		mac2 := md4.Sum(in)
		inp := append(msg, mdp...)
		inp = append(inp, addMsg...)
		if md4System.Verify(mac2, inp) {
			return mac2, inp, nil
		}
	}
	return nil, nil, errors.New("Not Found")
}
