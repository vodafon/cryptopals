package c28_sha1_key_mac

type SHA1System struct {
	key []byte
}

func NewSHA1System(key []byte) SHA1System {
	return SHA1System{
		key: key,
	}
}

func (obj SHA1System) MAC(message []byte) [Size]byte {
	return Sum(append(obj.key, message...))
}

func (obj SHA1System) Verify(mac [Size]byte, message []byte) bool {
	return mac == obj.MAC(message)
}

func (obj *SHA1) SetState(h0, h1, h2, h3, h4 uint32) {
	obj.h[0] = h0
	obj.h[1] = h1
	obj.h[2] = h2
	obj.h[3] = h3
	obj.h[4] = h4
}

func (obj *SHA1) SetLen(l uint64) {
	obj.len = l
}

// Source code from crypto/sha1

// The size of a SHA-1 checksum in bytes.
const Size = 20

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

// Sum returns the SHA-1 checksum of the data.
func Sum(data []byte) [Size]byte {
	d := &SHA1{}
	d.Reset()
	d.Write(data)
	return d.CheckSum()
}

// digest represents the partial evaluation of a checksum.
type SHA1 struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *SHA1) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

func (d *SHA1) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *SHA1) CheckSum() [Size]byte {
	l := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if l%64 < 56 {
		d.Write(tmp[0 : 56-l%64])
	} else {
		d.Write(tmp[0 : 64+56-l%64])
	}

	// Length in bits.
	l <<= 3
	putUint64(tmp[:], l)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	putUint32(digest[0:], d.h[0])
	putUint32(digest[4:], d.h[1])
	putUint32(digest[8:], d.h[2])
	putUint32(digest[12:], d.h[3])
	putUint32(digest[16:], d.h[4])

	return digest
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

func putUint32(x []byte, s uint32) {
	_ = x[3]
	x[0] = byte(s >> 24)
	x[1] = byte(s >> 16)
	x[2] = byte(s >> 8)
	x[3] = byte(s)
}

// blockGeneric is a portable, pure Go version of the SHA-1 block step.
// It's used by sha1block_generic.go and tests.
func block(dig *SHA1, p []byte) {
	var w [16]uint32

	h0, h1, h2, h3, h4 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4]
	for len(p) >= chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		// Each of the four 20-iteration rounds
		// differs only in the computation of f and
		// the choice of K (_K0, _K1, etc).
		i := 0
		for ; i < 16; i++ {
			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 20; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)

			f := b&c | (^b)&d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K0
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 40; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K1
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 60; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := ((b | c) & d) | (b & c)

			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K2
			a, b, c, d, e = t, a, b30, c, d
		}
		for ; i < 80; i++ {
			tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
			w[i&0xf] = tmp<<1 | tmp>>(32-1)
			f := b ^ c ^ d
			a5 := a<<5 | a>>(32-5)
			b30 := b<<30 | b>>(32-30)
			t := a5 + f + e + w[i&0xf] + _K3
			a, b, c, d, e = t, a, b30, c, d
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4] = h0, h1, h2, h3, h4
}
