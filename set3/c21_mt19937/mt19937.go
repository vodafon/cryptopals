package c21_mt19937

// w: word size (in number of bits)
// n: degree of recurrence
// m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
// r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
// a: coefficients of the rational normal form twist matrix
// b, c: TGFSR(R) tempering bitmasks
// s, t: TGFSR(R) tempering bit shifts
// u, d, l: additional Mersenne Twister tempering bit shifts/masks

const (
	wMT       = 32
	nMT       = 624
	mMT       = 397
	rMT       = 31
	aMT       = 0x9908b0df
	uMT       = 11
	dMT       = 0xffffffff
	sMT       = 7
	bMT       = 0x9d2c5680
	tMT       = 15
	cMT       = 0xefc60000
	lMT       = 18
	fMT       = 1812433253
	lowerMask = (1 << rMT) - 1
	upperMask = 0x80000000
)

type MT19937 struct {
	index uint32
	mt    [nMT]uint32
}

func NewMT19937(seed uint32) *MT19937 {
	obj := MT19937{
		index: nMT,
	}
	obj.mt[0] = seed
	for i := 1; i < nMT; i++ {
		obj.mt[i] = fMT*(obj.mt[i-1]^(obj.mt[i-1]>>(wMT-2))) + uint32(i)
	}
	return &obj
}

func (obj *MT19937) ExtractNumber() uint32 {
	if obj.index >= nMT {
		obj.twist()
	}
	y := obj.mt[obj.index]
	y ^= (y >> uMT) & dMT
	y ^= (y << sMT) & bMT
	y ^= (y << tMT) & cMT
	y ^= y >> lMT
	obj.index += 1
	return y
}

func (obj *MT19937) twist() {
	for i := 0; i < len(obj.mt)-1; i++ {
		x := (obj.mt[i] & upperMask) + (obj.mt[i+1%nMT] & lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA ^= aMT
		}
		obj.mt[i] = obj.mt[(i+mMT)%nMT] ^ xA
	}
	obj.index = 0
}
