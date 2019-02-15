package c47_c48_bb98

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/vodafon/cryptopals/set5/c39_rsa"
)

var (
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big3 = big.NewInt(3)
	B    = new(big.Int)
	B2   = new(big.Int)
	B3   = new(big.Int)
	pubK = c39_rsa.PublicKey{}
)

type BB98 struct {
	rsa *c39_rsa.RSA
}

func (obj BB98) Encrypt(msg []byte) ([]byte, error) {
	pk := obj.rsa.RSAPublicKey()
	return rsa.EncryptPKCS1v15(rand.Reader, &pk, msg)
}

func (obj BB98) Decrypt(ciphertext []byte) []byte {
	k := obj.rsa.PublicKey().Size()
	m := obj.rsa.Decrypt(ciphertext)
	return leftPad(m, k)
}

func (obj BB98) IsValidPKCS(ciphertext []byte) bool {
	m := obj.Decrypt(ciphertext)
	if len(m) < obj.rsa.PublicKey().Size() {
		return false
	}
	if m[0] == 0x00 && m[1] == 0x02 {
		return true
	}
	return false
}

func (obj BB98) padOracle(c, s *big.Int) bool {
	pk := obj.rsa.PublicKey()
	si := new(big.Int).Exp(s, pk.E, pk.N)
	ci := new(big.Int).Mul(c, si)
	ci.Mod(ci, pk.N)
	return obj.IsValidPKCS(ci.Bytes())
}

type Range struct {
	r, a, b, s *big.Int
}

func (obj Range) String() string {
	return fmt.Sprintf("r: %d\ns: %d\na: %d\nb: %d\nd: %d\n", obj.r, obj.s, obj.a, obj.b, new(big.Int).Sub(obj.b, obj.a))
}

// Base paper: http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
// Additional links:
//	https://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html#eq2
// 	https://www.youtube.com/watch?v=iA6OevUmeHk
func Exploit(c []byte, bb BB98) []byte {
	c0 := new(big.Int).SetBytes(c)
	pubK = bb.rsa.PublicKey()
	k := pubK.Size()
	B = big.NewInt(2 << 7)
	B.Exp(B, big.NewInt(int64(k-2)), nil)
	B2 = new(big.Int).Mul(B, big2)
	B3 = new(big.Int).Mul(B, big3)

	a := new(big.Int).Set(B2)
	b := new(big.Int).Set(B3)
	b.Sub(b, big1)

	ranges := []Range{}
	ranges = append(ranges, Range{big1, a, b, big1})
	s1 := searchS1(c0, bb)

	ranges = searchRanges(s1, ranges[len(ranges)-1], bb)

	sI := new(big.Int).Set(s1)

	for len(ranges) != 1 {
		tmpRanges := []Range{}
		sI = searchSI(c0, sI, bb)
		for _, rangeI := range ranges {
			rangesLocal := searchRanges(sI, rangeI, bb)
			tmpRanges = append(tmpRanges, rangesLocal...)
		}
		ranges = tmpRanges
	}

	return oneIntervalSearch(c0, sI, ranges, bb)
}

func oneIntervalSearch(c0, s0 *big.Int, ranges []Range, bb BB98) []byte {
	sI := new(big.Int).Set(s0)
	for ranges[0].a.Cmp(ranges[0].b) != 0 {
		if len(ranges) != 1 {
			panic("Invalid ranges size")
		}
		sI = binarySearch(c0, sI, ranges[0], bb)
		ranges = searchRanges(sI, ranges[0], bb)
	}
	k := pubK.Size()
	return leftPad(ranges[0].a.Bytes(), k)
}

func binarySearch(c0, s0 *big.Int, rangeI Range, bb BB98) *big.Int {
	r := new(big.Int).Mul(rangeI.b, s0)
	r.Sub(r, B2).Mul(r, big2)
	r = bigCeil(r, pubK.N)

	for {
		si := new(big.Int).Mul(r, pubK.N)
		si.Add(si, B2)
		si = bigCeil(si, rangeI.b)
		maxS := new(big.Int).Mul(r, pubK.N)
		maxS.Add(maxS, B3).Sub(maxS, big1)
		maxS = bigRound(maxS, rangeI.a)

		for si.Cmp(maxS) < 1 {
			if bb.padOracle(c0, si) {
				return si
			}
			si.Add(si, big1)
		}
		r.Add(r, big1)
	}
	return nil
}

func searchRanges(s0 *big.Int, range0 Range, bbb BB98) []Range {
	a, b := range0.a, range0.b
	ranges := []Range{}

	r := new(big.Int).Mul(a, s0)
	r.Sub(r, B3).Add(r, big1)
	r = bigCeil(r, pubK.N)
	maxR := new(big.Int).Mul(b, s0)
	maxR.Sub(maxR, B2).Div(maxR, pubK.N)
	for r.Cmp(maxR) < 1 {
		rI := new(big.Int).Set(r)
		aa := new(big.Int).Mul(rI, pubK.N)
		aa.Add(aa, B2)
		aa = bigCeil(aa, s0)
		if aa.Cmp(a) < 0 {
			aa.Set(a)
		}

		bb := new(big.Int).Mul(rI, pubK.N)
		bb.Add(bb, B3).Sub(bb, big1).Div(bb, s0)
		if bb.Cmp(b) > 0 {
			bb.Set(b)
		}
		rangeI := Range{
			r: rI,
			a: aa,
			b: bb,
			s: s0,
		}
		if bb.Cmp(aa) >= 0 {
			ranges = append(ranges, rangeI)
		}
		r.Add(r, big1)
	}
	return ranges
}

func searchSI(c0, s0 *big.Int, bb BB98) *big.Int {
	si := new(big.Int).Add(s0, big1)
	for {
		if bb.padOracle(c0, si) {
			return si
		}
		si.Add(si, big1)
	}
	return nil
}

func searchS1(c0 *big.Int, bb BB98) *big.Int {
	si := bigCeil(pubK.N, B3)
	for {
		if bb.padOracle(c0, si) {
			return si
		}
		si.Add(si, big1)
	}
	return nil
}

func bigCeil(a, b *big.Int) *big.Int {
	ai, bi := new(big.Int).Set(a), new(big.Int).Set(b)
	m := new(big.Int)
	ai.DivMod(ai, bi, m)
	if m.Sign() != 0 {
		ai.Add(ai, big1)
	}
	return ai
}

func bigRound(a, b *big.Int) *big.Int {
	ai, bi := new(big.Int).Set(a), new(big.Int).Set(b)
	m := new(big.Int)
	ai.DivMod(ai, bi, m)
	m.Mul(m, big2)
	if m.Cmp(bi) >= 0 {
		ai.Add(ai, big1)
	}
	return ai
}

func NewBB98(bs int) BB98 {
	rsa, err := c39_rsa.Generate(bs)
	if err != nil {
		panic(err)
	}
	return BB98{rsa}
}

func leftPad(src []byte, k int) []byte {
	if len(src) >= k {
		return src
	}
	dst := make([]byte, k)
	copy(dst[k-len(src):], src)
	return dst
}
