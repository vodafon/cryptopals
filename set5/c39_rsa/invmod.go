package c39_rsa

import "math/big"

func InvMod(a, b *big.Int) *big.Int {
	g, x := EGCD(a, b)
	if g.Cmp(bi(1)) != 0 {
		return nil
	}
	return x.Mod(x, b)
}

func DivMod(a, b *big.Int) (*big.Int, *big.Int) {
	q := new(big.Int).Div(a, b)
	return q, a.Sub(a, new(big.Int).Mul(q, b))
}

func EGCD(a, b *big.Int) (*big.Int, *big.Int) {
	lRem, rem := bn().Abs(a), bn().Abs(b)
	x, lX, y, lY := bi(0), bi(1), bi(1), bi(0)
	quotient := bn()

	for rem.Cmp(bi(0)) != 0 {
		tmpRem := rem
		quotient, rem = DivMod(lRem, rem)
		lRem = tmpRem
		tmpX, tmpY := x, y
		x = bn().Sub(lX, bn().Mul(quotient, x))
		lX = tmpX

		y = bn().Sub(lY, bn().Mul(quotient, y))
		lY = tmpY
	}
	if a.Sign() < 0 {
		lX = bn().Neg(lX)
	}

	return lRem, lX
}

func bi(n int64) *big.Int {
	return big.NewInt(n)
}

func bn() *big.Int {
	return new(big.Int)
}
