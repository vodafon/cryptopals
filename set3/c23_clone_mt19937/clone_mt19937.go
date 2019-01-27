package clone_mt19937

const (
	uMT = 11
	dMT = 0xffffffff
	sMT = 7
	bMT = 0x9d2c5680
	tMT = 15
	cMT = 0xefc60000
	lMT = 18
)

func Untemper(number uint32) uint32 {
	y := number
	y ^= y >> lMT
	y ^= y << tMT & cMT
	for i := 0; i < sMT; i++ {
		y ^= y << sMT & bMT
	}
	y ^= y >> uMT
	y ^= y >> (uMT * 2)
	return y
}
