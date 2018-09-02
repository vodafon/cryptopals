package c2_fixed_xor

func SafeXORBytes(a, b []byte) []byte {
	n := len(a)
	maxLen := len(b)
	if len(b) < n {
		n = len(b)
		maxLen = len(a)
	}
	dst := make([]byte, maxLen)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}
