package c8_detect_aes_ecb

func IsAesEcb(line []byte) bool {
	size := 16
	iter := len(line) / size
	blocks := [][]byte{}
	for i := 0; i < iter; i++ {
		block := line[i*size : (i+1)*size]
		for _, v := range blocks {
			if BytesEqual(v, block) {
				return true
			}
		}
		blocks = append(blocks, block)
	}
	return false
}

func BytesEqual(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}
