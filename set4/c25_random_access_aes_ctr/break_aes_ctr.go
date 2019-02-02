package c25_random_access_aes_ctr

import (
	"errors"

	"github.com/vodafon/cryptopals/set1/c2_fixed_xor"
	"github.com/vodafon/cryptopals/set3/c18_ctr_stream_mode"
)

func Edit(ciphertext, newtext []byte, nonce, offset uint32, ctr c18_ctr_stream_mode.CTRSystem) ([]byte, error) {
	dec, err := ctr.Decrypt(ciphertext, nonce)
	if err != nil {
		return nil, err
	}
	if uint32(len(dec)) < offset+uint32(len(newtext)) {
		return nil, errors.New("Incorrect offset")
	}
	copy(dec[offset:offset+uint32(len(newtext))], newtext)

	enc, err := ctr.Decrypt(dec, nonce)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func Recover(ciphertext []byte, nonce uint32, ctr c18_ctr_stream_mode.CTRSystem) ([]byte, error) {
	bs := uint32(16)
	plaintext := make([]byte, len(ciphertext))
	offset := uint32(0)
	for offset <= uint32(len(ciphertext)) {
		end := offset + bs
		if end > uint32(len(ciphertext)) {
			end = uint32(len(ciphertext))
		}
		c, err := Edit(ciphertext, make([]byte, end-offset), nonce, offset, ctr)
		if err != nil {
			return nil, err
		}
		copy(plaintext[offset:end], c2_fixed_xor.SafeXORBytes(ciphertext[offset:end], c[offset:end]))
		offset += bs
	}
	return plaintext, nil
}
