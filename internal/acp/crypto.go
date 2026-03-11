package acp

import "errors"

func EncryptACPPassword(password string, key []byte) ([]byte, error) {
	if len(key) != 4 {
		return nil, errors.New("encryption key must be 4 bytes")
	}
	if len(password) > 24 {
		return nil, errors.New("password length must be <= 24")
	}
	if len(password) == 0 {
		return make([]byte, 8), nil
	}

	chunks := (len(password) + 7) >> 3
	out := make([]byte, chunks*8)
	for i := 0; i < chunks; i++ {
		sub := make([]byte, 8)
		subLen := len(password) - i*8
		if subLen > 8 {
			subLen = 8
		}
		copy(sub, []byte(password[i*8:]))
		if subLen < 8 {
			sub[subLen] = 0x00
		}
		enc := encACPPassword(sub, key)
		copy(out[i*8:], enc)
	}
	return out, nil
}

func encACPPassword(password []byte, key []byte) []byte {
	newKey := make([]byte, 8)
	result := make([]byte, 8)

	for i := 0; i < 4; i++ {
		newKey[3-i] = key[i]
		newKey[4+i] = byte((key[i] ^ key[3-i]) * key[3-i])
	}

	j := 0
	for i := 0; i < 4; i++ {
		newKey[0] = password[j] ^ newKey[0]
		n := 2
		for k := 0; k < i; k++ {
			newKey[n] = newKey[n] ^ newKey[n-2]
			n += 2
		}
		result[i] = newKey[j]

		newKey[1] = password[j+1] ^ newKey[1]
		n = 3
		for k := 0; k < i; k++ {
			newKey[n] = newKey[n] ^ newKey[n-2]
			n += 2
		}
		result[7-i] = newKey[j+1]
		j += 2
	}
	return result
}
