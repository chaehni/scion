package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/dchest/cmac"
)

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func initMac(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cmac.New(block)
}
