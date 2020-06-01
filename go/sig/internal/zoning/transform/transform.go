// Package transform transforms from and to the intermediate representation.
// This representation consist of the authenticated proof
// and the encrypted and authenticated IP packet.

//   0        1        2        3        4        5        6        7
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |  Nonce    |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |  Type  |          Zone ID         |            Time Stamp             |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |                                  MAC                                  |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |                           MAC (continued)                             |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |                          IP packet (encrypted)                        |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |                                  ...                                  |
//   +--------+--------+--------+--------+--------+--------+--------+--------+

package transform

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
)

var headerLength = 8

// Transformer transforms IP packets to and from intermediate representation
type Transformer struct {
	AEAD cipher.AEAD
}

// Overhead is the number of additional bytes added to the original IP
// packet when transformed to intermediate representation.
func (t *Transformer) Overhead() int {
	return t.AEAD.NonceSize() + t.AEAD.Overhead() + headerLength
}

// ToIR transforms an IP packet to intermediate representation
func (t *Transformer) ToIR(packet, additionalData []byte) ([]byte, error) {

	// pre-allocating a buffer which can accomodate nonce, additionalData, ciphertext and tag
	// makes sure encryption does not copy data unnecessarily
	nonceSize := t.AEAD.NonceSize()
	dst := make([]byte, len(packet)+t.Overhead())
	nonce := dst[:nonceSize]
	// TODO: make sure nonce is never repeated (use randomness+LFSR/Ctr value)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	copy(dst[nonceSize:nonceSize+headerLength], additionalData)
	buf := t.AEAD.Seal(dst[:nonceSize+headerLength], nonce, packet, additionalData)
	return buf, nil
}

// FromIR transforms data back to an IP packet
func (t *Transformer) FromIR(message []byte) (additionalData []byte, packet []byte, err error) {

	nonceSize := t.AEAD.NonceSize()
	nonce, additionalData, cipher := message[:nonceSize], message[nonceSize:nonceSize+headerLength], message[nonceSize+headerLength:]
	plaintext, err := t.AEAD.Open(cipher[:0], nonce, cipher, additionalData)
	if err != nil {
		return nil, nil, err
	}
	return additionalData, plaintext, nil
}
