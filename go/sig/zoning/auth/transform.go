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

package auth

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
)

var headerLength = 8

// Transformer transforms IP packets to and from intermediate representation
type Transformer struct {
	aead        cipher.AEAD
	nonceCtr    uint64
	maxNonceCtr uint64
	mutex       sync.Mutex
}

// NewTransformer creates a new Transformer
func NewTransformer(aead cipher.AEAD) *Transformer {

	var maxCtr uint64
	if aead.NonceSize() >= 8 {
		maxCtr = math.MaxUint64
	} else {
		maxCtr = uint64(1<<(aead.NonceSize()*8) - 1)
	}

	return &Transformer{
		aead:        aead,
		nonceCtr:    0,
		maxNonceCtr: maxCtr,
	}
}

// Overhead is the number of additional bytes added to the original IP
// packet when transformed to intermediate representation.
func (t *Transformer) Overhead() int {
	return t.aead.NonceSize() + t.aead.Overhead() + headerLength
}

// ToIR transforms an IP packet to intermediate representation
func (t *Transformer) ToIR(packet, additionalData []byte) ([]byte, error) {

	// pre-allocating a buffer which can accomodate nonce, additionalData, ciphertext and tag
	// makes sure encryption does not copy data unnecessarily
	nonceSize := t.aead.NonceSize()
	dst := make([]byte, len(packet)+t.Overhead())
	nonce := dst[:nonceSize]

	// fetch a fresh nonce
	err := t.nextNonce(nonce)
	if err != nil {
		return nil, err
	}

	copy(dst[nonceSize:nonceSize+headerLength], additionalData)
	buf := t.aead.Seal(dst[:nonceSize+headerLength], nonce, packet, additionalData)
	return buf, nil
}

// FromIR transforms data back to an IP packet
func (t *Transformer) FromIR(message []byte) (additionalData []byte, packet []byte, err error) {

	nonceSize := t.aead.NonceSize()
	nonce, additionalData, cipher := message[:nonceSize], message[nonceSize:nonceSize+headerLength], message[nonceSize+headerLength:]
	plaintext, err := t.aead.Open(cipher[:0], nonce, cipher, additionalData)
	if err != nil {
		return nil, nil, err
	}
	return additionalData, plaintext, nil
}

// UpdateKey updates the key for the encryption used by Transformer
func (t *Transformer) UpdateKey() error {
	return errors.New("not implemented")
}

// nextNonce creates a new, unique nonce
// it is the little endian byte representation of a nonce counter
// in case the nonce is longer than 8 bytes the remaining capacity is filled with random bytes
func (t *Transformer) nextNonce(buf []byte) error {

	// atomically get next nonce counter
	for {
		old := t.nonceCtr
		new := old + 1
		if old == t.maxNonceCtr {
			return errors.New("nonce reached max count, new key required")
		}
		if atomic.CompareAndSwapUint64(&t.nonceCtr, old, new) {
			bs := make([]byte, 8)
			binary.LittleEndian.PutUint64(bs, new)
			n := copy(buf, bs[:min(8, t.aead.NonceSize())])
			if _, err := io.ReadFull(rand.Reader, buf[n:]); err != nil {
				return err
			}
			return nil
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
