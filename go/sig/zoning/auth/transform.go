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

	"github.com/scionproto/scion/go/lib/log"
)

var headerLength = 8

var _ = Transformer(&TR{})

// TR implements the Transformer interface
type TR struct {
	aead        cipher.AEAD
	nonceCtr    uint64
	maxNonceCtr uint64
	nonceRnd    []byte
	mutex       sync.Mutex
}

// NewTR creates a new Transformer
func NewTR(key []byte) (*TR, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	var maxCtr uint64
	var rndSize int
	if aead.NonceSize() >= 8 {
		maxCtr = math.MaxUint64
		rndSize = aead.NonceSize() - 8
	} else {
		maxCtr = uint64(1<<(aead.NonceSize()*8) - 1)
		rndSize = 0
	}

	tr := &TR{
		aead:        aead,
		nonceCtr:    0,
		maxNonceCtr: maxCtr,
	}
	tr.nonceRnd = make([]byte, rndSize)
	if _, err := io.ReadFull(rand.Reader, tr.nonceRnd); err != nil {
		return nil, err
	}
	return tr, nil
}

// Overhead is the number of additional bytes added to the original IP
// packet when transformed to intermediate representation.
func (t *TR) Overhead() int {
	return t.aead.NonceSize() + t.aead.Overhead() + headerLength
}

// ToIR transforms an IP packet to intermediate representation
func (t *TR) ToIR(packet, additionalData []byte) ([]byte, error) {

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

	// TODO: DEBUG:
	log.Debug("Printing Nonce", "nonce", nonce)

	copy(dst[nonceSize:nonceSize+headerLength], additionalData)
	buf := t.aead.Seal(dst[:nonceSize+headerLength], nonce, packet, additionalData)
	return buf, nil
}

// FromIR transforms data back to an IP packet
func (t *TR) FromIR(message []byte) (additionalData []byte, packet []byte, err error) {
	nonceSize := t.aead.NonceSize()
	//TODO: check message size before slicing
	nonce, additionalData, cipher := message[:nonceSize], message[nonceSize:nonceSize+headerLength], message[nonceSize+headerLength:]
	plaintext, err := t.aead.Open(cipher[:0], nonce, cipher, additionalData)
	if err != nil {
		return nil, nil, err
	}
	return additionalData, plaintext, nil
}

// UpdateKey updates the key for the encryption used by Transformer
func (t *TR) UpdateKey() error {
	return errors.New("not implemented")
}

// nextNonce creates a new, unique nonce.
// The returned nonce is the little-endian byte representation of a nonce counter.
// In case the nonce is longer than 8 bytes the remaining capacity is filled with random bytes
func (t *TR) nextNonce(buf []byte) error {

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
			n := copy(buf, bs)
			copy(buf[n:], t.nonceRnd)
			return nil
		}
	}
}
