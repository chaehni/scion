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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
)

// version should be increased when breaking changes are made
var version = []byte{1}
var headerLength = 8
var typeOffset = 0
var typeLength = 1
var zoneOffset = 1
var zoneLength = 3
var timeOffset = 4
var timeLength = 4

var _ = Transformer(&TR{})

// TR implements the Transformer interface
type TR struct {
	nonceCtr    uint64
	maxNonceCtr uint64
	nonceRnd    []byte
	once        sync.Once
}

// NewTR creates a new Transformer
func NewTR() (*TR, error) {

	var maxCtr uint64
	var rndSize int
	if nonceSize() >= 8 {
		maxCtr = math.MaxUint64
		rndSize = nonceSize() - 8
	} else {
		maxCtr = uint64(1<<(nonceSize()*8) - 1)
		rndSize = 0
	}

	tr := &TR{
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
	return nonceSize() + tagSize() + headerLength
}

// ToIR transforms an IP packet to intermediate representation
func (t *TR) ToIR(key, packet, additionalData []byte) ([]byte, error) {
	// pre-allocating a buffer which can accomodate nonce, additionalData, ciphertext and tag
	// makes sure encryption does not copy data unnecessarily
	nonceSize := nonceSize()
	dst := make([]byte, len(packet)+t.Overhead())
	nonce := dst[headerLength : headerLength+nonceSize]

	// fetch a fresh nonce
	err := t.nextNonce(nonce)
	if err != nil {
		return nil, err
	}
	copy(dst[:headerLength], additionalData)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	buf := aead.Seal(dst[:headerLength+nonceSize], nonce, packet, additionalData)
	return buf, nil
}

// FromIR transforms data back to an IP packet
func (t *TR) FromIR(key, message []byte) (additionalData []byte, packet []byte, err error) {
	nonceSize := nonceSize()
	//TODO: check message size before slicing
	additionalData, nonce, cipher := message[:headerLength], message[headerLength:nonceSize+headerLength], message[nonceSize+headerLength:]
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(cipher[:0], nonce, cipher, additionalData)
	if err != nil {
		return nil, nil, err
	}
	return additionalData, plaintext, nil
}

// GetZone extracts the zone infromation from the encrypted packet
func GetZone(message []byte) []byte {
	//TODO: check message size before slicing
	return message[zoneOffset:timeOffset]
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
