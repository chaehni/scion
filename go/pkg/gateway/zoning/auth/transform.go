// Package transform transforms from and to the intermediate representation.
// This representation consist of the authenticated proof
// and the encrypted and authenticated IP packet.

//   0        1        2        3        4
//   +--------+--------+--------+--------+
//   |  Type  |          ZoneID          |
//   +--------+--------+--------+--------+
//   |             TimeStamp             |
//   +--------+--------+--------+--------+
//   |               Nonce               |
//   +--------+--------+--------+--------+
//   |           Nonce (continued)       |
//   +--------+--------+--------+--------+
//   |           Nonce (continued)       |
//   +--------+--------+--------+--------+
//   |                MAC                |
//   +--------+--------+--------+--------+
//   |          MAC (continued)          |
//   +--------+--------+--------+--------+
//   |          MAC (continued)          |
//   +--------+--------+--------+--------+
//   |          MAC (continued)          |
//   +--------+--------+--------+--------+

package auth

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync/atomic"
	"time"

	"github.com/patrickmn/go-cache"
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
	nsMap *cache.Cache
}

type nonceState struct {
	nonceCtr    uint64
	maxNonceCtr uint64
	nonceRnd    []byte
}

func newNonceState() (*nonceState, error) {
	var maxCtr uint64
	var rndSize int
	if nonceSize() >= 8 {
		maxCtr = math.MaxUint64
		rndSize = nonceSize() - 8
	} else {
		maxCtr = uint64(1<<(nonceSize()*8) - 1)
		rndSize = 0
	}

	ns := &nonceState{
		nonceCtr:    0,
		maxNonceCtr: maxCtr,
	}
	ns.nonceRnd = make([]byte, rndSize)
	if _, err := io.ReadFull(rand.Reader, ns.nonceRnd); err != nil {
		return nil, err
	}
	return ns, nil
}

// nextNonce creates a new, unique nonce.
// The returned nonce is the little-endian byte representation of a nonce counter.
// In case the nonce is longer than 8 bytes the remaining capacity is filled with random bytes
func (ns *nonceState) nextNonce(buf []byte) error {

	// atomically get next nonce counter
	for {
		old := ns.nonceCtr
		new := old + 1
		if old == ns.maxNonceCtr {
			return errors.New("nonce reached max count, new key required")
		}
		if atomic.CompareAndSwapUint64(&ns.nonceCtr, old, new) {
			bs := make([]byte, 8)
			binary.LittleEndian.PutUint64(bs, new)
			n := copy(buf, bs)
			copy(buf[n:], ns.nonceRnd)
			return nil
		}
	}
}

// NewTR creates a new transformer
func NewTR() *TR {
	return &TR{
		nsMap: cache.New(cache.NoExpiration, -1),
	}
}

// Overhead is the number of additional bytes added to the original IP
// packet when transformed to intermediate representation.
func (t *TR) Overhead() int {
	return headerLength + nonceSize() + tagSize()
}

// ResetState resets the state for remote kept by the Transformer
func (t *TR) ResetState(remote string) error {
	_, err := t.resetState(remote)
	return err
}

func (t *TR) resetState(remote string) (*nonceState, error) {
	ns, err := newNonceState()
	if err != nil {
		return nil, err
	}
	t.nsMap.Set(remote, ns, -1)
	return ns, nil
}

// ToIR transforms an IP packet to intermediate representation
func (t *TR) ToIR(remote string, key, packet []byte, dstZone uint32) ([]byte, error) {
	// get nonce state for remote
	var ns interface{}
	var err error
	ns, ok := t.nsMap.Get(remote)
	if !ok {
		ns, err = t.resetState(remote)
		if err != nil {
			return nil, err
		}
		//return nil, fmt.Errorf("no nonce state found for sending to remote %v", remote)
	}
	// pre-allocating a buffer which can accomodate  additionalData, nonce, ciphertext and tag
	// makes sure encryption does not copy data unnecessarily
	dst := make([]byte, len(packet)+t.Overhead())
	nonceSize := nonceSize()
	adSlice := dst[:headerLength]
	copy(adSlice, t.buildHeader(dstZone))
	nonceSlice := dst[headerLength : headerLength+nonceSize]
	err = ns.(*nonceState).nextNonce(nonceSlice)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	buf := aead.Seal(dst[:headerLength+nonceSize], nonceSlice, packet, adSlice)
	return buf, nil
}

func (t *TR) buildHeader(zone uint32) []byte {
	ad := make([]byte, headerLength)
	copy(ad[typeOffset:typeOffset+typeLength], version)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, zone)
	copy(ad[zoneOffset:zoneOffset+zoneLength], buf)
	binary.LittleEndian.PutUint32(ad[timeOffset:], uint32(time.Now().Unix()))
	return ad
}

// FromIR transforms data back to an IP packet
func (t *TR) FromIR(key, message []byte) (additionalData []byte, packet []byte, err error) {
	nonceSize := nonceSize()
	if len(message) <= t.Overhead() {
		return nil, nil, fmt.Errorf("packet too small, need more than %d bytes", t.Overhead())
	}
	additionalData, nonce, cipher := message[:headerLength],
		message[headerLength:nonceSize+headerLength], message[nonceSize+headerLength:]
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
func (t *TR) GetZone(message []byte) (uint32, error) {
	if len(message) < zoneOffset+zoneLength {
		return 0, fmt.Errorf("cannot retrieve zone ID. message too short")
	}
	zone := uint32(message[zoneOffset]) | uint32(message[zoneOffset+1])<<8 |
		uint32(message[zoneOffset+2])<<16
	return zone, nil
}
