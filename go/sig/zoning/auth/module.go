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
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
)

// Module implements the authentication module
// It transforms IP packets to and from intermediate representation
type Module struct {
	km          KeyManager
	tmap        *cache.Cache
	ingress     bool
	maxTimeDiff time.Duration
}

type nonceState struct {
	nonceCtr    uint64
	maxNonceCtr uint64
	nonceRnd    []byte
}

// NewModule returns a new authentication module
func NewModule(km KeyManager, cfg tpconfig.AuthConf) *Module {
	return &Module{
		km:          km,
		tmap:        cache.New(cache.NoExpiration, -1),
		maxTimeDiff: cfg.MaxTimeDiff.Duration,
	}
}

// Handle handles individual IP packets, transforming them to/from intermediate representation
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	if pkt.Ingress {
		return m.handleIngress(pkt)
	}
	return m.handleEgress(pkt)
}

func (m *Module) handleIngress(pkt zoning.Packet) (zoning.Packet, error) {
	if pkt.RemoteTP == "" {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] source TP address not set in packet")
	}
	/* 	tr, err := NewTR()
	   	if err != nil {
	   		return zoning.NilPacket, fmt.Errorf("[AuthIngress] could not create transformer: %v", err)
	   	} */
	var ad []byte
	zone := GetZone(pkt.RawPacket)
	key, err := m.km.DeriveL2Key(pkt.RemoteTP, zone)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] key derivation failed: %v", err)
	}
	ad, pkt.RawPacket, err = FromIR(key, pkt.RawPacket)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
	}
	ts := time.Unix(int64(binary.LittleEndian.Uint32(ad[timeOffset:])), 0)
	err = m.checkTime(ts)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
	}
	return pkt, nil
}
func (m *Module) handleEgress(pkt zoning.Packet) (zoning.Packet, error) {
	ad := make([]byte, headerLength)
	copy(ad[:typeOffset+typeLength], version)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, pkt.DstZone)
	copy(ad[zoneOffset:zoneOffset+zoneLength], buf)
	binary.LittleEndian.PutUint32(ad[timeOffset:], uint32(time.Now().Unix()))

	if pkt.RemoteTP == "" {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] destination TP address not set in packet")
	}
	key, fresh, err := m.km.FetchL2Key(pkt.RemoteTP, buf[:3])
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] fetching L1 key for %v failed: %v", pkt.RemoteTP, err)
	}
	if fresh {
		ns, err := initNonceState()
		if err != nil {
			// how to handle? Next time we try fresh will be false and we don't set it here anymore
			return zoning.NilPacket, err
		}
		// we have two map lookups: 1. for the key and 2. for the TR which contains the key
		// basically the first lookup is just to see if the key is still valid
		// this is not ideal from computational overhead but it cleanly separates key management from encryption
		// if the key manager would also provide the TR we would only have one lookup but we don't have clean interfaces anymore
		m.tmap.Set(pkt.RemoteTP, ns, -1)
	}
	ns, ok := m.tmap.Get(pkt.RemoteTP)
	if !ok {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] transformer not found in cache: %v", err)
	}
	nonce, err := ns.(*nonceState).nextNonce()
	pkt.RawPacket, err = ToIR(key, nonce, pkt.RawPacket, ad)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] proof creation failed: %v", err)
	}
	return pkt, nil
}

func (m *Module) checkTime(t time.Time) error {
	diff := abs(t.Sub(time.Now().UTC()))
	if diff > m.maxTimeDiff {
		return errors.New("time difference is to big")
	}
	return nil

}

func initNonceState() (*nonceState, error) {
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
func (ns *nonceState) nextNonce() ([]byte, error) {

	// atomically get next nonce counter
	for {
		old := ns.nonceCtr
		new := old + 1
		if old == ns.maxNonceCtr {
			return nil, errors.New("nonce reached max count, new key required")
		}
		if atomic.CompareAndSwapUint64(&ns.nonceCtr, old, new) {
			nonce := make([]byte, nonceSize())
			bs := make([]byte, 8)
			binary.LittleEndian.PutUint64(bs, new)
			n := copy(nonce, bs)
			copy(nonce[n:], ns.nonceRnd)
			return nonce, nil
		}
	}
}

func abs(a time.Duration) time.Duration {
	if a >= 0 {
		return a
	}
	return -a
}
