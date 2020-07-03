package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/scionproto/scion/go/sig/zoning"
)

// this should be increased when breaking changes are made
var version = []byte("1")
var maxTimeDiff = 1 * time.Second

// Module implements the authentication module
// It transforms IP packets to and from intermediate representation
type Module struct {
	km      KeyManager
	tmap    *cache.Cache
	ingress bool
}

// NewModule returns a new authentication module
func NewModule(km KeyManager, ingress bool) *Module {
	return &Module{
		km:      km,
		ingress: ingress,
		tmap:    cache.New(cache.NoExpiration, -1),
	}
}

// Handle handles individual IP packets, transforming them to/from intermediate representation
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	if m.ingress {
		return m.handleIngress(pkt)
	}
	return m.handleEgress(pkt)
}

func (m *Module) handleIngress(pkt zoning.Packet) (zoning.Packet, error) {
	if pkt.SrcTP == "" {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] source TP address not set in packet")
	}
	key, err := m.km.DeriveL1Key(pkt.SrcTP)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] key derivation failed: %v", err)
	}
	tr, err := NewTR(key)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] could not create transformer: %v", err)
	}
	var ad []byte
	ad, pkt.RawPacket, err = tr.FromIR(pkt.RawPacket)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
	}
	pkt.RawDstZone = ad[1:4]
	ts := time.Unix(int64(binary.LittleEndian.Uint32(ad[4:])), 0)
	err = checkTime(ts)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
	}
	return pkt, nil
}
func (m *Module) handleEgress(pkt zoning.Packet) (zoning.Packet, error) {
	ad := make([]byte, 8)
	copy(ad[:1], version)
	copy(ad[1:4], pkt.RawDstZone)
	binary.LittleEndian.PutUint32(ad[4:], uint32(time.Now().Unix()))

	if pkt.DstTP == "" {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] destination TP address not set in packet")
	}
	key, fresh, err := m.km.FetchL1Key(pkt.DstTP)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] fetching L1 key for %v failed: %v", pkt.DstTP, err)
	}
	if fresh {
		tr, err := NewTR(key)
		if err != nil {
			// how to handle? Next time we try fresh will be false and we don't set it here anymore
			return zoning.NilPacket, err
		}
		// we have two map lookups: 1. for the key and 2. for the TR which contains the key
		// basically the first lookup is just to see if the key is still valid
		// this is not ideal from computational overhead but it cleanly separates key management from encryption
		// if the key manager would also provide the TR we would only have one lookup but we don't have clean interfaces anymore
		m.tmap.Set(pkt.DstTP, tr, -1)
	}
	tr, ok := m.tmap.Get(pkt.DstTP)
	if !ok {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] transformer not found in cache: %v", err)
	}
	pkt.RawPacket, err = tr.(*TR).ToIR(pkt.RawPacket, ad)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] proof creation failed: %v", err)
	}
	return pkt, nil
}

func checkTime(t time.Time) error {
	diff := abs(t.Sub(time.Now().UTC()))
	if diff > maxTimeDiff {
		return errors.New("time difference is to big")
	}
	return nil

}

func abs(a time.Duration) time.Duration {
	if a >= 0 {
		return a
	}
	return -a
}
