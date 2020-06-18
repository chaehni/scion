package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/scionproto/scion/go/sig/zoning"
)

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
	var ad []byte
	if m.ingress {
		key, err := m.km.DeriveL1Key(pkt.SrcTP.String())
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthIngress] key derivation failed: %v", err)
		}
		tr, err := NewTR(key)
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthIngress] could not create transformer: %v", err)
		}
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

	} else {
		ad = make([]byte, 8)
		copy(ad[:1], version)
		copy(ad[1:4], pkt.RawDstZone)
		binary.LittleEndian.PutUint32(ad[4:], uint32(time.Now().Unix()))

		key, fresh, err := m.km.FetchL1Key(pkt.DstTP.String()) // make sure pkt.DstTP is set before this module
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthEgress] fetching L1 key failed: %v", err)
		}
		if fresh {
			tr, err := NewTR(key)
			if err != nil {
				// how to handler?
				return zoning.NilPacket, err
			}
			m.tmap.Set(pkt.DstTP.String(), tr, -1)
		}
		tr, ok := m.tmap.Get(pkt.DstTP.String())
		if !ok {
			return zoning.NilPacket, fmt.Errorf("[AuthEgress] transformer not found in cache: %v", err)
		}
		pkt.RawPacket, err = tr.(*TR).ToIR(pkt.RawPacket, ad)
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthEgress] proof creation failed: %v", err)
		}
		return pkt, nil
	}
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
