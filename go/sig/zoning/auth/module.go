package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	tr, err := NewTR()
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] could not create transformer: %v", err)
	}
	var ad []byte
	zone := GetZone(pkt.RawPacket)
	key, err := m.km.DeriveL2Key(pkt.RemoteTP, zone)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] key derivation failed: %v", err)
	}
	ad, pkt.RawPacket, err = tr.FromIR(key, pkt.RawPacket)
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
		tr, err := NewTR()
		if err != nil {
			// how to handle? Next time we try fresh will be false and we don't set it here anymore
			return zoning.NilPacket, err
		}
		// we have two map lookups: 1. for the key and 2. for the TR which contains the key
		// basically the first lookup is just to see if the key is still valid
		// this is not ideal from computational overhead but it cleanly separates key management from encryption
		// if the key manager would also provide the TR we would only have one lookup but we don't have clean interfaces anymore
		m.tmap.Set(pkt.RemoteTP, tr, -1)
	}
	tr, ok := m.tmap.Get(pkt.RemoteTP)
	if !ok {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] transformer not found in cache: %v", err)
	}
	pkt.RawPacket, err = tr.(*TR).ToIR(key, pkt.RawPacket, ad)
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

func abs(a time.Duration) time.Duration {
	if a >= 0 {
		return a
	}
	return -a
}
