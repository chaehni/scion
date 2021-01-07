package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/pkg/gateway/zoning"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/tpconfig"
)

//var dummyErr = errors.New("")
var egressPrefix = "[AuthEgress]"
var ingressPrefix = "[AuthIngress]"

var _ = zoning.Module(&Module{})

// Module implements the authentication module
// It transforms IP packets to and from intermediate representation
type Module struct {
	km          KeyManager
	tr          Transformer
	ingress     bool
	maxTimeDiff time.Duration
}

// NewModule returns a new authentication module
func NewModule(km KeyManager, tr Transformer, cfg tpconfig.AuthConf) *Module {
	return &Module{
		km:          km,
		tr:          tr,
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
	ts := time.Unix(int64(binary.LittleEndian.Uint32(pkt.RawPacket[timeOffset:timeOffset+timeLength])), 0)
	err := m.checkTime(ts)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
	}
	if pkt.RemoteTP == "" {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] source TP address not set in packet")
	}
	zone, err := m.tr.GetZone(pkt.RawPacket)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%s %v", ingressPrefix, err)
	}
	key, err := m.km.DeriveL2Key(pkt.RemoteTP, zone)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] key derivation failed: %v", err)
	}
	_, pkt.RawPacket, err = m.tr.FromIR(key, pkt.RawPacket)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
	}
	return pkt, nil
}

func (m *Module) handleEgress(pkt zoning.Packet) (zoning.Packet, error) {
	if pkt.RemoteTP == "" {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] destination TP address not set in packet")
	}
	key, fresh, err := m.km.FetchL2Key(pkt.RemoteTP, pkt.DstZone)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("[AuthEgress] fetching L1 key for %v failed: %v", pkt.RemoteTP, err)
	}
	if fresh {
		m.tr.ResetState(pkt.RemoteTP)
		if err != nil {
			// how to handle? Next time we try fresh will be false and we don't set it here anymore
			return zoning.NilPacket, err
		}
	}
	pkt.RawPacket, err = m.tr.ToIR(pkt.RemoteTP, key, pkt.RawPacket, pkt.DstZone)
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
