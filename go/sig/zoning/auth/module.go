package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/sig/zoning"
)

var version = []byte("1")
var maxTimeDiff = 1 * time.Second

// Module implements the authentication module
// It transforms IP packets to and from intermediate representation
type Module struct {
	t       *Transformer
	ingress bool
}

// NewModule returns a new authentication module
func NewModule(t *Transformer, ingress bool) *Module {
	return &Module{
		t:       t,
		ingress: ingress,
	}
}

// Handle handles individual IP packets, transforming them to/from intermediate representation
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	var err error
	var ad []byte
	if m.ingress {
		ad, pkt.RawPacket, err = m.t.FromIR(pkt.RawPacket)
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
		}
		pkt.DstZone = ad[1:4]
		ts := time.Unix(int64(binary.LittleEndian.Uint32(ad[4:])), 0)
		err = checkTime(ts)
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthIngress] verification failed: %v", err)
		}
		return pkt, nil
	} else {
		ad = make([]byte, 8)
		copy(ad[:1], version)
		copy(ad[1:4], pkt.DstZone)
		binary.LittleEndian.PutUint32(ad[4:], uint32(time.Now().Unix()))
		pkt.RawPacket, err = m.t.ToIR(pkt.RawPacket, ad)
		if err != nil {
			return zoning.NilPacket, fmt.Errorf("[AuthIngress] proof creation failed: %v", err)
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
