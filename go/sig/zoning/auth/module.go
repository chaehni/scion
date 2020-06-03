package auth

import "github.com/scionproto/scion/go/sig/zoning"

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
	if m.ingress {
		_, pkt.RawPacket, err = m.t.FromIR(pkt.RawPacket)
		if err != nil {
			return zoning.NilPacket, err
		}
		return pkt, nil
	} else {
		pkt.RawPacket, err = m.t.ToIR(pkt.RawPacket, []byte("12345678"))
		if err != nil {
			return zoning.NilPacket, err
		}
		return pkt, nil
	}
}
