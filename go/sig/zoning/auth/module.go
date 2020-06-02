package auth

import "github.com/scionproto/scion/go/sig/zoning"

// Module implements the authentication module
// It transforms IP packets to and from intermediate representation
type Module struct {
	t       Transformer
	ingress bool
}

// Handle handles individual IP packets, transforming them to/from intermediate representation
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	if m.ingress {
		// decapsulate
	} else {
		// encapsulate
	}

	return pkt, nil
}
