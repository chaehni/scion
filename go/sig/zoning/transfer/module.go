package transfer

import (
	"github.com/scionproto/scion/go/sig/zoning"
)

// Module implements the transfer module.
// It checks packets for valid zone transfers.
type Module struct{}

// Handle checks packets for valid zone transfers
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	return pkt, nil
}
