package transfer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/go/sig/zoning"
)

// Module implements the Module interface.
// It checks packets for valid zone transfers.
type Module struct{}

// Handle checks packets for valid zone transfers
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	p := gopacket.NewPacket(pkt.RawPacket, layers.LayerTypeIPv4, gopacket.Default)
	for _, layer := range p.Layers() {
		fmt.Println("Egress: PACKET LAYER:", layer.LayerType())
	}
	l4 := p.ApplicationLayer()
	if l4 != nil {
		fmt.Println(string(l4.Payload()))
	}
	return pkt, nil
}
