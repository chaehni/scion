package zoning

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LogModule implements a module which logs traffic it handles.
// It checks packets for valid zone transfers.
type LogModule struct {
	Prefix string
}

// Handle checks packets for valid zone transfers
func (m *LogModule) Handle(pkt Packet) (Packet, error) {
	p := gopacket.NewPacket(pkt.RawPacket, layers.LayerTypeIPv4, gopacket.Default)
	l4 := p.ApplicationLayer()
	if l4 != nil {
		fmt.Printf("[%v] %v ---> %v\n%v\n", m.Prefix, pkt.SrcHost, pkt.DstHost, string(l4.Payload()))
	}
	return pkt, nil
}
