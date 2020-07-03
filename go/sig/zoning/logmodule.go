package zoning

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LogModule implements a module which logs traffic it handles.
// It checks packets for valid zone transfers.
type LogModule struct {
	LocalTP string
}

// Handle checks packets for valid zone transfers
func (m *LogModule) Handle(pkt Packet) (Packet, error) {
	p := gopacket.NewPacket(pkt.RawPacket, layers.LayerTypeIPv4, gopacket.Default)
	l4 := p.ApplicationLayer()
	if l4 != nil {
		if pkt.Ingress {
			fmt.Printf("[ingress log] %v ---> %v ====> %v ---> %v\n%v\n", pkt.SrcHost, pkt.RemoteTP, m.LocalTP, pkt.DstHost, string(l4.Payload()))
		} else {
			fmt.Printf("[egress log] %v ---> %v ====> %v ---> %v\n%v\n", pkt.SrcHost, m.LocalTP, pkt.RemoteTP, pkt.DstHost, string(l4.Payload()))
		}
	}
	return pkt, nil
}
