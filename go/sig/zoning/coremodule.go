package zoning

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

const (
	ip4Ver    = 0x4
	ip6Ver    = 0x6
	ip4SrcOff = 12
	ip4DstOff = 16
	ip6DstOff = 24
)

// CoreModule implements the zoning architecture's core module
type CoreModule struct {
	local string
}

// NewCoreModule returns a new core module
func NewCoreModule(ia addr.IA, ip net.IP) *CoreModule {
	return &CoreModule{local: fmt.Sprintf("%v,%v", ia, ip)}
}

// Handle handles IP packets
func (cm *CoreModule) Handle(pkt Packet) (Packet, error) {
	dst, err := cm.getDestIP(pkt.RawPacket)
	if err != nil {
		return NilPacket, err
	}
	src, err := cm.getSrcIP(pkt.RawPacket)
	if err != nil {
		return NilPacket, err
	}
	pkt.DstHost = dst
	pkt.SrcHost = src

	return pkt, nil
}

func (cm *CoreModule) getDestIP(b common.RawBytes) (net.IP, error) {
	ver := (b[0] >> 4)
	switch ver {
	case ip4Ver:
		return net.IP(b[ip4DstOff : ip4DstOff+net.IPv4len]), nil
	case ip6Ver:
		return net.IP(b[ip6DstOff : ip6DstOff+net.IPv6len]), nil
	default:
		return nil, common.NewBasicError("Unsupported IP protocol version in egress packet", nil,
			"type", ver)
	}
}
func (cm *CoreModule) getSrcIP(b common.RawBytes) (net.IP, error) {
	ver := (b[0] >> 4)
	switch ver {
	case ip4Ver:
		return net.IP(b[ip4SrcOff : ip4SrcOff+net.IPv4len]), nil
	case ip6Ver:
		return net.IP(b[ip6DstOff : ip6DstOff+net.IPv6len]), nil
	default:
		return nil, common.NewBasicError("Unsupported IP protocol version in egress packet", nil,
			"type", ver)
	}
}
