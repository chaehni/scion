package zoning

import (
	"net"

	"github.com/scionproto/scion/go/lib/common"
)

var EgressChain Chain
var IngressChain Chain

// Chain is a pipeline of modules which is traversed by each packet
type Chain struct {
	modules []Module
	//mutex   sync.Mutex
}

// Register adds the passed modules to the Pipeline in the same order they are provided in the argument
func (c *Chain) Register(m ...Module) {
	/* 	c.mutex.Lock()
	   	defer c.mutex.Unlock() */
	c.modules = append(c.modules, m...)
}

// Handle passes the packet to the registered modules. If a module returns an error, the error is returned from the pipeline.
// Ohterwise the returned packet is the result of all modules applied to the input packet
func (c *Chain) Handle(pkt Packet) (Packet, error) {
	var err error
	for _, m := range c.modules {
		pkt, err = m.Handle(pkt)
		if err != nil {
			return Packet{}, err
		}
	}
	return pkt, nil
}

// Packet contains a raw IP packet with additional meta data
type Packet struct {
	Ingress   bool
	SrcHost   net.IP
	DstHost   net.IP
	RemoteTP  string
	DstZone   uint32
	RawPacket common.RawBytes
}

// NilPacket is the empty Packet
var NilPacket = Packet{}

// Module is a single element in the pipeline that handles IP packets
// Modules must be thread safe
type Module interface {
	Handle(Packet) (Packet, error)
}
