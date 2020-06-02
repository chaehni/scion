package zoning

import (
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
)

// Pipeline is a pipeline of modules which are passed by each packet
type Pipeline struct {
	modules []Module
	mutex   sync.Mutex
}

// Register adds the passed modules to the Pipeline in the same order they are provided in the argument
func (p *Pipeline) Register(m ...Module) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.modules = append(p.modules, m...)
}

// Handle passes the packet to the registered modules. If a module returns an error, the error is returned from the pipeline.
// Ohterwise the returned packet is the result of all modules applied to the input packet
func (p *Pipeline) Handle(pkt Packet) (Packet, error) {
	var err error
	for _, m := range p.modules {
		pkt, err = m.Handle(pkt)
		if err != nil {
			return Packet{}, err
		}
	}
	return pkt, nil
}

// Packet contains a raw IP packet with additional meta data
type Packet struct {
	SrcIP     net.IP
	DstIP     net.IP
	RawPacket common.RawBytes
}

// Module is a single element in the pipeline that handles IP packets
// Modules must be thread safe
type Module interface {
	Handle(Packet) (Packet, error)
}
