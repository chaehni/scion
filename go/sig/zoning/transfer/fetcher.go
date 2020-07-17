package transfer

import (
	"errors"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

// Fetcher is used to fetch controller information from the controller
type Fetcher interface {
	FetchSubnets() (types.Subnets, error)
	FetchTransfers() (types.Transfers, error)
}

var _ = Fetcher(&RuleFetcher{})

// RuleFetcher implements the Fetcher interface
type RuleFetcher struct {
	// TODO: local address is sent to the controller to identify the right TP
	// This is hack, the controller should read the remote address itself but
	// the dumbed down shttp package doesn't allow to set the local address on the client side
	// instead it always uses 127.0.0.1
	localAddr      string
	controllerAddr string
}

// NewRuleFetcher returns a fetcher used to fetch rules from the controller
func NewRuleFetcher(ia addr.IA, ip net.IP, cfg tpconfig.TransConf) *RuleFetcher {
	return &RuleFetcher{
		localAddr:      fmt.Sprintf("%v,%v", ia, ip),
		controllerAddr: cfg.ControllerAddr,
	}
}

func (f *RuleFetcher) FetchSubnets() (types.Subnets, error) {
	return nil, errors.New("not implemented")
}
func (f *RuleFetcher) FetchTransfers() (types.Transfers, error) {
	return nil, errors.New("not implemented")
}
