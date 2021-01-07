package transition

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/tpconfig"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/types"
)

// Fetcher is used to fetch controller information from the controller
type Fetcher interface {
	FetchSubnets() (types.Subnets, error)
	FetchTransitions() (types.Transitions, error)
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
	client         *http.Client
}

// NewRuleFetcher returns a fetcher used to fetch rules from the controller
func NewRuleFetcher(ia addr.IA, ip net.IP, cfg tpconfig.TransConf) *RuleFetcher {
	return &RuleFetcher{
		localAddr:      fmt.Sprintf("%v,%v", ia, ip),
		controllerAddr: cfg.ControllerAddr,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			//Transport: shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil),
		},
	}
}

// FetchSubnets fechtches the configured subnet information from the controller
func (f *RuleFetcher) FetchSubnets() (types.Subnets, error) {
	// TODO: make an API package and read routes from there
	resp, err := f.client.Post(fmt.Sprintf("https://%s/api/get-subnets", f.controllerAddr), "text/plain", strings.NewReader(f.localAddr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	subnets := types.Subnets{}
	err = decoder.Decode(&subnets)
	if err != nil {
		return nil, err
	}
	return subnets, nil
}

// FetchTransitions fechtches the configured transitions information from the controller
func (f *RuleFetcher) FetchTransitions() (types.Transitions, error) {
	resp, err := f.client.Post(fmt.Sprintf("https://%s/api/get-transitions", f.controllerAddr), "text/plain", strings.NewReader(f.localAddr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	transitions := types.Transitions{}
	err = decoder.Decode(&transitions)
	if err != nil {
		return nil, err
	}
	return transitions, nil
}
