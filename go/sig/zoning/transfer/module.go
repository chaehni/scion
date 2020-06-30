package transfer

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

var errorPrefix = "[TransferModule]"
var refreshInterval = 5 * time.Minute

// Module implements the transfer module.
// It checks packets for valid zone transfers.
type Module struct {
	subnets        types.Subnets
	transfers      types.Transfers
	client         *http.Client
	controllerAddr string
	lock           sync.RWMutex
}

// New creates a new Transfer Module
func New(controllerAddr, cert, key string) (*Module, error) {

	mod := &Module{
		client: &http.Client{
			Transport: shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil),
		},
		controllerAddr: controllerAddr,
	}

	// start periodic task fetching info from controller
	ticker := time.NewTicker(refreshInterval)
	err := mod.fetchInfo()
	if err != nil {
		return nil, fmt.Errorf("%v Failed to fetch initial data from controller: %v", errorPrefix, err)
	}
	go func() {
		for range ticker.C {
			err := mod.fetchInfo()
			if err != nil {
				// TODO: handle errors where info cannot be updated (use LogFatal?)
				// e.g. by having a deadline timer after which we stop using stalled info. deadline timer is reset after every successful fetch
				panic(err)
			}
		}
	}()
	return mod, nil
}

// Handle checks packets for valid zone transfers
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	// get reader lock in case data is currently being refreshed
	m.lock.RLock()
	defer m.lock.RUnlock()
	// get zones for src/dest
	srcZone, _, err := m.findZone(pkt.SrcHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v find source zone: %v", errorPrefix, err)
	}
	pkt.DstZone, pkt.DstTP, err = m.findZone(pkt.DstHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v find destination zone: %v", errorPrefix, err)
	}

	// check if transfer is allowed
	dests, ok := m.transfers[srcZone]
	if !ok {
		return zoning.NilPacket, fmt.Errorf("%v no transfer rules found for source zone %v", errorPrefix, srcZone)
	}
	for _, dest := range dests {
		if pkt.DstZone == dest {
			return pkt, nil
		}
	}
	return zoning.NilPacket, fmt.Errorf("%v transfer from zone %v to zone %v not allowed", errorPrefix, srcZone, pkt.DstZone)
}

func (m *Module) findZone(ip net.IP) (types.ZoneID, string, error) {
	for _, net := range m.subnets {
		if net.IPNet.Contains(ip) {
			return net.ZoneID, net.TPAddr, nil
		}
	}
	return 0, "", fmt.Errorf("no matching zone found for IP %v", ip)
}

func (m *Module) fetchInfo() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// TODO: make an API package and read routes from there
	resp, err := m.client.Get(fmt.Sprintf("https://%s/api/get-subnets", m.controllerAddr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&m.subnets)
	if err != nil {
		return err
	}

	resp, err = m.client.Get(fmt.Sprintf("https://%s/api/get-transfers", m.controllerAddr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	decoder = json.NewDecoder(resp.Body)
	err = decoder.Decode(&m.transfers)
	if err != nil {
		return err
	}
	return nil
}
