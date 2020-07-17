package transfer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
	"github.com/scionproto/scion/go/sig/zoning/types"

	"github.com/yl2chen/cidranger"
)

// Init initializes the transfer package
func Init() {
	fatal.Check()
}

var errorPrefix = "[TransferModule]"

var _ = zoning.Module(&Module{})

// Module implements the transfer module.
// It checks packets for valid zone transfers.
type Module struct {
	//subnets   types.Subnets
	cfg       tpconfig.TransConf
	ranger    cidranger.Ranger
	transfers types.Transfers
	client    *http.Client

	fetcher Fetcher

	lock sync.RWMutex
}

// NewModule creates a new Transfer Module
func NewModule(fetcher Fetcher, cfg tpconfig.TransConf) *Module {

	return &Module{
		cfg:    cfg,
		ranger: cidranger.NewPCTrieRanger(),
		client: &http.Client{
			Transport: shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil),
		},
		/* localAddr:      fmt.Sprintf("%v,%v", ia, ip),
		controllerAddr: cfg.ControllerAddr, */
		fetcher: fetcher,
	}
}

// Handle checks packets for valid zone transfers
func (m *Module) Handle(pkt zoning.Packet) (zoning.Packet, error) {
	if pkt.Ingress {
		return m.handleIngress(pkt)
	}
	return m.handleEgress(pkt)
}

func (m *Module) handleIngress(pkt zoning.Packet) (zoning.Packet, error) {
	// get reader lock in case data is currently being refreshed
	m.lock.RLock()
	defer m.lock.RUnlock()
	// get zones for src/dest
	srcZone, srcTP, err := m.findZone(pkt.SrcHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v error finding source zone: %v", errorPrefix, err)
	}
	destZone, _, err := m.findZone(pkt.DstHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v error finding destination zone: %v", errorPrefix, err)
	}

	// check if claimed src IP is located behind the actual srcTP (as read from SCION header)
	// (if srcTP was spoofed too, we wouldn't even get this far since the MAC verification would have failed in the auth module)
	if srcTP != pkt.RemoteTP {
		return zoning.NilPacket, fmt.Errorf("%v source TP %v is not responsible for claimed source %v", errorPrefix, pkt.RemoteTP, srcTP)
	}

	// check if transfer is allowed
	dests, ok := m.transfers[srcZone]
	if !ok {
		return zoning.NilPacket, fmt.Errorf("%v no transfer rules found for source zone %v", errorPrefix, srcZone)
	}
	for _, dest := range dests {
		if destZone == dest {
			return pkt, nil
		}
	}
	return zoning.NilPacket, fmt.Errorf("%v transfer from zone %v to zone %v not allowed", errorPrefix, srcZone, destZone)
}

func (m *Module) handleEgress(pkt zoning.Packet) (zoning.Packet, error) {
	// get reader lock in case data is currently being refreshed
	m.lock.RLock()
	defer m.lock.RUnlock()
	// get zones for src/dest
	srcZone, _, err := m.findZone(pkt.SrcHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v error finding source zone: %v", errorPrefix, err)
	}
	destZone, dstTP, err := m.findZone(pkt.DstHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v error finding destination zone: %v", errorPrefix, err)
	}
	pkt.RemoteTP = dstTP
	pkt.DstZone = uint32(destZone)

	// check if transfer is allowed
	dests, ok := m.transfers[srcZone]
	if !ok {
		return zoning.NilPacket, fmt.Errorf("%v no transfer rules found for source zone %v", errorPrefix, srcZone)
	}
	for _, dest := range dests {
		if destZone == dest {
			return pkt, nil
		}
	}
	return zoning.NilPacket, fmt.Errorf("%v transfer from zone %v to zone %v not allowed", errorPrefix, srcZone, destZone)
}

func (m *Module) findZone(ip net.IP) (types.ZoneID, string, error) {
	res, err := m.ranger.ContainingNetworks(ip)
	if err != nil {
		return 0, "", err
	}
	//return 0, "", fmt.Errorf("no matching zone found for IP %v", ip)
	if len(res) != 1 {
		return 0, "", fmt.Errorf("found %d subnets containing IP %v", len(res), ip)
	}
	return res[0].(*types.Subnet).ZoneID, res[0].(*types.Subnet).TPAddr, nil
}

// StartFetcher starts the periodic fetcher assigned to the transfer module
func (m *Module) StartFetcher() {
	// start periodic task fetching info from controller
	ticker := time.NewTicker(m.cfg.RefrehInterval.Duration)
	var err error
	subnets, err := m.fetcher.FetchSubnets()
	if err != nil {
		fatal.Fatal(fmt.Errorf("%v Failed to fetch initial subnets data from controller: %v", errorPrefix, err))
	}
	transfers, err := m.fetcher.FetchTransfers()
	if err != nil {
		fatal.Fatal(fmt.Errorf("%v Failed to fetch initial transfer data from controller: %v", errorPrefix, err))
	}
	m.setInfo(subnets, transfers)
	go func() {
		for range ticker.C {
			subnets, err := m.fetcher.FetchSubnets()
			// TODO: handle errors where info cannot be updated (use LogFatal?)
			// e.g. by having a deadline timer after which we stop using stalled info. deadline timer is reset after every successful fetch
			if err != nil {
				fatal.Fatal(err)
			}
			transfers, err := m.fetcher.FetchTransfers()
			if err != nil {
				fatal.Fatal(err)
			}

			m.setInfo(subnets, transfers)
		}
	}()
}

func (m *Module) setInfo(nets types.Subnets, transfers types.Transfers) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, net := range nets {
		m.ranger.Insert(net)
	}
	m.transfers = transfers

}

/* func (m *Module) fetchInfo() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// TODO: make an API package and read routes from there
	resp, err := m.client.Post(fmt.Sprintf("https://%s/api/get-subnets", m.controllerAddr), "text/plain", strings.NewReader(m.localAddr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&m.subnets)
	if err != nil {
		return err
	}

	resp, err = m.client.Post(fmt.Sprintf("https://%s/api/get-transfers", m.controllerAddr), "text/plain", strings.NewReader(m.localAddr))
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
} */
