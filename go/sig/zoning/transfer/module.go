package transfer

import (
	"crypto/tls"

	"fmt"
	"log"
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

//var dummyErr = errors.New("dummy")
var errorPrefix = "[TransferModule]"

var _ = zoning.Module(&Module{})

// Module implements the transfer module.
// It checks packets for valid zone transfers.
type Module struct {
	//subnets   types.Subnets
	cfg    tpconfig.TransConf
	ranger cidranger.Ranger
	//transfers types.Transfers
	transfers map[types.ZoneID]map[types.ZoneID]struct{}
	client    *http.Client

	fetcher Fetcher

	lock sync.RWMutex
}

// NewModule creates a new Transfer Module
func NewModule(fetcher Fetcher, cfg tpconfig.TransConf) *Module {

	return &Module{
		cfg:       cfg,
		ranger:    cidranger.NewPCTrieRanger(),
		transfers: make(map[types.ZoneID]map[types.ZoneID]struct{}),
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
		return zoning.NilPacket, fmt.Errorf("%v source TP %v is not responsible for claimed source %v", errorPrefix, pkt.RemoteTP, pkt.SrcHost)
	}

	// check if transfer is allowed
	err = m.checkTransfer(srcZone, destZone)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v %v", errorPrefix, err)
	}
	return pkt, nil
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
	err = m.checkTransfer(srcZone, destZone)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v %v", errorPrefix, err)
	}
	return pkt, nil
}

func (m *Module) findZone(ip net.IP) (types.ZoneID, string, error) {
	res, err := m.ranger.ContainingNetworks(ip)
	if err != nil {
		return 0, "", err
	}
	if len(res) != 1 {
		return 0, "", fmt.Errorf("found %d subnets containing IP %v", len(res), ip)
	}
	subnet := res[0].(*types.Subnet)
	return subnet.ZoneID, subnet.TPAddr, nil
	//return 0, "", dummyErr
}

func (m *Module) checkTransfer(from, to types.ZoneID) error {
	outer, ok := m.transfers[from]
	if !ok {
		return fmt.Errorf("%v no transfer rules found for source zone %v", errorPrefix, from)
	}
	_, ok = outer[to]
	if !ok {
		return fmt.Errorf("%v transfer from zone %v to zone %v not allowed", errorPrefix, from, to)
	}
	return nil
}

// StartFetcher starts the periodic fetcher assigned to the transfer module
func (m *Module) StartFetcher() {
	// start periodic task fetching info from controller
	ticker := time.NewTicker(m.cfg.RefrehInterval.Duration)
	var err error
	subnets, err := m.fetcher.FetchSubnets()
	if err != nil {
		log.Fatal(fmt.Errorf("%v Failed to fetch initial subnets data from controller: %v", errorPrefix, err))
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
	for outer, slice := range transfers {
		if m.transfers[outer] == nil {
			m.transfers[outer] = make(map[types.ZoneID]struct{})
		}
		for _, inner := range slice {
			m.transfers[outer][inner] = struct{}{}
		}
	}
	//m.transfers = transfers

}
