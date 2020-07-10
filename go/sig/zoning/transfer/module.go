package transfer

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/sig/zoning"
	"github.com/scionproto/scion/go/sig/zoning/tpconfig"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

var errorPrefix = "[TransferModule]"

// Module implements the transfer module.
// It checks packets for valid zone transfers.
type Module struct {
	subnets   types.Subnets
	transfers types.Transfers
	client    *http.Client
	// TODO: local address is sent to the controller to identify the right TP
	// This is hack, the controller should read the remote address itself but
	// the dumbed down shttp package doesn't allow to set the local address on the client side
	// instead it always uses 127.0.0.1
	localAddr      string
	controllerAddr string
	lock           sync.RWMutex
}

// New creates a new Transfer Module
func New(ia addr.IA, ip net.IP, cfg tpconfig.TransConf) (*Module, error) {

	mod := &Module{
		client: &http.Client{
			Transport: shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil),
		},
		localAddr:      fmt.Sprintf("%v,%v", ia, ip),
		controllerAddr: cfg.ControllerAddr,
	}

	// start periodic task fetching info from controller
	ticker := time.NewTicker(cfg.RefrehInterval.Duration)
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
		return zoning.NilPacket, fmt.Errorf("%v find source zone: %v", errorPrefix, err)
	}
	destZone, _, err := m.findZone(pkt.DstHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v find destination zone: %v", errorPrefix, err)
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
		return zoning.NilPacket, fmt.Errorf("%v find source zone: %v", errorPrefix, err)
	}
	destZone, dstTP, err := m.findZone(pkt.DstHost)
	if err != nil {
		return zoning.NilPacket, fmt.Errorf("%v find destination zone: %v", errorPrefix, err)
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
}
