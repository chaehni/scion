package transition

import (
	"crypto/tls"
	"io"

	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/shttp"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/pkg/gateway/zoning"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/tpconfig"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/types"

	"github.com/patrickmn/go-cache"
	"github.com/yl2chen/cidranger"
)

// Init initializes the transition package
func Init() {
	fatal.Check()
}

//var dummyErr = errors.New("dummy")
var errorPrefix = "[TransitionModule]"

var _ = zoning.Module(&Module{})

// Module implements the transition module.
// It checks packets for valid zone transitions.
type Module struct {
	//subnets   types.Subnets
	cfg    tpconfig.TransConf
	ranger cidranger.Ranger
	//transitions types.Transitions
	transitions map[types.ZoneID]map[types.ZoneID]struct{}
	client      *http.Client

	fetcher Fetcher

	tunnel io.ReadWriteCloser

	lock sync.RWMutex

	cache *cache.Cache
}

// NewModule creates a new Transition Module
func NewModule(fetcher Fetcher, cfg tpconfig.TransConf, tunnelIO io.ReadWriteCloser) *Module {

	return &Module{
		cfg:         cfg,
		ranger:      cidranger.NewPCTrieRanger(),
		transitions: make(map[types.ZoneID]map[types.ZoneID]struct{}),
		client: &http.Client{
			Transport: shttp.NewRoundTripper(&tls.Config{InsecureSkipVerify: true}, nil),
		},
		fetcher: fetcher,
		tunnel:  tunnelIO,
		cache:   cache.New(2*time.Second, 10*time.Minute),
	}
}

// Handle checks packets for valid zone transitions
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

	// check if transition is allowed
	err = m.checkTransition(srcZone, destZone)
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

	// check if established
	established := false
	cachedDst, ok := m.cache.Get(pkt.DstHost.String())
	if ok && cachedDst.(string) == pkt.SrcHost.String() {
		established = true
	}

	// check if transition is allowed
	err = m.checkTransition(srcZone, destZone)
	if err != nil && !established {
		return zoning.NilPacket, fmt.Errorf("%v %v", errorPrefix, err)
	}

	// add to Established cache
	m.cache.Set(pkt.SrcHost.String(), pkt.DstHost.String(), cache.DefaultExpiration)

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

func (m *Module) checkTransition(from, to types.ZoneID) error {
	outer, ok := m.transitions[from]
	if !ok {
		return fmt.Errorf("no transition rules found for source zone %v", from)
	}
	_, ok = outer[to]
	if !ok {
		return fmt.Errorf("transition from zone %v to zone %v not allowed", from, to)
	}
	return nil
}

// StartFetcher starts the periodic fetcher assigned to the transition module
func (m *Module) StartFetcher() {
	// start periodic task fetching info from controller
	ticker := time.NewTicker(m.cfg.RefrehInterval.Duration)
	var err error
	subnets, err := m.fetcher.FetchSubnets()
	if err != nil {
		log.Fatal(fmt.Errorf("%v Failed to fetch initial subnets data from controller: %v", errorPrefix, err))
	}
	transitions, err := m.fetcher.FetchTransitions()
	if err != nil {
		fatal.Fatal(fmt.Errorf("%v Failed to fetch initial transition data from controller: %v", errorPrefix, err))
	}
	m.setInfo(subnets, transitions)
	go func() {
		for range ticker.C {
			subnets, err := m.fetcher.FetchSubnets()
			// TODO: handle errors where info cannot be updated (use LogFatal?)
			// e.g. by having a deadline timer after which we stop using stalled info. deadline timer is reset after every successful fetch
			if err != nil {
				fatal.Fatal(err)
			}
			transitions, err := m.fetcher.FetchTransitions()
			if err != nil {
				fatal.Fatal(err)
			}

			m.setInfo(subnets, transitions)
		}
	}()
}

func (m *Module) setInfo(nets types.Subnets, transitions types.Transitions) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, net := range nets {
		m.ranger.Insert(net)
	}
	for outer, slice := range transitions {
		if m.transitions[outer] == nil {
			m.transitions[outer] = make(map[types.ZoneID]struct{})
		}
		for _, inner := range slice {
			m.transitions[outer][inner] = struct{}{}
		}
	}
	//m.transitions = transitions

}
