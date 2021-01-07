package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/gateway/zoning/tpconfig"

	"github.com/lucas-clemente/quic-go"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/pbkdf2"
)

// Init initializes the auth package
func Init() {
	fatal.Check()
}

var l0Salt = []byte("L0 Salt value")

// KeyPld is the payload sent to other ZTPs carrying the key and the key expiration time
type keyPld struct {
	key []byte
	ttl time.Time
}

func (k keyPld) MarshalJSON() ([]byte, error) {
	dummy := struct {
		Key []byte
		TTL time.Time
	}{
		k.key,
		k.ttl,
	}
	return json.Marshal(dummy)
}

func (k *keyPld) UnmarshalJSON(b []byte) error {
	var dummy struct {
		Key []byte
		TTL time.Time
	}
	err := json.Unmarshal(b, &dummy)
	k.key = dummy.Key
	k.ttl = dummy.TTL
	return err
}

var _ = KeyManager(&KeyMan{})

// KeyMan implements KeyManager interface
type KeyMan struct {
	keyLength        int
	keyTTL           time.Duration
	keyPurgeInterval time.Duration

	ms         []byte
	l0         []byte
	l0TTL      time.Time
	l0Lock     sync.RWMutex
	keyCache   *cache.Cache
	scionNet   *snet.SCIONNetwork
	querier    *sciond.Querier
	listenIP   net.IP
	listenPort int
	reqLock    sync.Mutex

	mac hash.Hash
}

// NewKeyMan creates a new Keyman
func NewKeyMan(masterSecret []byte, listenIP net.IP, cfg tpconfig.AuthConf, test bool) *KeyMan {

	var network *snet.SCIONNetwork
	var pathQuerier *sciond.Querier
	if !test {
		ds := reliable.NewDispatcher("")
		sciondConn, err := sciond.NewService(sciond.DefaultAPIAddress).Connect(context.Background())
		if err != nil {
			fmt.Println(err)
		}
		localIA, err := sciondConn.LocalIA(context.Background())
		if err != nil {
			fmt.Println(err)
		}
		pathQuerier = &sciond.Querier{Connector: sciondConn, IA: localIA}
		network = snet.NewNetwork(localIA, ds, sciond.RevHandler{Connector: sciondConn})
		//network = snet.NewNetworkWithPR(localIA, ds, pathQuerier, sciond.RevHandler{Connector: sciondConn})
		if err != nil {
			fmt.Println(err)
		}
		err = squic.Init(cfg.Key, cfg.Cert)
		if err != nil {
			panic(err)
		}
	}

	return &KeyMan{
		keyLength:        cfg.KeyLength,
		keyTTL:           cfg.KeyTTL.Duration,
		keyPurgeInterval: cfg.KeyPurgeInterval.Duration,

		ms:         masterSecret,
		keyCache:   cache.New(cache.NoExpiration, cfg.KeyPurgeInterval.Duration),
		scionNet:   network,
		querier:    pathQuerier,
		listenIP:   listenIP,
		listenPort: cfg.ServerPort,
	}
}

// FillKeyStore fills the key cache with dummy remote TPs but real keys used for testing
func (km *KeyMan) FillKeyStore(n int) error {
	for i := 0; i < n; i++ {
		remote := fmt.Sprintf("%016x", i)
		l1, err := km.DeriveL1Key(remote)
		if err != nil {
			return err
		}
		km.keyCache.Set(remote, l1, 24*time.Hour)
	}
	return nil
}

// FillKeyStoreFakeKeys fills the key cache with dummy remote values and keys used for testing
func (km *KeyMan) FillKeyStoreFakeKeys(n int) error {
	for i := 0; i < n; i++ {
		remote := fmt.Sprintf("%016x", i)
		l1 := make([]byte, km.keyLength)
		_, err := rand.Read(l1)
		if err != nil {
			return err
		}
		km.keyCache.Set(remote, l1, 24*time.Hour)
	}
	return nil
}

// UpdateMS updates the key manager's master secret
func (km *KeyMan) UpdateMS(masterSecret []byte) {
	km.l0Lock.Lock()
	defer km.l0Lock.Unlock()
	km.ms = masterSecret
}

func (km *KeyMan) getL0Key() ([]byte, time.Time, error) {
	// create new key in case we don't have a key yet or current key has expired
	if km.l0 == nil || km.l0TTL.Before(time.Now()) {
		err := km.refreshL0()
		if err != nil {
			return nil, time.Time{}, err
		}
	}

	km.l0Lock.RLock()
	k := make([]byte, km.keyLength)
	copy(k, km.l0)
	km.l0Lock.RUnlock()
	return k, km.l0TTL, nil
}

func (km *KeyMan) refreshL0() error {
	km.l0Lock.Lock()
	// check again if key indeed is missing or expired in case multiple goroutines entered the function
	if km.l0 != nil && km.l0TTL.After(time.Now()) {
		return nil
	}

	if len(km.ms) == 0 {
		return errors.New("master secret cannot be empty")
	}
	key := pbkdf2.Key(km.ms, l0Salt, 1000, km.keyLength, sha256.New)
	km.l0 = key
	km.l0TTL = time.Now().Add(km.keyTTL)
	var err error
	km.mac, err = initMac(km.l0)
	if err != nil {
		return err
	}
	km.l0Lock.Unlock()
	return nil
}

// FetchL1Key fetches the Level-1 key used to send traffic to a remote ZTP.
// In case the key is not cached or expired it is fetched from remote.
func (km *KeyMan) FetchL1Key(remote string) ([]byte, bool, error) {
	var fresh = false
	var err error
	if remote == "" {
		return nil, false, errors.New("remote cannot be empty")
	}
	// fetch key in case it is missing or has expired
	x, t, ok := km.keyCache.GetWithExpiration(remote)
	if !ok || t.Before(time.Now()) {
		x, fresh, err = km.fetchL1FromRemote(remote)
		if err != nil {
			return nil, false, err
		}
	}
	l1 := x.([]byte)
	key := make([]byte, km.keyLength)
	copy(key, l1)
	return key, fresh, nil
}

// FetchL2Key fetches the Level-2 key used to encrypt outgoing traffic
func (km *KeyMan) FetchL2Key(remote string, zone uint32) ([]byte, bool, error) {
	l1, fresh, err := km.FetchL1Key(remote)
	if err != nil {
		return nil, false, err
	}
	mac, err := initMac(l1)
	if err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, zone)
	mac.Write(buf[:3])
	return mac.Sum(nil), fresh, nil
}

func (km *KeyMan) DeriveL2ForGivenL1(l1 []byte, remote string, zone uint32) ([]byte, error) {
	mac, err := initMac(l1)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, zone)
	mac.Write(buf[:3])
	return mac.Sum(nil), nil
}

func (km *KeyMan) fetchL1FromRemote(remote string) ([]byte, bool, error) {
	//TODO: this lock is bad because it serializes all requests, not just the ones going to the same destination
	km.reqLock.Lock()
	defer km.reqLock.Unlock()

	// check if in the meantime another goroutine successfully fetched the key
	l1, t, ok := km.keyCache.GetWithExpiration(remote)
	if ok && t.After(time.Now()) {
		return l1.([]byte), false, nil
	}

	remoteCpy, err := snet.ParseUDPAddr(remote)
	if err != nil {
		return nil, false, err
	}
	remoteCpy.Host.Port = km.listenPort
	paths, err := km.querier.Query(context.Background(), remoteCpy.IA)
	if err != nil {
		return nil, false, err
	}
	if len(paths) == 0 {
		return nil, false, fmt.Errorf("no paths found for remote %v", remote)
	}
	remoteCpy.Path = paths[0].Path()
	remoteCpy.NextHop = paths[0].UnderlayNextHop()

	listen := &net.UDPAddr{IP: km.listenIP, Port: 0}
	sess, err := squic.Dial(km.scionNet, listen, remoteCpy, addr.SvcNone, nil)
	if err != nil {
		return nil, false, err
	}
	defer sess.CloseWithError(0, "")
	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		return nil, false, err
	}
	defer stream.Close()

	io.WriteString(stream, "get-key")
	if err != nil {
		return nil, false, err
	}

	// fetch key
	var l1Pld keyPld
	decoder := json.NewDecoder(stream)
	decoder.Decode(&l1Pld)
	if err != nil {
		return nil, false, err
	}

	// check if we indeed got a valid key
	if len(l1Pld.key) != km.keyLength {
		return nil, false, fmt.Errorf("fetched key has invalid length %d", len(l1Pld.key))
	}
	if l1Pld.ttl.Before(time.Now()) {
		return nil, false, errors.New("fetched key is expired")
	}
	log.Debug("[AuthModule Fetcher] successfully fetched L1 key from", "remote", remote)

	// set key with TTL
	km.keyCache.Set(remote, l1Pld.key, l1Pld.ttl.Sub(time.Now()))
	return l1Pld.key, true, nil
}

// DeriveL1Key derives the Level-1 key used to derive the L2 key
func (km *KeyMan) DeriveL1Key(remote string) ([]byte, error) {
	k, _, err := km.deriveL1Key(remote)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (km *KeyMan) deriveL1Key(remote string) ([]byte, time.Time, error) {
	_, t, err := km.getL0Key()
	if err != nil {
		return nil, time.Time{}, err
	}
	io.WriteString(km.mac, remote)
	sum := km.mac.Sum(nil)
	km.mac.Reset()
	return sum, t, nil
}

// DeriveL2Key derives the Level-2 key used to verify incoming traffic
func (km *KeyMan) DeriveL2Key(remote string, zone uint32) ([]byte, error) {
	l1, _, err := km.deriveL1Key(remote)
	if err != nil {
		return nil, err
	}
	mac, err := initMac(l1)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, zone)
	mac.Write(buf[:3])
	return mac.Sum(nil), nil
}

// ServeL1 starts a server handling incoming Level-1 key requests
func (km *KeyMan) ServeL1() {
	go func() {
		err := km.serveL1()
		fatal.Fatal(err)
	}()
}

func (km *KeyMan) serveL1() error {
	logger := log.FromCtx(context.Background())
	l, err := squic.Listen(km.scionNet, &net.UDPAddr{IP: km.listenIP, Port: km.listenPort}, addr.SvcNone, nil)
	if err != nil {
		return err
	}
	for {
		sess, err := l.Accept(context.Background())
		if err != nil {
			logger.Error("[AuthModule Listener] failed to accept incoming session", "err", err)
		}
		go func(sess quic.Session) {
			defer sess.CloseWithError(0, "")
			stream, err := sess.AcceptStream(context.Background())
			if err != nil {
				logger.Error("[AuthModule Listener] failed accetp incoming stream", "err", err)
				return
			}
			defer stream.Close()

			remoteAddr, ok := sess.RemoteAddr().(*snet.UDPAddr)
			if !ok {
				logger.Error("[AuthModule Listener] failed assert remote UDPAddr", "err", err)
				return
			}

			logger.Debug("[AuthModule Listener] L1 key request from", "remote", remoteAddr)

			// derive L1 key
			k, t, err := km.deriveL1Key(udpAddrToString(remoteAddr))
			if err != nil {
				logger.Error("[AuthModule] failed to derive L1 key", "err", err)
				return
			}

			pld := keyPld{
				key: k,
				ttl: t,
			}

			// write key with timestamp to conn
			enc, err := json.Marshal(pld)
			if err != nil {
				logger.Error("[AuthModule] failed marshal L1 key", "err", err)
				return
			}
			n, err := stream.Write(enc)
			if err != nil {
				logger.Error("[AuthModule] failed write key", "err", err, "bytes written", n)
				return
			}
			// wait for peer to close session
			ioutil.ReadAll(stream)
		}(sess)
	}
}

func udpAddrToString(addr *snet.UDPAddr) string {
	return fmt.Sprintf("%s,%s", addr.IA, addr.Host.IP)
}
