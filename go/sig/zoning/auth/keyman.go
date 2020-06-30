package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"

	"github.com/lucas-clemente/quic-go"
	"github.com/patrickmn/go-cache"
	"github.com/scionproto/scion/go/lib/addr"
	"golang.org/x/crypto/pbkdf2"
)

// Init initializes the auth package
func Init() {
	fatal.Check()
}

// TODO make these values customizable by passing them as input to keymanager
var keyLength = 16
var keyTTL = 24 * time.Hour
var keyPurgeInterval = 24 * time.Hour
var l0Salt = []byte("L0 Salt value")
var serverPort = 9090

// KeyPld is the payload sent to other ZTPs carrying the key
type KeyPld struct {
	Key []byte
	TTL time.Time
}

var _ = KeyManager(&KeyMan{})

// KeyMan implements KeyManager interface
type KeyMan struct {
	ms       []byte
	l0       []byte
	l0TTL    time.Time
	l0Lock   sync.RWMutex
	keyCache *cache.Cache
	scionNet *snet.SCIONNetwork
	querier  *sciond.Querier
	listenIP net.IP
	reqLock  sync.Mutex
}

// NewKeyMan creates a new Keyman
func NewKeyMan(masterSecret []byte, scionNet *snet.SCIONNetwork, querier *sciond.Querier, listenIP net.IP) *KeyMan {
	return &KeyMan{
		ms:       masterSecret,
		keyCache: cache.New(cache.NoExpiration, keyPurgeInterval),
		scionNet: scionNet,
		querier:  querier,
		listenIP: listenIP,
	}
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
	defer km.l0Lock.RUnlock()
	k := make([]byte, keyLength)
	copy(k, km.l0)
	return k, km.l0TTL, nil
}

func (km *KeyMan) refreshL0() error {
	km.l0Lock.Lock()
	defer km.l0Lock.Unlock()
	// check again if key indeed is missing or expired in case multiple goroutines entered the function
	if km.l0 != nil && km.l0TTL.After(time.Now()) {
		return nil
	}

	if len(km.ms) == 0 {
		return errors.New("master secret cannot be empty")
	}
	key := pbkdf2.Key(km.ms, l0Salt, 1000, 12, sha256.New)
	km.l0 = key
	km.l0TTL = time.Now().Add(keyTTL)
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
	_, t, ok := km.keyCache.GetWithExpiration(remote)
	if !ok || t.Before(time.Now()) {
		fresh, err = km.fetchL1FromRemote(remote)
		if err != nil {
			return nil, false, err
		}
	}
	x, ok := km.keyCache.Get(remote)
	if !ok {
		return nil, false, errors.New("fetching key failed") // Should never happen, we just fetched it
	}
	l1 := x.([]byte)
	key := make([]byte, keyLength)
	copy(key, l1)
	return key, fresh, nil
}

func (km *KeyMan) fetchL1FromRemote(remote string) (bool, error) {
	//TODO: this lock is bad because it serializes all requests, not just the ones going to the same destination
	km.reqLock.Lock()
	defer km.reqLock.Unlock()

	// check if in the meantime another goroutine successfully fetched the key
	_, t, ok := km.keyCache.GetWithExpiration(remote)
	if ok && t.After(time.Now()) {
		return false, nil
	}

	remoteCpy, err := snet.ParseUDPAddr(remote)
	if err != nil {
		return false, err
	}
	remoteCpy.Host.Port = serverPort
	paths, err := km.querier.Query(context.Background(), remoteCpy.IA)
	if err != nil {
		return false, err
	}
	if len(paths) == 0 {
		return false, fmt.Errorf("no paths found for remote %v", remote)
	}
	remoteCpy.Path = paths[0].Path()
	remoteCpy.NextHop = paths[0].OverlayNextHop()

	listen := &net.UDPAddr{IP: km.listenIP, Port: 0}
	sess, err := squic.Dial(km.scionNet, listen, remoteCpy, addr.SvcNone, nil)
	if err != nil {
		return false, err
	}
	defer sess.Close()
	stream, err := sess.OpenStreamSync()
	if err != nil {
		return false, err
	}
	defer stream.Close()

	io.WriteString(stream, "get-key")
	if err != nil {
		return false, err
	}

	// fetch key
	var l1 KeyPld
	decoder := json.NewDecoder(stream)
	decoder.Decode(&l1)
	if err != nil {
		return false, err
	}

	// check if we indeed got a valid key
	if len(l1.Key) != keyLength {
		return false, fmt.Errorf("fetched key has invalid length %d", len(l1.Key))
	}
	if l1.TTL.Before(time.Now()) {
		return false, errors.New("fetched key is expired")
	}
	log.Debug("[AuthModule Fetcher] successfully fetched L1 key from", "remote", remote)

	// set key with TTL
	km.keyCache.Set(remote, l1.Key, l1.TTL.Sub(time.Now()))
	return true, nil
}

// DeriveL1Key derives the Level-1 key used to verify incoming traffic
func (km *KeyMan) DeriveL1Key(remote string) ([]byte, error) {
	k, _, err := km.deriveL1Key(remote)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (km *KeyMan) deriveL1Key(remote string) ([]byte, time.Time, error) {
	l0, t, err := km.getL0Key()
	if err != nil {
		return nil, time.Time{}, err
	}
	mac, err := initMac(l0)
	if err != nil {
		return nil, time.Time{}, err
	}
	io.WriteString(mac, remote)
	return mac.Sum(nil), t, nil
}

// ServeL1 starts a server handling incoming Level-1 key requests
func (km *KeyMan) ServeL1() {
	go func() {
		err := km.serveL1()
		fatal.Fatal(err)
	}()
}

func (km *KeyMan) serveL1() error {
	l, err := squic.Listen(km.scionNet, &net.UDPAddr{IP: km.listenIP, Port: serverPort}, addr.SvcNone, nil)
	if err != nil {
		return err
	}
	for {
		sess, err := l.Accept()
		if err != nil {
			log.Warn("[AuthModule Listener] failed to accept incoming session", "err", err)
		}
		go func(sess quic.Session) {
			defer sess.Close()
			stream, err := sess.AcceptStream()
			if err != nil {
				log.Warn("[AuthModule Listener] failed accetp incoming stream", "err", err)
				return
			}
			defer stream.Close()

			remoteAddr, ok := sess.RemoteAddr().(*snet.UDPAddr)
			if !ok {
				log.Warn("[AuthModule Listener] failed assert remote UDPAddr", "err", err)
				return
			}

			log.Debug("[AuthModule Listener] L1 key request from", "remote", remoteAddr)

			// derive L1 key
			k, t, err := km.deriveL1Key(udpAddrToString(remoteAddr))
			if err != nil {
				log.Warn("[AuthModule] failed to derive L1 key", "err", err)
				return
			}

			pld := KeyPld{
				Key: k,
				TTL: t,
			}

			// write key with timestamp to conn
			enc, err := json.Marshal(pld)
			if err != nil {
				log.Warn("[AuthModule] failed marshal L1 key", "err", err)
				return
			}
			n, err := stream.Write(enc)
			if err != nil {
				log.Warn("[AuthModule] failed write key", "err", err, "bytes written", n)
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
