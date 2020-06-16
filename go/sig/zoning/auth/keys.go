package auth

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/addr"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
)

var keyLength = 16
var keyTTL = 24 * time.Hour
var errorNoError quic.ErrorCode = 0x100

// KeyManager is a thread-safe key store managing L0 and L1 keys
type KeyManager interface {
	GetL0Key() (*Key, error)
	FetchL1Key(remote string) (*Key, error)
	DeriveL1Key(remote string) (*Key, error)
}

var _ = KeyManager(&KeyMan{})

// Key is exported so that it can be seen by the json package for (Un)marshaling
type Key struct {
	Key []byte
	TTL time.Time
}

// KeyMan implements KeyManager
type KeyMan struct {
	// represents the l0 key, clients should never directly access this key
	// instead they should use the getL0Key() function
	l0           *Key
	l0Lock       sync.RWMutex
	keyCache     map[string]*Key // TODO: in case of poor performance replace this with a sync.Map / replace snet.UPDAddr with snet.SCIONAddress
	keyCacheLock sync.RWMutex
	//keyCacheCond sync.Cond
	//sciond         string
	listenAddr     *snet.UDPAddr
	tlsServerConf  *tls.Config
	tlsClientrConf *tls.Config
	scionNet       *snet.SCIONNetwork
}

func NewKeyMan(scionNet *snet.SCIONNetwork, listenAddr *snet.UDPAddr) *KeyMan {
	return &KeyMan{
		scionNet: scionNet,
		keyCache: make(map[string]*Key),
		//keyCacheCond: sync.Cond{L: &sync.Mutex{}},
		listenAddr: listenAddr,
	}
}

func (km *KeyMan) GetL0Key() (*Key, error) {
	// create new key in case we don't have a key yet or current key has expired
	if km.l0 == nil || km.l0.TTL.Before(time.Now()) {
		err := km.refreshL0()
		if err != nil {
			return nil, err
		}
	}

	km.l0Lock.RLock()
	defer km.l0Lock.RUnlock()
	k := make([]byte, keyLength)
	copy(k, km.l0.Key)
	return &Key{Key: k, TTL: km.l0.TTL}, nil // TODO: not return TTL, clients should not cache the keys themselves
}

func (km *KeyMan) refreshL0() error {
	km.l0Lock.Lock()
	defer km.l0Lock.Unlock()
	// check again if key indeed is missing or expired in case multiple goroutines entered the function
	if km.l0 != nil && km.l0.TTL.After(time.Now()) {
		return nil
	}

	// TODO: derive secret value more securely
	buf := make([]byte, keyLength)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return err
	}
	km.l0 = &Key{Key: buf, TTL: time.Now().Add(keyTTL)}
	return nil
}

func (km *KeyMan) FetchL1Key(remote string) (*Key, error) {
	// fetch key in case it is missing or has expired
	if remote == "" {
		return nil, errors.New("remote cannot be nil")
	}
	k, ok := km.keyCache[remote]
	if !ok || k.TTL.Before(time.Now()) {
		err := km.fetchL1FromRemote(remote)
		if err != nil {
			return nil, err
		}
	}
	km.keyCacheLock.RLock()
	defer km.keyCacheLock.RUnlock()
	l1 := km.keyCache[remote]
	key := make([]byte, keyLength)
	copy(key, l1.Key)
	return &Key{Key: key, TTL: l1.TTL}, nil
}

// TODO: this is bad because it blocks the full keyCache while attempting to fetch one key
// in case the remote doesn't respond all sending/receiving is blocked until the connection times out at which point the next goroutine will try to fetch the key, and so on
func (km *KeyMan) fetchL1FromRemote(remote string) error {

	remoteAddr, err := snet.ParseUDPAddr(remote)
	remoteAddr.Host.Port = 9090
	if err != nil {
		return err
	}
	listen := &net.UDPAddr{IP: km.listenAddr.Host.IP, Port: 0}
	sess, err := squic.Dial(km.scionNet, listen, remoteAddr, addr.SvcNone, nil)
	if err != nil {
		return err
	}
	defer sess.Close()
	stream, err := sess.OpenStreamSync()
	if err != nil {
		return err
	}
	defer stream.Close()

	io.WriteString(stream, "get-key")
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	// fetch key
	var l1 Key
	decoder := json.NewDecoder(stream)
	decoder.Decode(&l1)
	if err != nil {
		return err
	}

	km.keyCacheLock.Lock()
	defer km.keyCacheLock.Unlock()
	k, ok := km.keyCache[remote]
	if ok && k.TTL.After(time.Now()) {
		return nil
	}

	km.keyCache[remote] = &l1
	return nil
}

func (km *KeyMan) DeriveL1Key(remote string) (*Key, error) {
	l0, err := km.GetL0Key()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(l0.Key)
	if err != nil {
		return nil, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, err
	}
	io.WriteString(mac, remote)
	return &Key{Key: mac.Sum(nil), TTL: l0.TTL}, nil
}

func (km *KeyMan) ServeL1() error {
	l, err := squic.Listen(km.scionNet, km.listenAddr.Host, addr.SvcNone, nil)
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
			// Close the stream after writing. Data will be delivered reliably
			// The session will be closed by the client once it reads all the data
			defer stream.Close()

			// derive the L1 Key
			remoteAddr, ok := sess.RemoteAddr().(*snet.UDPAddr)
			if !ok {
				log.Warn("[AuthModule Listener] failed assert remote UDPAddr", "err", err)
				return
			}
			l1, err := km.DeriveL1Key(fmt.Sprintf("%s,%s", remoteAddr.IA, remoteAddr.Host.IP))
			if err != nil {
				log.Warn("[AuthModule] failed to derive L1 key", "err", err)
				return
			}
			// write key with timestamp to conn
			enc, err := json.Marshal(l1)
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
			if err != nil {
				fmt.Println(err)
			}
		}(sess)
	}
}
