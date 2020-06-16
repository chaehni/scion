package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/addr"

	"github.com/dchest/cmac"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
)

var keyLength = 128
var keyTTL = 24 * time.Hour

// keyManager implements a thread-safe store managing L0 and L1 keys
type keyManager interface {
	getL0Key() (*Key, error)
	fetchL1Key(remote *snet.UDPAddr) (*Key, error)
	deriveL1Key(remote *snet.UDPAddr) (*Key, error)
}

var _ = keyManager(&keyMan{})

// Key is exported so that it can be seen by the json package for (Un)marshaling
type Key struct {
	Key []byte
	TTL time.Time
}

// keyMan implements keyManager
type keyMan struct {
	// represents the l0 key, clients should never directly access this key
	// instead they should use the getL0Key() function
	l0           *Key
	l0Lock       sync.RWMutex
	keyCache     map[snet.UDPAddr]*Key // TODO: in case of poor performance replace this with a sync.Map
	keyCacheLock sync.RWMutex
	//sciond         string
	localAddr      snet.UDPAddr
	tlsServerConf  *tls.Config
	tlsClientrConf *tls.Config
	SCIONNet       *snet.SCIONNetwork
}

func (km *keyMan) getL0Key() (*Key, error) {
	// create new key in case we don't have a key yet or current key has expired
	if km.l0 == nil || km.l0.TTL.After(time.Now()) {
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

func (km *keyMan) refreshL0() error {
	km.l0Lock.Lock()
	defer km.l0Lock.Unlock()
	// check again if key indeed is missing or expired in case multiple goroutines entered the function
	if km.l0 != nil && km.l0.TTL.Before(time.Now()) {
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

func (km *keyMan) fetchL1Key(remote *snet.UDPAddr) (*Key, error) {
	// fetch key in case it is missing or has expired
	k, ok := km.keyCache[*remote]
	if !ok || k.TTL.After(time.Now()) {
		err := km.fetchL1FromRemote(remote)
		if err != nil {
			return nil, err
		}
	}
	km.keyCacheLock.RLock()
	defer km.keyCacheLock.RUnlock()
	l1 := km.keyCache[*remote]
	key := make([]byte, keyLength)
	copy(key, l1.Key)
	return &Key{Key: key, TTL: l1.TTL}, nil
}

func (km *keyMan) fetchL1FromRemote(remote *snet.UDPAddr) error {
	km.keyCacheLock.Lock()
	defer km.keyCacheLock.Unlock()
	// check again if key indeed is missing or is expired in case multiple goroutines entered the function
	k, ok := km.keyCache[*remote]
	if ok && k.TTL.Before(time.Now()) {
		return nil
	}

	// set up connection
	/* ds := reliable.NewDispatcher("")
	sciondConn, err := sciond.NewService("").Connect(context.Background())
	if err != nil {
		return err
	}
	localIA, err := sciondConn.LocalIA(context.Background())
	if err != nil {
		return err
	}
	pathQuerier := sciond.Querier{Connector: sciondConn, IA: localIA}
	network := snet.NewNetworkWithPR(localIA, ds, pathQuerier, sciond.RevHandler{Connector: sciondConn})
	if err != nil {
		return err
	}
	err = squic.Init("", "")
	if err != nil {
		return err
	} */
	sess, err := squic.Dial(km.SCIONNet, km.localAddr.Host, remote, addr.SvcNone, nil)
	if err != nil {
		return err
	}
	defer sess.Close()
	stream, err := sess.OpenStreamSync()
	if err != nil {
		return err
	}
	defer stream.Close()

	// fetch key
	var b bytes.Buffer
	_, err = io.Copy(&b, stream)
	if err != nil {
		return err
	}
	var l1 Key
	json.Unmarshal(b.Bytes(), &l1)
	if err != nil {
		return err
	}
	km.keyCache[*remote] = &l1
	return nil
}

func (km *keyMan) deriveL1Key(remote *snet.UDPAddr) (*Key, error) {
	l0, err := km.getL0Key()
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
	io.WriteString(mac, remote.String())
	return &Key{Key: mac.Sum(nil), TTL: l0.TTL}, nil
}

func (km *keyMan) serveL1() error {
	l, err := squic.Listen(km.SCIONNet, km.localAddr.Host, addr.SvcNone, nil)
	if err != nil {
		return err
	}
	for {
		sess, err := l.Accept()
		if err != nil {
			log.Warn("[AuthModule Listener] failed to accept incoming session %v", err)
		}
		go func(sess quic.Session) {
			defer sess.Close()
			stream, err := sess.AcceptStream()
			if err != nil {
				log.Warn("[AuthModule Listener] failed accetp incoming stream %v", err)
			}
			defer stream.Close()

			// derive the L1 Key
			remoteAddr, ok := sess.RemoteAddr().(*snet.UDPAddr)
			if !ok {
				log.Warn("[AuthModule Listener] failed assert remote UDPAddr: %v", err)
			}
			l1, err := km.deriveL1Key(remoteAddr)
			if err != nil {
				log.Warn("[AuthModule] failed to derive L1 key: %v", err)
			}
			// write key with timestamp to conn
			enc, err := json.Marshal(l1)
			if err != nil {
				log.Warn("[AuthModule] failed marshal L1 key: %v", err)
			}
			stream.Write(enc)
		}(sess)
	}
}

/* func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...), nil
} */
