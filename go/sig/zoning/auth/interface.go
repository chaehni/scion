package auth

import (
	"github.com/scionproto/scion/go/lib/snet"
)

// KeyManager is a thread-safe key store managing L0 and L1 keys
type KeyManager interface {
	// FetchL1Key fetches the level 1 key to be used to send data to remote.
	// It returns the key and a bool indicating if the key cached key has exoured and a fresh key
	// has been fetched from remote.
	FetchL1Key(remote *snet.UDPAddr) ([]byte, bool, error)
	// Derive L1Key derives the level 1 key to be used to verify incoming traffic.
	DeriveL1Key(remote *snet.UDPAddr) ([]byte, error)
}

// Transformer transforms IP packets to and from intermediate representation
type Transformer interface {
	ToIR(packet, additionalData []byte) ([]byte, error)
	FromIR(message []byte) (additionalData []byte, packet []byte, err error)
}
