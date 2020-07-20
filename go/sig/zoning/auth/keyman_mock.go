package auth

import (
	"encoding/binary"
)

var _ = KeyManager(&MockKeyMan{})

// MockKeyMan wraps a KeyManager for testing purposes
type MockKeyMan struct {
	km    KeyManager
	l1map map[string][]byte
}

// NewMockKeyMan creates a new NewMockKeyMan
func NewMockKeyMan(km KeyManager) *MockKeyMan {
	return &MockKeyMan{
		km: km,
	}
}

// FetchL1Key fetches the Level-1 key used to send traffic to a remote ZTP.
// In case the key is not cached or expired it is fetched from remote.
func (km *MockKeyMan) FetchL1Key(remote string) ([]byte, bool, error) {
	l1, err := km.km.DeriveL1Key(remote)
	if err != nil {
		return nil, false, err
	}
	return l1, false, nil
}

// FetchL2Key fetches the Level-2 key used to encrypt outgoing traffic
func (km *MockKeyMan) FetchL2Key(remote string, zone uint32) ([]byte, bool, error) {
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

// DeriveL1Key derives the Level-1 key used to derive the L2 key
func (km *MockKeyMan) DeriveL1Key(remote string) ([]byte, error) {
	return km.km.DeriveL1Key(remote)
}

// DeriveL2Key derives the Level-2 key used to verify incoming traffic
func (km *MockKeyMan) DeriveL2Key(remote string, zone uint32) ([]byte, error) {
	return km.km.DeriveL2Key(remote, zone)
}

// ServeL1 starts a server handling incoming Level-1 key requests
func (km *MockKeyMan) ServeL1() {
	// no-op
}
