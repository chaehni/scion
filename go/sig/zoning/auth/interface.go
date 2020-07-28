package auth

// KeyManager is a thread-safe key store managing L0 and L1 keys
type KeyManager interface {
	// FetchL1Key fetches the level 1 key to be used to send data to remote.
	// It returns the key and a bool indicating if the key cached key has exoured and a fresh key
	// has been fetched from remote.
	FetchL1Key(remote string) ([]byte, bool, error)
	// FetchL2Key fetches the Level-2 key used to encrypt outgoing traffic
	FetchL2Key(remote string, zone uint32) ([]byte, bool, error)
	// Derive L1Key derives the level 1 key used to derive the L2 key.
	DeriveL1Key(remote string) ([]byte, error)
	// Derive L2Key derives the level 2 key used to verify incoming traffic.
	DeriveL2Key(remote string, zone uint32) ([]byte, error)
}

// Transformer transforms IP packets to and from intermediate representation
type Transformer interface {
	ToIR(remote string, key, packet []byte, dstZone uint32) ([]byte, error)
	FromIR(key, cipher []byte) (additionalData []byte, packet []byte, err error)
	ResetState(remote string) error
	GetZone(message []byte) (uint32, error)
}
