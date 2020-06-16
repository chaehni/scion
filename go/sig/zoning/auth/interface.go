package auth

// KeyManager is a thread-safe key store managing L0 and L1 keys
type KeyManager interface {
	GetL0Key() ([]byte, error)
	FetchL1Key(remote string) ([]byte, error)
	DeriveL1Key(remote string) ([]byte, error)
}

// Transformer transforms IP packets to and from intermediate representation
type Transformer interface {
	ToIR(packet, additionalData []byte) ([]byte, error)
	FromIR(message []byte) (additionalData []byte, packet []byte, err error)
}
