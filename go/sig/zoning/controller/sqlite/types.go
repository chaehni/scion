package sqlite

import "net"

// Transfer maps a zone ID to all Zone IDs to which it is allowed to send data
type Transfer map[int][]int

// Zone denotes a network zone
type Zone struct {
	ID      int
	Name    string
	Subnets []*Subnet
}

// Site denotes a branch site of the network
type Site struct {
	TPAddr net.IP
}

// Subnet is an IP subnet that is located behind a TP
type Subnet struct {
	//Zone   int // not needed as it lives inside a Zone struct
	IPNet  net.IPNet
	TPAddr net.IP
}
