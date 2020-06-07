package types

import "net"

// ZoneID represents 24bit zone identifiers
// TODO: possible check to make sure IDs are always in the range [0, 1<<24-1]
type ZoneID int

// Transfers maps a zone ID to all Zone IDs to which it is allowed to send data
type Transfers map[ZoneID][]ZoneID

// Zone denotes a network zone
type Zone struct {
	ID      ZoneID
	Name    string
	Subnets []*Subnet
}

// Site denotes a branch site of the network
type Site struct {
	TPAddr net.IP
}

// Subnet is an IP subnet that is located behind a TP
type Subnet struct {
	IPNet  net.IPNet
	ZoneID ZoneID
	TPAddr net.IP
}

// Subnets is a list of IP subnets
type Subnets []*Subnet
