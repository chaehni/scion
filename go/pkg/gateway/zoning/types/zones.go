package types

import (
	"encoding/json"
	"net"
)

// ZoneID represents 24bit zone identifiers
// TODO: possible check to make sure IDs are always in the range [0, 1<<24-1]
type ZoneID uint

// Zone denotes a network zone
type Zone struct {
	ID   ZoneID
	Name string
	//	Subnets []*Subnet
}

// Site denotes a branch site of the network
type Site struct {
	TPAddr string
	Name   string
}

// Subnet is an IP subnet that is located behind a TP
type Subnet struct {
	IPNet  net.IPNet
	ZoneID ZoneID
	TPAddr string
}

func (s Subnet) MarshalJSON() ([]byte, error) {
	dummy := struct {
		CIDR   string
		ZoneID ZoneID
		TPAddr string
	}{
		CIDR:   s.IPNet.String(),
		ZoneID: s.ZoneID,
		TPAddr: s.TPAddr,
	}

	return json.Marshal(dummy)
}

func (s *Subnet) UnmarshalJSON(b []byte) error {
	dummy := struct {
		CIDR   string
		ZoneID ZoneID
		TPAddr string
	}{}
	err := json.Unmarshal(b, &dummy)
	if err != nil {
		return err
	}
	_, net, err := net.ParseCIDR(dummy.CIDR)
	if err != nil {
		return err
	}
	s.IPNet = *net
	s.ZoneID = dummy.ZoneID
	s.TPAddr = dummy.TPAddr
	return nil
}

// Transitions maps a zone ID to all Zone IDs to which it is allowed to send data
type Transitions map[ZoneID][]ZoneID

// Network implements the RangerEntry interface for use with github.com/yl2chen/cidranger
func (s *Subnet) Network() net.IPNet {
	return s.IPNet
}

// Subnets is a list of IP subnets
type Subnets []*Subnet
