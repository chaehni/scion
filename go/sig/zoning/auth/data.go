package auth

import "net"

// Transfer maps a zone ID to all Zone IDs to which it is allowed to send data
type Transfer struct {
	ZoneID   int
	DstZones []Zone
}

// Zone denotes a network zone
type Zone struct {
	ID      int
	Name    string
	Subnets []Subnet
}

type Site struct {
	TPAddr net.IP
}

type Subnet struct {
	//Zone int
	Net  net.IPNet
	Site Site
}
