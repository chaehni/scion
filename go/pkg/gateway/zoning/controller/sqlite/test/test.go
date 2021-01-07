package main

import (
	"encoding/json"
	"fmt"
	"net"

	_ "github.com/mattn/go-sqlite3"
	"github.com/scionproto/scion/go/sig/zoning/controller/sqlite"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

func main() {

	db, err := sqlite.New(":memory:")
	if err != nil {
		panic(err)
	}

	err = db.InsertZone(1, "test")
	if err != nil {
		panic(err)
	}

	err = db.InsertZone(345, "other")
	if err != nil {
		panic(err)
	}

	err = db.InsertSite("17-ffaa:0:87,8.8.9.8", "Main DC")
	if err != nil {
		panic(err)
	}

	err = db.InsertSubnet(1, net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}, "17-ffaa:0:87,8.8.9.8")
	if err != nil {
		panic(err)
	}
	err = db.InsertSubnet(345, net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.IPv4Mask(255, 0, 255, 0)}, "17-ffaa:0:87,8.8.9.8")
	if err != nil {
		panic(err)
	}

	// transitions
	t := types.Transitions{
		1:   {1, 345},
		345: {345, 1},
	}

	err = db.InsertTransitions(t)
	if err != nil {
		panic(err)
	}

	// delete zone
	/* err = db.DeleteZone(1)
	if err != nil {
		panic(err)
	} */

	// delete transitions
	err = db.DeleteTransitions(t)
	if err != nil {
		panic(err)
	}

	nets, err := db.GetSubnets("17-ffaa:0:87,8.8.9.8")
	if err != nil {
		panic(err)
	}
	fmt.Println((nets))
	b, err := json.Marshal(nets)
	fmt.Println(string(b))
}
