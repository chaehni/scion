package main

import (
	"net"

	_ "github.com/mattn/go-sqlite3"
	"github.com/scionproto/scion/go/sig/zoning/controller/sqlite"
)

func main() {

	db, err := sqlite.New(":memory:")
	if err != nil {
		panic(err)
	}

	/* db, _ := sql.Open("sqlite3", ":memory:")

	_, err := db.Exec(`PRAGMA foreign_keys = 1`)
	if err != nil {
		panic(err)
	}

	tx, _ := db.BeginTx(context.Background(), nil)

	_, err = tx.Exec(sqlite.Schema)
	if err != nil {
		panic(err)
	}
	_, err = tx.Exec(`INSERT INTO Sites (tp_address) VALUES ("blob")`)
	if err != nil {
		panic(err)
	}
	_, err = tx.Exec(`INSERT INTO Zones (id) VALUES (5)`)
	if err != nil {
		panic(err)
	}
	tx.Commit()

	tx2, _ := db.BeginTx(context.Background(), nil)

	_, err = tx2.Exec(`INSERT INTO Subnets (zone, net_ip, net_mask, tp_address) VALUES (34, "blob", "blob", "blob")`)
	if err != nil {
		panic(err)
	}
	tx2.Commit() */

	sub := &sqlite.Subnet{Zone: 456, IPNet: net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.IPv4Mask(255, 255, 255, 0)}, TPAddr: net.ParseIP("8.8.8.8")}

	err = db.InsertZone(&sqlite.Zone{ID: 1, Name: "Test"})
	if err != nil {
		panic(err)
	}

	err = db.InsertZone(&sqlite.Zone{ID: 456, Name: "Test"})
	if err != nil {
		panic(err)
	}

	err = db.InsertSubnet(sub)
	if err != nil {
		panic(err)
	}

}
