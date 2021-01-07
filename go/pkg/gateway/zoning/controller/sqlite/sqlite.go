package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

var maxZoneID = 1<<24 - 1

// Backend wraps the database backend
type Backend struct {
	db *sql.DB
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (*Backend, error) {
	var err error

	db, err := sql.Open("sqlite3", fmt.Sprintf("%v", path))
	if err != nil {
		return nil, err
	}

	// from now on, close the sql database in case of error
	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	// prevent weird errors. (see https://stackoverflow.com/a/35805826)
	db.SetMaxOpenConns(1)

	// Make sure DB is reachable
	if err = db.Ping(); err != nil {
		return nil, common.NewBasicError("Initial DB ping failed, connection broken?", err,
			"path", path)
	}

	// set journaling to WAL
	_, err = db.Exec("PRAGMA journal_mode = WAL;")
	if err != nil {
		return nil, errors.New("Failed to enable WAL journal mode")
	}

	// enable foreign key constraints
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return nil, errors.New("Failed to enable foreign key constraints")
	}

	// Ensure foreign keys are supported and enabled
	var enabled bool
	err = db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled)
	if err == sql.ErrNoRows {
		return nil, common.NewBasicError("Foreign keys not supported", err,
			"path", path)
	}
	if err != nil {
		return nil, common.NewBasicError("Failed to check for foreign key support", err,
			"path", path)
	}
	if !enabled {
		db.Close()
		return nil, common.NewBasicError("Failed to enable foreign key support", nil,
			"path", path)
	}

	// Check the schema version and set up new DB if necessary.
	var existingVersion int
	err = db.QueryRow("PRAGMA user_version;").Scan(&existingVersion)
	if err != nil {
		return nil, common.NewBasicError("Failed to check schema version", err,
			"path", path)
	}
	if existingVersion == 0 {
		if err = setup(db, Schema, SchemaVersion, path); err != nil {
			return nil, err
		}
	} else if existingVersion != SchemaVersion {
		return nil, common.NewBasicError("Database schema version mismatch", nil,
			"expected", SchemaVersion, "have", existingVersion, "path", path)
	}
	return &Backend{db: db}, nil
}

func setup(db *sql.DB, schema string, schemaVersion int, path string) error {
	_, err := db.Exec(schema)
	if err != nil {
		return common.NewBasicError("Failed to set up SQLite database", err, "path", path)
	}
	// Write schema version to database.
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d;", schemaVersion))
	if err != nil {
		return common.NewBasicError("Failed to write schema version", err, "path", path)
	}
	return nil
}

// Exec executes an arbitrary command on the backend
func (b *Backend) Exec(stmt string) (sql.Result, error) {
	return b.db.Exec(stmt)
}

/* Insertions */

// InsertZone inserts a Zone into the Backend
func (b *Backend) InsertZone(zoneID int, name string) error {
	// check zoneID is not too big
	if zoneID > maxZoneID {
		return fmt.Errorf("zone ID must be at most %d", maxZoneID)
	}
	stmt := `INSERT INTO Zones (id, name) VALUES (?, ?)`
	_, err := b.db.Exec(stmt, zoneID, name)
	if err != nil {
		return err
	}
	return nil
}

// InsertSite inserts a branch site into the Backend
func (b *Backend) InsertSite(tpAddr string, name string) error {
	_, err := snet.ParseUDPAddr(tpAddr)
	if err != nil {
		return fmt.Errorf("%s is not a valid address", tpAddr)
	}
	stmt := `INSERT INTO Sites (tp_address, name) VALUES (?, ?)`
	_, err = b.db.Exec(stmt, tpAddr, name)
	if err != nil {
		return err
	}
	return nil
}

// InsertSubnet inserts a Subnet into the Backend
func (b *Backend) InsertSubnet(zoneID int, net net.IPNet, tpAddr string) error {
	if zoneID > maxZoneID {
		return fmt.Errorf("zone ID must be at most %d", maxZoneID)
	}
	_, err := snet.ParseUDPAddr(tpAddr)
	if err != nil {
		return fmt.Errorf("%s is not a valid address", tpAddr)
	}
	stmt := `INSERT INTO Subnets (zone, net_ip, net_mask, tp_address) VALUES (?, ?, ?, ?)`
	_, err = b.db.Exec(stmt, zoneID, net.IP, net.Mask, tpAddr)
	if err != nil {
		return err
	}
	return nil
}

// InsertTransitions inserts premitted zone transitions into the Backend
func (b *Backend) InsertTransitions(transitions types.Transitions) error {
	stmt := `INSERT INTO Transitions (src, dest) VALUES (?, ?)`

	// do insertion in a transaction to ensure atomicity
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}

	for src, dests := range transitions {
		for _, dest := range dests {
			_, err = tx.Exec(stmt, src, dest)
			if err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	tx.Commit()
	return nil
}

/* Deletions */

// DeleteZone inserts a Zone into the Backend
func (b *Backend) DeleteZone(zoneID int) error {
	stmt := `DELETE FROM Zones WHERE ID = ?`
	_, err := b.db.Exec(stmt, zoneID)
	if err != nil {
		return err
	}
	return nil
}

// DeleteSite inserts a branch site into the Backend
func (b *Backend) DeleteSite(tpAddr string) error {
	stmt := `DELETE FROM Sites WHERE tp_address = ?`
	_, err := b.db.Exec(stmt, tpAddr)
	if err != nil {
		return err
	}
	return nil
}

// DeleteSubnet inserts a Subnet into the Backend
func (b *Backend) DeleteSubnet(net net.IPNet) error {
	stmt := `DELETE FROM Subnets WHERE net_ip = ? AND net_mask = ?`
	_, err := b.db.Exec(stmt, net.IP, net.Mask)
	if err != nil {
		return err
	}
	return nil
}

// DeleteTransitions inserts premitted zone transitions into the Backend
func (b *Backend) DeleteTransitions(transitions types.Transitions) error {
	stmt := `DELETE FROM Transitions WHERE src = ? AND dest = ?`

	// do insertion in a transaction to ensure atomicity
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}

	for src, dests := range transitions {
		for _, dest := range dests {
			_, err = tx.Exec(stmt, src, dest)
			if err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	tx.Commit()
	return nil
}

/* Getters */

// GetAllSubnets returns all subnets stored in the backend
func (b *Backend) GetAllSubnets() ([]*types.Subnet, error) {

	stmt := `SELECT net_ip, net_mask, zone, tp_address 
	FROM   subnets`

	rows, err := b.db.Query(stmt)
	if err != nil {
		return nil, err
	}

	var nets []*types.Subnet
	var ip []byte
	var mask []byte
	var zone types.ZoneID
	var tp string
	for rows.Next() {
		err = rows.Scan(&ip, &mask, &zone, &tp)
		if err != nil {
			return nil, err
		}
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: mask}, ZoneID: zone, TPAddr: tp})
	}
	return nets, nil
}

// GetSubnets returns all subnets stored in the backend relevant for ZTP with address tpAddr
func (b *Backend) GetSubnets(tpAddr string) ([]*types.Subnet, error) {
	stmt := `WITH tp_zones
	AS (SELECT DISTINCT zone 
		FROM   subnets 
		WHERE  tp_address = ?), 
	possible_dests 
	AS (SELECT DISTINCT dest
		FROM   transitions 
		WHERE  src IN tp_zones AND dest NOT IN tp_zones), 
	possible_src 
	AS (SELECT DISTINCT src
		FROM  transitions 
		WHERE  dest IN tp_zones AND src NOT IN tp_zones) 
	SELECT net_ip, net_mask, zone, tp_address 
	FROM   subnets 
	WHERE  zone IN tp_zones OR zone IN possible_dests
	   OR zone IN possible_src`

	rows, err := b.db.Query(stmt, tpAddr)
	if err != nil {
		return nil, err
	}

	var nets []*types.Subnet
	var ip []byte
	var mask []byte
	var zone types.ZoneID
	var tp string
	for rows.Next() {
		err = rows.Scan(&ip, &mask, &zone, &tp)
		if err != nil {
			return nil, err
		}
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: mask}, ZoneID: zone, TPAddr: tp})
	}
	return nets, nil
}

// GetAllTransitions returns all allowed dtransitions stored in the backend
func (b *Backend) GetAllTransitions() (map[int][]int, error) {
	stmt := `SELECT src, dest 
	FROM   transitions`

	rows, err := b.db.Query(stmt)
	if err != nil {
		return nil, err
	}

	transitions := make(map[int][]int)
	var src int
	var dest int
	for rows.Next() {
		err = rows.Scan(&src, &dest)
		if err != nil {
			return nil, err
		}
		dests, ok := transitions[src]
		if !ok {
			transitions[src] = []int{dest}
			continue
		}
		transitions[src] = append(dests, dest)
	}
	return transitions, nil
}

// GetTransitions returns all allowed transitions of a given TP stored in the backend
func (b *Backend) GetTransitions(tpAddr string) (map[int][]int, error) {
	stmt := `WITH relevant_zones 
	AS (SELECT DISTINCT zone 
		FROM   subnets 
		WHERE  tp_address = ?) 
	SELECT src, dest 
	FROM   transitions 
	WHERE  src IN relevant_zones 
	   OR dest IN relevant_zones`

	rows, err := b.db.Query(stmt, tpAddr)
	if err != nil {
		return nil, err
	}

	transitions := make(map[int][]int)
	var src int
	var dest int
	for rows.Next() {
		err = rows.Scan(&src, &dest)
		if err != nil {
			return nil, err
		}
		dests, ok := transitions[src]
		if !ok {
			transitions[src] = []int{dest}
			continue
		}
		transitions[src] = append(dests, dest)
	}
	return transitions, nil
}
