package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/sig/zoning/types"
)

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
	if zoneID > 1<<24-1 {
		return errors.New("ZoneID too big, must fit into 24 bits")
	}
	stmt := `INSERT INTO Zones (id, name) VALUES (?, ?)`
	_, err := b.db.Exec(stmt, zoneID, name)
	if err != nil {
		return err
	}
	return nil
}

// InsertSite inserts a branch site into the Backend
func (b *Backend) InsertSite(tpAddr net.IP, name string) error {
	stmt := `INSERT INTO Sites (tp_address, name) VALUES (?, ?)`
	_, err := b.db.Exec(stmt, tpAddr, name)
	if err != nil {
		return err
	}
	return nil
}

// InsertSubnet inserts a Subnet into the Backend
func (b *Backend) InsertSubnet(zoneID int, net net.IPNet, tpAddr net.IP) error {
	stmt := `INSERT INTO Subnets (zone, net_ip, net_mask, tp_address) VALUES (?, ?, ?, ?)`
	_, err := b.db.Exec(stmt, zoneID, net.IP, net.Mask, tpAddr)
	if err != nil {
		return err
	}
	return nil
}

// InsertTransfers inserts premitted zone transfers into the Backend
func (b *Backend) InsertTransfers(transfers map[int][]int) error {
	stmt := `INSERT INTO Transfers (src, dest) VALUES (?, ?)`

	// do insertion in a transaction to ensure atomicity
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}

	for src, dests := range transfers {
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
func (b *Backend) DeleteSite(tpAddr net.IP) error {
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

// DeleteTransfers inserts premitted zone transfers into the Backend
func (b *Backend) DeleteTransfers(transfers map[int][]int) error {
	stmt := `DELETE FROM Transfers WHERE src = ? AND dest = ?`

	// do insertion in a transaction to ensure atomicity
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}

	for src, dests := range transfers {
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
	stmt := `SELECT net_ip, net_mask, zone, tp_address FROM Subnets`
	rows, err := b.db.Query(stmt)
	if err != nil {
		return nil, err
	}

	var nets []*types.Subnet
	var ip []byte
	var mask []byte
	var zone types.ZoneID
	var tp []byte
	for rows.Next() {
		err = rows.Scan(&ip, &mask, &zone, &tp)
		if err != nil {
			return nil, err
		}
		nets = append(nets, &types.Subnet{IPNet: net.IPNet{IP: ip, Mask: mask}, ZoneID: zone, TPAddr: tp})
	}
	return nets, nil
}

// GetAllTransfers returns all allowed transfers stored in the backend
func (b *Backend) GetAllTransfers() (map[int][]int, error) {
	stmt := `SELECT src, dest FROM Transfers`
	rows, err := b.db.Query(stmt)
	if err != nil {
		return nil, err
	}

	transfers := make(map[int][]int)
	var src int
	var dest int
	for rows.Next() {
		err = rows.Scan(&src, &dest)
		if err != nil {
			return nil, err
		}
		dests, ok := transfers[src]
		if !ok {
			transfers[src] = []int{dest}
			continue
		}
		transfers[src] = append(dests, dest)
	}
	return transfers, nil
}