package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
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

func (b *Backend) Exec(stmt string) (sql.Result, error) {
	return b.db.Exec(stmt)
}

// InsertZone inserts a Zone into the Backend
func (b *Backend) InsertZone(zoneID int, name string) error {
	//TODO check that id is only 24bit
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}

	// insert zone
	stmt := `INSERT INTO Zones (id, name) VALUES (?, ?)`
	_, err = tx.Exec(stmt, id, name)
	if err != nil {
		tx.Rollback()
		return err
	}

	// insert all subnets associated with this Zone
	for _, subnet := range zone.Subnets {
		err = insertSubnet(tx, subnet)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	tx.Commit()
	return nil
}

// InsertSubnet inserts a Subnet into the Backend
func (b *Backend) InsertSubnet(subnet *Subnet) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = insertSubnet(tx, subnet)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func insertSubnet(tx *sql.Tx, subnet *Subnet) error {
	stmt := `INSERT INTO Subnets (zone, net_ip, net_mask, tp_address) VALUES (?, ?, ?, ?)`
	_, err := tx.Exec(stmt, subnet.Zone, subnet.IPNet.IP, subnet.IPNet.Mask, subnet.TPAddr)
	if err != nil {
		return err
	}
	return nil
}
