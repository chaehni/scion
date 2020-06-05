package sqlite

const (
	// SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	SchemaVersion = 1

	// Schema is the SQLite database layout.
	Schema = `CREATE TABLE Zones(
		id INTEGER NOT NULL,
		name TEXT,
		PRIMARY KEY(id)
	  );

	  CREATE TABLE Sites(
		tp_address BLOB NOT NULL,
		PRIMARY KEY(tp_address) ON CONFLICT REPLACE
	  );
	  
	  CREATE TABLE Subnets(
		zone INTEGER NOT NULL,
		net_ip BLOB NOT NULL,
		net_mask BLOB NOT NULL,
		tp_address BLOB NOT NULL,
		FOREIGN KEY (zone) REFERENCES Zones(id) ON DELETE CASCADE,
		FOREIGN KEY (tp_address) REFERENCES Sites(tp_address) ON DELETE CASCADE,
		UNIQUE(net_ip, net_mask)
	  );
	  
	  CREATE TABLE Transfer(
		src INTEGER NOT NULL,
		dest INTEGER NOT NULL,
		FOREIGN KEY (src) REFERENCES Zones(id) ON DELETE CASCADE,
		FOREIGN KEY (dest) REFERENCES Zones(id) ON DELETE CASCADE,
		PRIMARY KEY (src, dest) ON CONFLICT REPLACE
	  )`

	ZoneTable     = "Zones"
	SubnetTable   = "Subnets"
	TransferTable = "Transfers"
)
