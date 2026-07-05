package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	conn.SetMaxOpenConns(4)
	conn.SetMaxIdleConns(2)

	db := &DB{conn: conn}

	// Enable WAL mode for concurrent reads during writes
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enabling WAL mode: %w", err)
	}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return db, nil
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS alerts (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp       DATETIME NOT NULL,
		src_ip          TEXT NOT NULL,
		dst_ip          TEXT NOT NULL,
		src_port        INTEGER NOT NULL,
		dst_port        INTEGER NOT NULL,
		protocol        TEXT NOT NULL,
		attack_type     TEXT NOT NULL,
		confidence      REAL NOT NULL,
		severity        TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);
	CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts(src_ip);

	CREATE TABLE IF NOT EXISTS sessions (
		id                 INTEGER PRIMARY KEY AUTOINCREMENT,
		started_at         DATETIME NOT NULL,
		ended_at           DATETIME,
		interface          TEXT NOT NULL,
		source_type        TEXT NOT NULL,
		packets_processed  INTEGER DEFAULT 0,
		alerts_generated   INTEGER DEFAULT 0
	);
	`

	_, err := d.conn.Exec(schema)
	return err
}

func (d *DB) Close() error {
	return d.conn.Close()
}
