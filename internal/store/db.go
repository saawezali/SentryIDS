package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func New(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("store: create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("store: open db: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, fmt.Errorf("store: set WAL: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    DATETIME NOT NULL,
            src_ip       TEXT NOT NULL,
            dst_ip       TEXT NOT NULL,
            src_port     INTEGER NOT NULL,
            dst_port     INTEGER NOT NULL,
            protocol     TEXT NOT NULL,
            attack_type  TEXT NOT NULL,
            confidence   REAL NOT NULL,
            severity     TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);
        CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts(src_ip);

        CREATE TABLE IF NOT EXISTS sessions (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at        DATETIME NOT NULL,
            ended_at          DATETIME,
            interface         TEXT NOT NULL,
            source_type       TEXT NOT NULL,  -- "live" or "pcap"
            packets_processed INTEGER DEFAULT 0,
            alerts_generated  INTEGER DEFAULT 0
        );
    `)
	return err
}
