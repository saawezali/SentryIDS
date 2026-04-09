package store

import "time"

type Session struct {
	ID               int64
	StartedAt        time.Time
	EndedAt          *time.Time
	Interface        string
	SourceType       string
	PacketsProcessed int64
	AlertsGenerated  int64
}

func (d *DB) StartSession(iface, sourceType string) (int64, error) {
	result, err := d.conn.Exec(`
		INSERT INTO sessions (started_at, interface, source_type)
		VALUES (?, ?, ?)`,
		time.Now(), iface, sourceType,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (d *DB) EndSession(id, packets, alertsGenerated int64) error {
	_, err := d.conn.Exec(`
		UPDATE sessions
		SET    ended_at = ?, packets_processed = ?, alerts_generated = ?
		WHERE  id = ?`,
		time.Now(), packets, alertsGenerated, id,
	)
	return err
}
