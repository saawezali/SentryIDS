package store

import (
	"time"
)

type Alert struct {
	ID         int64
	Timestamp  time.Time
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	AttackType string
	Confidence float64
	Severity   string
}

func (d *DB) InsertAlert(a *Alert) error {
	result, err := d.conn.Exec(`
		INSERT INTO alerts
			(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, confidence, severity)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Timestamp, a.SrcIP, a.DstIP, a.SrcPort, a.DstPort,
		a.Protocol, a.AttackType, a.Confidence, a.Severity,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	a.ID = id
	return nil
}

func (d *DB) RecentAlerts(limit int) ([]Alert, error) {
	rows, err := d.conn.Query(`
		SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
		       protocol, attack_type, confidence, severity
		FROM   alerts
		ORDER  BY timestamp DESC
		LIMIT  ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := make([]Alert, 0)

	for rows.Next() {
		var a Alert
		err := rows.Scan(
			&a.ID, &a.Timestamp, &a.SrcIP, &a.DstIP,
			&a.SrcPort, &a.DstPort, &a.Protocol,
			&a.AttackType, &a.Confidence, &a.Severity,
		)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}

	return alerts, rows.Err()
}

func (d *DB) AlertCountByType() (map[string]int, error) {
	rows, err := d.conn.Query(`
		SELECT attack_type, COUNT(*) as count
		FROM   alerts
		GROUP  BY attack_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)

	for rows.Next() {
		var attackType string
		var count int
		if err := rows.Scan(&attackType, &count); err != nil {
			return nil, err
		}
		counts[attackType] = count
	}

	return counts, rows.Err()
}
