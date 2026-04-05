package store

import (
	"fmt"

	"sentryids/internal/engine"
)

func (s *Store) InsertAlert(a engine.Alert) (int64, error) {
	res, err := s.db.Exec(`
        INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, confidence, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Timestamp, a.SrcIP, a.DstIP, a.SrcPort, a.DstPort,
		a.Protocol, a.AttackType, a.Confidence, a.Severity,
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert alert: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) GetRecentAlerts(limit int) ([]engine.Alert, error) {
	rows, err := s.db.Query(`
        SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
               protocol, attack_type, confidence, severity
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []engine.Alert
	for rows.Next() {
		var a engine.Alert
		if err := rows.Scan(
			&a.ID, &a.Timestamp, &a.SrcIP, &a.DstIP,
			&a.SrcPort, &a.DstPort, &a.Protocol,
			&a.AttackType, &a.Confidence, &a.Severity,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}
