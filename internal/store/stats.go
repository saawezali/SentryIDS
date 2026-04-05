package store

import (
	"fmt"
	"time"
)

type TimeSeriesBucket struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
}

type IPStat struct {
	IP         string `json:"ip"`
	AlertCount int    `json:"alert_count"`
	TopAttack  string `json:"top_attack"`
}

func (s *Store) GetAlertStats(since time.Time) (map[string]int, error) {
	rows, err := s.db.Query(`
        SELECT attack_type, COUNT(*) as cnt
        FROM alerts
        WHERE timestamp >= ?
        GROUP BY attack_type`, since)
	if err != nil {
		return nil, fmt.Errorf("store: alert stats: %w", err)
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var attackType string
		var count int
		if err := rows.Scan(&attackType, &count); err != nil {
			return nil, err
		}
		result[attackType] = count
	}
	return result, rows.Err()
}

func (s *Store) GetAlertTimeSeries(since time.Time, bucketMinutes int) ([]TimeSeriesBucket, error) {
	rows, err := s.db.Query(`
        SELECT
            strftime('%Y-%m-%dT%H:', timestamp) ||
            printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / ?) * ?) || ':00Z' AS bucket,
            COUNT(*) as cnt
        FROM alerts
        WHERE timestamp >= ?
        GROUP BY bucket
        ORDER BY bucket ASC`,
		bucketMinutes, bucketMinutes, since,
	)
	if err != nil {
		return nil, fmt.Errorf("store: time series: %w", err)
	}
	defer rows.Close()

	var buckets []TimeSeriesBucket
	for rows.Next() {
		var b TimeSeriesBucket
		var ts string
		if err := rows.Scan(&ts, &b.Count); err != nil {
			return nil, err
		}
		t, err := time.Parse("2006-01-02T15:04:05Z", ts)
		if err != nil {
			continue
		}
		b.Timestamp = t
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
}

func (s *Store) GetTopIPs(limit int) ([]IPStat, error) {
	rows, err := s.db.Query(`
        SELECT
            src_ip,
            COUNT(*) as alert_count,
            (SELECT attack_type FROM alerts a2
             WHERE a2.src_ip = a.src_ip
             GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 1) as top_attack
        FROM alerts a
        GROUP BY src_ip
        ORDER BY alert_count DESC
        LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: top IPs: %w", err)
	}
	defer rows.Close()

	var stats []IPStat
	for rows.Next() {
		var stat IPStat
		if err := rows.Scan(&stat.IP, &stat.AlertCount, &stat.TopAttack); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

func (s *Store) CountAlerts() (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count)
	return count, err
}
