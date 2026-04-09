package store

type Store interface {
	InsertAlert(a *Alert) error
	RecentAlerts(limit int) ([]Alert, error)
	AlertCountByType() (map[string]int, error)
	StartSession(iface, sourceType string) (int64, error)
	EndSession(id, packets, alertsGenerated int64) error
	Close() error
}

var _ Store = (*DB)(nil)
