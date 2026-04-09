package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	ConfidenceThreshold float64 `json:"confidence_threshold"`
	DefaultInterface    string  `json:"default_interface"`
	MaxAlertsInMemory   int     `json:"max_alerts_in_memory"`
	DBPath              string  `json:"db_path"`
	Theme               string  `json:"theme"`
}

func DefaultConfig() Config {
	return Config{
		ConfidenceThreshold: 0.75,
		DefaultInterface:    "eth0",
		MaxAlertsInMemory:   200,
		DBPath:              "~/.sentryids/sentryids.db",
		Theme:               "dark",
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)

	if err != nil {
		return Config{}, err
	}

	var cfg Config

	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func Save(cfg Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
