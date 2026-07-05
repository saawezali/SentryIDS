package config

import (
	"encoding/json"
	"fmt"
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

func Validate(cfg Config) error {
	if cfg.ConfidenceThreshold < 0 || cfg.ConfidenceThreshold > 1 {
		return fmt.Errorf("confidence threshold must be between 0 and 1")
	}
	if cfg.MaxAlertsInMemory < 1 || cfg.MaxAlertsInMemory > 10000 {
		return fmt.Errorf("max alerts in memory must be between 1 and 10000")
	}
	if cfg.DBPath == "" {
		return fmt.Errorf("database path cannot be empty")
	}
	if cfg.Theme != "dark" && cfg.Theme != "light" && cfg.Theme != "system" {
		return fmt.Errorf("theme must be dark, light, or system")
	}
	return nil
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
	if err := Validate(cfg); err != nil {
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

	return os.WriteFile(path, data, 0600)
}
