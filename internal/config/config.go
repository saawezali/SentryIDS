package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	ConfidenceThreshold float32 `json:"confidence_threshold"`
	DefaultInterface    string  `json:"default_interface"`
	MaxAlertsInMemory   int     `json:"max_alerts_in_memory"`
	DBPath              string  `json:"db_path"`
	Theme               string  `json:"theme"`
}

func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		ConfidenceThreshold: 0.75,
		DefaultInterface:    "eth0",
		MaxAlertsInMemory:   200,
		DBPath:              filepath.Join(home, ".sentryids", "sentryids.db"),
		Theme:               "dark",
	}
}

func Load() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return DefaultConfig(), err
	}

	dir := filepath.Join(home, ".sentryids")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return DefaultConfig(), err
	}

	path := filepath.Join(dir, "config.json")

	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		return cfg, save(cfg, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultConfig(), err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DefaultConfig(), err
	}
	return cfg, nil
}

func Save(cfg Config) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".sentryids", "config.json")
	return save(cfg, path)
}

func save(cfg Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
