package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	want := DefaultConfig()
	if err := Save(want, path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		t.Fatalf("config file was not created: %v", err)
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfidenceThreshold = 1.1
	if err := Validate(cfg); err == nil {
		t.Fatal("expected invalid confidence threshold to fail")
	}
	cfg = DefaultConfig()
	cfg.MaxAlertsInMemory = 0
	if err := Validate(cfg); err == nil {
		t.Fatal("expected invalid alert limit to fail")
	}
}
