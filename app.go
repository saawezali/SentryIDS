package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"sentryids/internal/capture"
	"sentryids/internal/config"
	"sentryids/internal/engine"
	"sentryids/internal/store"
)

type App struct {
	ctx        context.Context
	cfg        config.Config
	db         *store.DB
	eng        *engine.Engine
	capturer   *capture.Capturer
	cancelFunc context.CancelFunc
	running    bool
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	cfgPath := configPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		cfg = config.DefaultConfig()
		if saveErr := config.Save(cfg, cfgPath); saveErr != nil {
			log.Printf("saving default config: %v", saveErr)
		}
	}
	a.cfg = cfg

	dbPath := expandHome(cfg.DBPath)
	db, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("opening database: %v", err)
	}
	a.db = db

	eng, err := engine.New(engine.Config{
		OrtLibPath:          ortLibPath(),
		ScalerPath:          "models/scaler_params.json",
		ConfidenceThreshold: float32(cfg.ConfidenceThreshold),
		InputBufferSize:     512,
		Store:               db,
	})
	if err != nil {
		log.Fatalf("initialising engine: %v", err)
	}
	a.eng = eng

	go a.forwardAlerts()
}

func (a *App) shutdown(ctx context.Context) {
	if a.running {
		a.StopCapture()
	}
	if a.eng != nil {
		a.eng.Stop()
	}
	if a.db != nil {
		a.db.Close()
	}
}

func (a *App) StartCapture(iface string) string {
	if a.running {
		return "capture already running"
	}

	captureCtx, cancel := context.WithCancel(context.Background())
	a.cancelFunc = cancel

	if err := a.eng.Start(captureCtx, iface, "live"); err != nil {
		cancel()
		return fmt.Sprintf("starting engine: %v", err)
	}

	a.capturer = capture.New(iface, a.eng.InputChannel())
	if err := a.capturer.Start(captureCtx); err != nil {
		cancel()
		return fmt.Sprintf("starting capture on %s: %v", iface, err)
	}

	a.running = true

	wailsRuntime.EventsEmit(a.ctx, "capture:started", iface)
	return ""
}

func (a *App) StopCapture() {
	if !a.running {
		return
	}
	a.cancelFunc()
	a.running = false
	a.capturer = nil
	wailsRuntime.EventsEmit(a.ctx, "capture:stopped", nil)
}

func (a *App) GetRecentAlerts(limit int) ([]store.Alert, error) {
	return a.db.RecentAlerts(limit)
}

func (a *App) GetAlertCounts() (map[string]int, error) {
	return a.db.AlertCountByType()
}

func (a *App) GetConfig() config.Config {
	return a.cfg
}

func (a *App) SaveConfig(cfg config.Config) string {
	a.cfg = cfg
	if err := config.Save(cfg, configPath()); err != nil {
		return err.Error()
	}
	return ""
}

func (a *App) IsRunning() bool {
	return a.running
}

func (a *App) ListInterfaces() ([]string, error) {
	return capture.FindInterfaces()
	/*if err != nil {
		return nil, err
	}
	return devs, nil*/
}

func (a *App) forwardAlerts() {
	for alert := range a.eng.AlertChannel() {
		wailsRuntime.EventsEmit(a.ctx, "alert:new", alert)
	}
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentryids", "config.json")
}

func expandHome(path string) string {
	if len(path) > 1 && path[:2] == "~/" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func ortLibPath() string {
	switch runtime.GOOS {
	case "windows":
		return "lib/onnxruntime.dll"
	case "darwin":
		return "lib/libonnxruntime.dylib"
	default:
		return "lib/libonnxruntime.so"
	}
}
