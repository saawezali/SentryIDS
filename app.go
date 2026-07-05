package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"sentryids/internal/capture"
	"sentryids/internal/config"
	"sentryids/internal/engine"
	"sentryids/internal/store"
)

type App struct {
	ctx          context.Context
	cfg          config.Config
	db           *store.DB
	eng          *engine.Engine
	capturer     *capture.Capturer
	cancelFunc   context.CancelFunc
	engineCancel context.CancelFunc
	running      bool
	stopping     bool
	mu           sync.RWMutex
	initErr      error
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
		a.initErr = fmt.Errorf("opening database: %w", err)
		log.Printf("%v", a.initErr)
		return
	}
	a.db = db

	ortPath, err := prepareORTLibrary()
	if err != nil {
		a.initErr = fmt.Errorf("preparing ONNX Runtime: %w", err)
		log.Printf("%v", a.initErr)
		return
	}
	eng, err := engine.New(engine.Config{
		OrtLibPath:          ortPath,
		ScalerData:          scalerData,
		ModelData:           modelData,
		ConfidenceThreshold: float32(cfg.ConfidenceThreshold),
		InputBufferSize:     512,
		Store:               db,
	})
	if err != nil {
		a.initErr = fmt.Errorf("initialising engine: %w", err)
		log.Printf("%v", a.initErr)
		return
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
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return "capture already running"
	}
	if a.stopping {
		return "capture is still stopping"
	}

	if a.eng == nil {
		if a.initErr != nil {
			return a.initErr.Error()
		}
		return "detection engine is unavailable"
	}
	engineCtx, engineCancel := context.WithCancel(context.Background())
	captureCtx, captureCancel := context.WithCancel(context.Background())
	a.cancelFunc = captureCancel
	a.engineCancel = engineCancel

	if err := a.eng.Start(engineCtx, iface, "live"); err != nil {
		captureCancel()
		engineCancel()
		return fmt.Sprintf("starting engine: %v", err)
	}

	a.capturer = capture.New(iface, a.eng.InputChannel())
	if err := a.capturer.Start(captureCtx); err != nil {
		captureCancel()
		engineCancel()
		a.eng.Wait()
		return fmt.Sprintf("starting capture on %s: %v", iface, err)
	}

	a.running = true

	wailsRuntime.EventsEmit(a.ctx, "capture:started", iface)
	return ""
}

func (a *App) StopCapture() {
	a.mu.Lock()
	if !a.running || a.stopping {
		a.mu.Unlock()
		return
	}
	a.stopping = true
	captureCancel := a.cancelFunc
	engineCancel := a.engineCancel
	capturer := a.capturer
	a.mu.Unlock()

	// Let capture flush completed flows before stopping the engine consumer.
	captureCancel()
	capturer.Wait()
	engineCancel()
	a.eng.Wait()

	a.mu.Lock()
	a.running = false
	a.stopping = false
	a.capturer = nil
	a.cancelFunc = nil
	a.engineCancel = nil
	a.mu.Unlock()
	wailsRuntime.EventsEmit(a.ctx, "capture:stopped", nil)
}

func (a *App) GetRecentAlerts(limit int) ([]store.Alert, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database is unavailable")
	}
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}
	return a.db.RecentAlerts(limit)
}

func (a *App) GetAlertCounts() (map[string]int, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database is unavailable")
	}
	return a.db.AlertCountByType()
}

func (a *App) GetConfig() config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

func (a *App) SaveConfig(cfg config.Config) string {
	if err := config.Validate(cfg); err != nil {
		return err.Error()
	}
	if cfg.DefaultInterface != "" {
		available, err := capture.FindInterfaces()
		if err == nil {
			found := false
			for _, iface := range available {
				if iface == cfg.DefaultInterface {
					found = true
					break
				}
			}
			if !found {
				return fmt.Sprintf("interface %q not found", cfg.DefaultInterface)
			}
		}
	}
	if err := config.Save(cfg, configPath()); err != nil {
		return err.Error()
	}
	a.mu.Lock()
	a.cfg = cfg
	if a.eng != nil {
		a.eng.SetThreshold(float32(cfg.ConfidenceThreshold))
	}
	a.mu.Unlock()
	return ""
}

func (a *App) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
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
	for {
		select {
		case alert, ok := <-a.eng.AlertChannel():
			if !ok {
				return
			}
			wailsRuntime.EventsEmit(a.ctx, "alert:new", alert)

		case <-a.eng.Done():
			return
		}
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

func prepareORTLibrary() (string, error) {
	switch runtime.GOOS {
	case "linux":
		if len(linuxORTData) == 0 {
			return "", fmt.Errorf("embedded ONNX Runtime library is empty")
		}
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir := filepath.Join(cacheDir, "sentryids")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", err
		}
		path := filepath.Join(dir, "libonnxruntime.so")
		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, linuxORTData) {
			return path, nil
		}
		if err := os.WriteFile(path, linuxORTData, 0755); err != nil {
			return "", err
		}
		return path, nil
	default:
		return "", fmt.Errorf("%s is not supported by this build", runtime.GOOS)
	}
}
