package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	_ "embed"

	"sentryids/internal/store"

	ort "github.com/yalue/onnxruntime_go"
)

var modelData []byte

type Engine struct {
	session   *ort.DynamicAdvancedSession
	scaler    *Scaler
	store     store.Store
	inputCh   chan Features
	alertCh   chan store.Alert
	sessionID int64
	packets   int64
	alerts    int64
	threshold float32
}

type Config struct {
	OrtLibPath          string
	ScalerPath          string
	ConfidenceThreshold float32
	InputBufferSize     int
	Store               store.Store
}

func New(cfg Config) (*Engine, error) {
	ort.SetSharedLibraryPath(cfg.OrtLibPath)
	if err := ort.InitializeEnvironment(); err != nil {
		return nil, fmt.Errorf("initialising ORT environment: %w", err)
	}

	scaler, err := LoadScaler(cfg.ScalerPath)
	if err != nil {
		return nil, fmt.Errorf("loading scaler: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "sentryids-model-*.onnx")
	if err != nil {
		return nil, fmt.Errorf("creating temp model file: %w", err)
	}

	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(modelData); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("writing temp model file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("closing temp model file: %w", err)
	}

	defer os.Remove(tmpPath)

	session, err := ort.NewDynamicAdvancedSession(
		tmpPath,
		[]string{"float_input"},
		[]string{"output_label", "output_probability"},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("creating ORT session: %w", err)
	}

	return &Engine{
		session:   session,
		scaler:    scaler,
		store:     cfg.Store,
		inputCh:   make(chan Features, cfg.InputBufferSize),
		alertCh:   make(chan store.Alert, 64),
		threshold: cfg.ConfidenceThreshold,
	}, nil
}

func (e *Engine) InputChannel() chan<- Features {
	return e.inputCh
}

func (e *Engine) AlertChannel() <-chan store.Alert {
	return e.alertCh
}

func (e *Engine) Start(ctx context.Context, iface, sourceType string) error {
	id, err := e.store.StartSession(iface, sourceType)
	if err != nil {
		return fmt.Errorf("starting session: %w", err)
	}
	e.sessionID = id
	e.packets = 0
	e.alerts = 0

	go func() {
		defer func() {
			if err := e.store.EndSession(e.sessionID, e.packets, e.alerts); err != nil {
				log.Printf("ending session: %v", err)
			}
		}()

		for {
			select {
			case feat, ok := <-e.inputCh:
				if !ok {
					return
				}
				e.packets++
				e.process(feat)

			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (e *Engine) process(feat Features) {
	vec := feat.Vector
	e.scaler.Transform(&vec)

	inputTensor, err := ort.NewTensor(ort.NewShape(1, 41), vec[:])
	if err != nil {
		log.Printf("creating input tensor: %v", err)
		return
	}
	defer inputTensor.Destroy()

	labelTensor, err := ort.NewEmptyTensor[int64](ort.NewShape(1))
	if err != nil {
		log.Printf("creating label tensor: %v", err)
		return
	}
	defer labelTensor.Destroy()

	probTensor, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 5))
	if err != nil {
		log.Printf("creating prob tensor: %v", err)
		return
	}
	defer probTensor.Destroy()

	err = e.session.Run(
		[]ort.ArbitraryTensor{inputTensor},
		[]ort.ArbitraryTensor{labelTensor, probTensor},
	)
	if err != nil {
		log.Printf("running inference: %v", err)
		return
	}

	labelIdx := labelTensor.GetData()[0]
	probs := probTensor.GetData()
	label := ClassLabel(labelIdx)
	confidence := probs[labelIdx]

	if label == Normal || confidence < e.threshold {
		return
	}

	alert := store.Alert{
		Timestamp:  time.Now(),
		SrcIP:      feat.SrcIP,
		DstIP:      feat.DstIP,
		SrcPort:    feat.SrcPort,
		DstPort:    feat.DstPort,
		Protocol:   feat.Protocol,
		AttackType: label.String(),
		Confidence: float64(confidence),
		Severity:   label.Severity(),
	}

	if err := e.store.InsertAlert(&alert); err != nil {
		log.Printf("inserting alert: %v", err)
		return
	}
	e.alerts++

	select {
	case e.alertCh <- alert:
	default:
	}
}

func (e *Engine) Stop() error {
	if e.session != nil {
		return e.session.Destroy()
	}
	return nil
}
