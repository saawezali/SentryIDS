package engine

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"sentryids/internal/store"

	ort "github.com/yalue/onnxruntime_go"
)

type Engine struct {
	session       *ort.DynamicAdvancedSession
	scaler        *Scaler
	store         store.Store
	inputCh       chan Features
	alertCh       chan store.Alert
	stopCh        chan struct{}
	threshold     float32
	droppedAlerts int64
	wg            sync.WaitGroup
	mu            sync.RWMutex
}

type Config struct {
	OrtLibPath          string
	ScalerPath          string
	ScalerData          []byte
	ModelData           []byte
	ConfidenceThreshold float32
	InputBufferSize     int
	Store               store.Store
}

func New(cfg Config) (*Engine, error) {
	ort.SetSharedLibraryPath(cfg.OrtLibPath)
	if err := ort.InitializeEnvironment(); err != nil {
		return nil, fmt.Errorf("initialising ORT environment: %w", err)
	}

	var scaler *Scaler
	var err error
	if len(cfg.ScalerData) > 0 {
		scaler, err = LoadScalerData(cfg.ScalerData)
	} else {
		scaler, err = LoadScaler(cfg.ScalerPath)
	}
	if err != nil {
		return nil, fmt.Errorf("loading scaler: %w", err)
	}

	if len(cfg.ModelData) == 0 {
		return nil, fmt.Errorf("model data is empty")
	}

	session, err := ort.NewDynamicAdvancedSessionWithONNXData(
		cfg.ModelData,
		[]string{"float_input"},
		[]string{"label", "probabilities"},
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
		stopCh:    make(chan struct{}),
		threshold: cfg.ConfidenceThreshold,
	}, nil
}

func (e *Engine) InputChannel() chan<- Features {
	return e.inputCh
}

func (e *Engine) AlertChannel() <-chan store.Alert {
	return e.alertCh
}

func (e *Engine) Done() <-chan struct{} {
	return e.stopCh
}

func (e *Engine) Start(ctx context.Context, iface, sourceType string) error {
	id, err := e.store.StartSession(iface, sourceType)
	if err != nil {
		return fmt.Errorf("starting session: %w", err)
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		var packets, alerts int64
		defer func() {
			if err := e.store.EndSession(id, packets, alerts); err != nil {
				log.Printf("ending session: %v", err)
			}
		}()

		for {
			select {
			case feat, ok := <-e.inputCh:
				if !ok {
					return
				}
				packets += feat.PacketCount
				if e.process(feat) {
					alerts++
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (e *Engine) process(feat Features) bool {
	label, confidence, err := e.Predict(feat)
	if err != nil {
		log.Printf("running inference: %v", err)
		return false
	}

	e.mu.RLock()
	threshold := e.threshold
	e.mu.RUnlock()
	if label == Normal || confidence < threshold {
		return false
	}

	ts := feat.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	alert := store.Alert{
		Timestamp:  ts,
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
		return false
	}

	select {
	case e.alertCh <- alert:
	default:
		e.mu.Lock()
		e.droppedAlerts++
		e.mu.Unlock()
	}
	return true
}

// Predict scales one extracted flow and runs it through the loaded model.
func (e *Engine) Predict(feat Features) (ClassLabel, float32, error) {
	vec := feat.Vector
	e.scaler.Transform(&vec)

	inputTensor, err := ort.NewTensor(ort.NewShape(1, 41), vec[:])
	if err != nil {
		return Normal, 0, fmt.Errorf("creating input tensor: %w", err)
	}
	defer inputTensor.Destroy()

	labelTensor, err := ort.NewEmptyTensor[int64](ort.NewShape(1))
	if err != nil {
		return Normal, 0, fmt.Errorf("creating label tensor: %w", err)
	}
	defer labelTensor.Destroy()

	outputs := []ort.Value{labelTensor, nil}
	err = e.session.Run(
		[]ort.ArbitraryTensor{inputTensor},
		outputs,
	)
	if err != nil {
		return Normal, 0, err
	}
	defer outputs[1].Destroy()

	labelIdx := labelTensor.GetData()[0]
	label := ClassLabel(labelIdx)
	confidence, err := probabilityForLabel(outputs[1], labelIdx)
	if err != nil {
		return Normal, 0, fmt.Errorf("reading inference probabilities: %w", err)
	}
	if label < Normal || label > U2R {
		return Normal, 0, fmt.Errorf("model returned unknown class %d", labelIdx)
	}
	return label, confidence, nil
}

func probabilityForLabel(value ort.Value, label int64) (float32, error) {
	if probabilities, ok := value.(*ort.Tensor[float32]); ok {
		data := probabilities.GetData()
		if label < 0 || int(label) >= len(data) {
			return 0, fmt.Errorf("predicted label %d is outside probability tensor", label)
		}
		return data[label], nil
	}
	sequence, ok := value.(*ort.Sequence)
	if !ok {
		return 0, fmt.Errorf("expected probability sequence, got %T", value)
	}
	items, err := sequence.GetValues()
	if err != nil || len(items) != 1 {
		return 0, fmt.Errorf("expected one probability map, got %d: %w", len(items), err)
	}
	probMap, ok := items[0].(*ort.Map)
	if !ok {
		return 0, fmt.Errorf("expected probability map, got %T", items[0])
	}
	keysValue, probabilitiesValue, err := probMap.GetKeysAndValues()
	if err != nil {
		return 0, err
	}
	keys, ok := keysValue.(*ort.Tensor[int64])
	if !ok {
		return 0, fmt.Errorf("expected int64 probability keys, got %T", keysValue)
	}
	probabilities, ok := probabilitiesValue.(*ort.Tensor[float32])
	if !ok {
		return 0, fmt.Errorf("expected float32 probabilities, got %T", probabilitiesValue)
	}
	for i, key := range keys.GetData() {
		if key == label && i < len(probabilities.GetData()) {
			return probabilities.GetData()[i], nil
		}
	}
	return 0, fmt.Errorf("predicted label %d missing from probabilities", label)
}

func (e *Engine) Wait() {
	e.wg.Wait()
}

func (e *Engine) SetThreshold(threshold float32) {
	e.mu.Lock()
	e.threshold = threshold
	e.mu.Unlock()
}

func (e *Engine) Stop() error {
	close(e.stopCh)
	if e.session != nil {
		return e.session.Destroy()
	}
	return nil
}
