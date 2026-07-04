package main

import (
	"testing"

	"sentryids/internal/engine"
	"sentryids/internal/store"
)

type modelTestStore struct{}

func (modelTestStore) InsertAlert(*store.Alert) error             { return nil }
func (modelTestStore) RecentAlerts(int) ([]store.Alert, error)    { return nil, nil }
func (modelTestStore) AlertCountByType() (map[string]int, error)  { return nil, nil }
func (modelTestStore) StartSession(string, string) (int64, error) { return 1, nil }
func (modelTestStore) EndSession(int64, int64, int64) error       { return nil }
func (modelTestStore) Close() error                               { return nil }

func TestEmbeddedModelCanRunInference(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ortPath, err := prepareORTLibrary()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		OrtLibPath: ortPath, ScalerData: scalerData, ModelData: modelData,
		ConfidenceThreshold: 0.75, InputBufferSize: 1, Store: modelTestStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	label, confidence, err := eng.Predict(engine.Features{})
	if err != nil {
		t.Fatal(err)
	}
	if label < engine.Normal || label > engine.U2R {
		t.Fatalf("invalid class %v", label)
	}
	if confidence < 0 || confidence > 1 {
		t.Fatalf("invalid confidence %f", confidence)
	}
}
