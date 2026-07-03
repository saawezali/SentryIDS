package engine

import (
	"encoding/json"
	"fmt"
	"os"
)

type Scaler struct {
	Mean  [41]float32
	Scale [41]float32
}

type scalerJSON struct {
	Mean  []float64 `json:"mean"`
	Scale []float64 `json:"scale"`
}

func LoadScaler(path string) (*Scaler, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scaler params: %w", err)
	}

	var raw scalerJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing scaler params: %w", err)
	}

	if len(raw.Mean) != 41 || len(raw.Scale) != 41 {
		return nil, fmt.Errorf("scaler params: expected 41 features, got mean=%d scale=%d",
			len(raw.Mean), len(raw.Scale))
	}

	var s Scaler
	for i := 0; i < 41; i++ {
		s.Mean[i] = float32(raw.Mean[i])
		s.Scale[i] = float32(raw.Scale[i])
	}

	return &s, nil
}

func (s *Scaler) Transform(v *[41]float32) {
	for i := 0; i < 41; i++ {
		v[i] = (v[i] - s.Mean[i]) / s.Scale[i]
	}
}
