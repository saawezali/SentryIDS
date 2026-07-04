package main

import _ "embed"

// Runtime resources are embedded so the application does not depend on the
// directory it was launched from.

//go:embed models/ids_model.onnx
var modelData []byte

//go:embed models/scaler_params.json
var scalerData []byte

//go:embed lib/libonnxruntime.so
var linuxORTData []byte
