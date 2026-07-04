# SentryIDS

SentryIDS is a Linux desktop intrusion-detection prototype built with Go, Wails, React, libpcap, and an ONNX model trained on NSL-KDD.

## Current scope

- Captures TCP, UDP, and ICMP traffic from a selected local interface.
- Aggregates packets into bidirectional flows and derives the 41-feature NSL-KDD input vector.
- Classifies completed flows as Normal, DoS, Probe, R2L, or U2R.
- Stores alerts and capture-session statistics in SQLite.
- Shows recent alerts and attack counts in the desktop UI.

The NSL-KDD schema does not map perfectly to modern live traffic. Content features that cannot be inferred from packet headers remain zero, so this project should be treated as an educational prototype—not a production security control.

## Requirements

- Linux x86-64 (the repository currently embeds a Linux x86-64 ONNX Runtime library)
- Go 1.25+
- Node.js and npm
- Wails CLI 2.12
- libpcap development files
- GTK/WebKit packages required by Wails
- Permission to capture packets, usually via root or Linux capabilities

On Debian/Ubuntu, the core native packages are typically:

```sh
sudo apt install libpcap-dev libgtk-3-dev libwebkit2gtk-4.1-dev
```

## Development

```sh
npm --prefix frontend install
wails dev
```

Packet capture usually requires elevated privileges. A safer alternative to running the whole GUI as root is granting capture capabilities to the built binary:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip build/bin/sentryids
```

## Build and test

```sh
go test ./...
go vet ./...
npm --prefix frontend run build
wails build
```

The production build embeds the frontend, model, scaler, and Linux ONNX Runtime library. At startup the native library is extracted to the user's cache directory; the executable does not depend on the repository working directory.

## Configuration

Configuration is stored at `~/.sentryids/config.json`. The default database is `~/.sentryids/sentryids.db`. Supported themes are `dark`, `light`, and `system`; confidence thresholds must be between 0 and 1.

Changing the database path applies on the next application start. Confidence-threshold changes apply immediately.

## Retraining

```sh
python3 -m venv training/venv
training/venv/bin/pip install -r training/requirements.txt
training/venv/bin/python training/train.py
training/venv/bin/python training/evaluate.py
```

Training fails on unknown attack labels instead of silently treating them as normal traffic. ONNX export disables `ZipMap`; the Go runtime supports both the new tensor output and the legacy map output in the checked-in model.
