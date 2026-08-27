# xhttptunnel

High-Performance Bidirectional Split-HTTP / Meek Streaming Tunnel Server & Client with Session Multiplexing.

## Features

- **Split-HTTP Bidirectional Streaming**: High-throughput uplink POST chunking and downlink streaming with automatic sequence reconstruction.
- **Reliable Packet Ring Buffer**: Zero-lock concurrent ring buffer preventing chunk drop and memory leak.
- **Auto Self-Signed TLS & Domain Camouflage**: Auto-generates simulated ECDSA TLS certificates matching Amazon / Bing CDN profiles.
- **Health Check Probe (`/healthz`)**: Built-in HTTP probe endpoint for load balancers.
- **Stun Node Sharing (`gen-uri`)**: One-click sharing URI (`xhttp://`) and terminal ASCII QR code generation for Android & TV.
- **Active Fallback Camouflage**: Transparent reverse proxy forwarding to decoy web services for unauthorized probes.

---

## One-Key Management (Linux Server & Client)

### 1. Server Installation (Default)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/master/scripts/install.sh | sudo bash -s install server
```

### 2. Client Installation (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/master/scripts/install.sh | sudo bash -s install client
```

### 3. Upgrade / Uninstall
```bash
# One-key Upgrade (Keeps existing config.json)
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/master/scripts/install.sh | sudo bash -s upgrade

# One-key Uninstall
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/master/scripts/install.sh | sudo bash -s uninstall
```

### 4. Service Management
```bash
systemctl start xhttptunnel    # Start service
systemctl stop xhttptunnel     # Stop service
systemctl restart xhttptunnel  # Restart service
systemctl status xhttptunnel   # Check status
journalctl -u xhttptunnel -f   # View live logs
```

---

## Configuration Reference (`config.json`)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | `string` | `"server"` | Operational mode: `"server"` or `"client"`. |
| `listen` | `string` | `":8443"` | Listen address (`":8443"` for server; `"tcp://127.0.0.1:1080"` for client). |
| `server` | `string` | `""` | Server endpoint URL for client mode (e.g. `"https://example.com:8443/stream"`). |
| `target` | `string` | `"tcp://127.0.0.1:22"` | Target service address (`tcp://127.0.0.1:22` or `udp://127.0.0.1:51820`). |
| `path` | `string` | `"/stream"` | Custom Split-HTTP proxy path. |
| `psk` | `string` | `"my-secret-token"` | Pre-shared key / token for authentication (aliases `token`/`auth_token`). |
| `selfsign` | `bool` | `true` | Auto-generate self-signed TLS certificate if `cert`/`key` omitted. |
| `selfsign_cn` | `string` | `"www.bing.com"` | Common Name (SNI) for generated certificate. |
| `fallback` | `string` | `""` | Fallback URL or host for unauthorized requests. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |
| `max_sessions` | `int` | `2000` | Server max concurrent sessions. |

---

## Quick Start

### 1. Export Stun QR Code & Sharing Link
```bash
xhttptunnel gen-uri -c /etc/xhttptunnel/config.json
```
