# xhttptunnel

High-Performance Bidirectional Split-HTTP / Meek Streaming Tunnel Server & Client with Session Multiplexing.

## Features

- **Split-HTTP Bidirectional Streaming**: High-throughput uplink POST chunking and downlink streaming with automatic sequence reconstruction.
- **Reliable Packet Ring Buffer**: Zero-lock concurrent ring buffer preventing chunk drop and memory leak.
- **Auto Self-Signed TLS & Domain Camouflage**: Auto-generates simulated ECDSA TLS certificates matching Amazon / Bing CDN profiles.
- **Stun Node Sharing (`gen-uri`)**: One-click encrypted `stun://` share link (plus a plaintext `xhttp://` URI) and terminal ASCII QR code generation for Android & TV.
- **Active Fallback Camouflage**: Transparent reverse proxy forwarding to decoy web services for unauthorized probes.
- **Embeddable Go SDK**: Client and server live in the [`tunnel`](tunnel/) package — route your own dials through the tunnel, or inject custom socket dialers for interface binding and Android `VpnService.protect()`.

---

## One-Key Management (Linux Server & Client)

### 1. Server Installation (Default)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | sudo bash -s install server
```

### 2. Client Installation (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | sudo bash -s install client
```

### 3. Upgrade / Uninstall
```bash
# One-key Upgrade (Keeps existing config.json)
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | sudo bash -s upgrade

# One-key Uninstall
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | sudo bash -s uninstall
```

To install an exact release instead of `latest`, pass its tag through
`XHTTPTUNNEL_VERSION`:

```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | \
  sudo env XHTTPTUNNEL_VERSION=v1.0.20260904-8f60417 bash -s install server
```

Release tags use `v1.0.yyyyMMdd-<short commit hash>`. Release assets are
standalone binaries named `xhttptunnel_<os>_<arch>` (with `.exe` on Windows),
not zip or tar archives.

For example, create and push a correctly named release tag from the commit you
want to publish:

```bash
release_tag="v1.0.$(date -u +%Y%m%d)-$(git rev-parse --short=7 HEAD)"
git tag "${release_tag}"
git push origin "${release_tag}"
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
| `default_target` / `forward` | `string` | — | Aliases for `target` (server / client respectively); cross-filled when `target` is set. |
| `path` | `string` | `"/stream"` | Custom Split-HTTP proxy path. |
| `psk` | `string` | `"my-secret-token"` | Pre-shared key / token for authentication (aliases `token`/`auth_token`). |
| `cert` / `key` | `string` | `""` | TLS certificate / private key files. Both empty = cleartext origin (behind a TLS-terminating CDN). |
| `selfsign` | `bool` | `true` | Auto-generate self-signed TLS certificate if `cert`/`key` omitted. |
| `selfsign_cn` | `string` | `"www.bing.com"` | Common Name (SNI) for generated certificate. |
| `fallback` | `string` | `""` | Fallback URL or host for unauthorized requests. |
| `sni` | `string` | server host | TLS SNI disguise (client). |
| `host` | `string` | server host | HTTP `Host` header disguise (client). |
| `alpn` | `string` | `"auto"` | Transport selection: `h3`, `h2`, `h1`, or `auto` (probe HTTP/3, fall back). |
| `stream_mode` | `string` | `"auto"` | Client downlink transport: `auto` (negotiate), `poll` (legacy long-poll), or `stream` (force streaming downlink). |
| `fingerprint` | `string` | `""` | Expected server certificate SHA-256 fingerprint (pinning). Strongly recommended for `https://` servers. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |
| `dump` | `bool` | `false` | Hex-dump tunnelled traffic to stdout (debugging only). |
| `max_sessions` | `int` | `2000` | Server max concurrent sessions. |
| `max_conns` | `int` | `2000` | Client max concurrent local connections / sessions. |
| `chunk_size_kb` | `int` | `256` | Upstream payload per poll request (clamped 16–900). Must match on both ends. |
| `idle_timeout` | `int` | `900` | Client: drop a local connection after this many seconds of silence. |
| `allowed_targets` | `[]string` | `[]` | Server: restrict client-requested targets (`"host:port"`, `":port"`, or `"host:"`). Empty = allow all. |
| `trust_proxy_headers` | `bool` | `false` | Server: honour `CF-Connecting-IP`/`X-Forwarded-For`/`X-Real-IP` for client-address logging. Enable only behind a trusted proxy that strips them. |

For a direct TLS deployment, `:8443` (or `tcp+udp://:8443`) starts HTTPS and HTTP/3 on the same port. Use `tcp://127.0.0.1:8443` for a cleartext CDN origin; without a certificate/key the server intentionally does not bind UDP or advertise HTTP/3.

---

## Quick Start

### 1. Export Stun QR Code & Sharing Link
```bash
xhttptunnel gen-uri -c /etc/xhttptunnel/config.json
```

---

## Use as a Go Library

The tunnel core lives in the [`tunnel`](tunnel/) package, so external Go
programs can embed both endpoints instead of shelling out to the binary:

```bash
go get github.com/NNdroid/xhttptunnel/tunnel
```

### Client: route your own dials through the tunnel

`Client.DialContext` is `net.Dialer`-shaped, so it plugs straight into
`http.Transport`, gRPC, database drivers — anything that accepts a dial
function:

```go
import "github.com/NNdroid/xhttptunnel/tunnel"

c, err := tunnel.NewClient(tunnel.ClientConfig{
	ServerURL:   "https://cdn.example.com:8443/stream",
	PSK:         "my-secret-token",
	Fingerprint: "AA:BB:...", // certificate pinning (recommended)
})
if err != nil {
	log.Fatal(err)
}

// Every connection made by this http.Client travels through the tunnel.
transport := &http.Transport{DialContext: c.DialContext}
resp, err := (&http.Client{Transport: transport}).Get("http://127.0.0.1:22/")
```

`Client.ListenAndServe(ctx, "tcp://127.0.0.1:1080")` instead runs the same
local TCP/UDP forwarder the CLI runs, forwarding to `ClientConfig.Target`.

### Client: control the underlying sockets (Android / interface binding)

By default the client dials through the system network stack. When the host
app must own the sockets — binding to a specific interface, or Android
`VpnService.protect()` so tunnel traffic bypasses the VPN it is establishing —
inject your own dialers:

```go
c, _ := tunnel.NewClient(tunnel.ClientConfig{
	ServerURL: "https://cdn.example.com:8443/stream",
	PSK:       "my-secret-token",
	// TCP sockets for the h1/h2 transports.
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// Hand the socket fd to VpnService.protect() so this connection
		// bypasses the VPN it is being used to establish.
		if tcp, ok := conn.(*net.TCPConn); ok {
			if rc, cerr := tcp.SyscallConn(); cerr == nil {
				rc.Control(func(fd uintptr) { vpnProtect(int(fd)) })
			}
		}
		return conn, nil
	},
	// QUIC connections for the h3 transport (optional). Wrap quic.DialAddr
	// to bind or protect the underlying UDP socket.
	QUICDial: quic.DialAddr,
	// Clients that share one routing policy may share cached transports;
	// distinct (or empty) keys keep them isolated so a socket dialled for
	// one network is never reused on another.
	TransportKey: "vpn-0",
	// Per-client upstream chunk cap; 0 uses the package default.
	ChunkSizeKB: 256,
})
```

`TransportKey` matters because HTTP transports (and the negotiated-protocol
cache) are pooled per endpoint across clients: without a key, a client with an
injected dialer could hand a warm transport — bound to the wrong network — to
another client. Equal non-empty keys opt into sharing; empty keys isolate each
injected client.

### Server: expose your service behind the camouflage

```go
srv, err := tunnel.NewServer(tunnel.ServerConfig{
	Listen:        "tcp+udp://:8443",
	PSK:           "my-secret-token",
	SelfSign:      true, // or set CertFile/KeyFile
	DefaultTarget: "tcp://127.0.0.1:22",
	AllowedTargets: []string{":22", ":51820"},
})
if err != nil {
	log.Fatal(err)
}
defer srv.Close()

go func() { srv.ListenAndServe(ctx) }() // ctx cancels for graceful stop
```

Set `ServerConfig.Handler` to receive sessions yourself: each accepted
`*tunnel.XHTTPConn` reports what the client asked for via `TargetAddr()` /
`Network()`, and the handler owns the connection.

### Server: mount into your own http.Server

If the application already owns an HTTP server (and its TLS, HTTP/2, routing),
mount the tunnel endpoint instead of giving the tunnel its own port:

```go
srv, _ := tunnel.NewServer(tunnel.ServerConfig{Path: "/stream", PSK: "..."})
defer srv.Close()

mux := http.NewServeMux()
mux.Handle("/stream", srv.Handler()) // Split-HTTP endpoint inside your app
```

Observability: `srv.ActiveSessions()` reports live sessions; `client.ActiveDials()`
reports open client sessions (both share `MaxConns` budgeting, which now also
applies to `DialContext`). Programmatically actionable failures return
`errors.Is`-able sentinels such as `tunnel.ErrSessionLimit`.

Lifecycle & session management:

```go
// Graceful drain: stop accepting, wait for in-flight sessions (deadline
// applies), then force-close whatever is left.
if err := srv.Shutdown(shutdownCtx); err != nil { /* deadline expired */ }

// Inspect and evict sessions (e.g. an admin endpoint):
for _, id := range srv.SessionIDs() { /* ... */ }
srv.Kick(id)     // close one session; the client re-establishes if alive
srv.KickAll()    // close every session
```

Logging is per-instance: `ClientConfig.Logger` / `ServerConfig.Logger` receive
only that instance's log lines, so two tunnels in one process can log to
different sinks. Nil inherits the package logger set via `tunnel.SetLogger`.

### Transport modes (downlink)

`DialConfig.StreamMode` / `ClientConfig` default (`"auto"`) upgrades the
downlink from long-poll to a **streaming GET** (SSE-style: the server pushes
frames into one response body as they arrive) on h2/h3, keeping the bounded
POST uplink unchanged — so deployment requirements are identical to the
legacy mode (no new proxy features needed; nginx `proxy_request_buffering`
stays safe). Uplink throughput no longer shares a round trip with each
downlink chunk.

Negotiation (three layers, cached per `protocol|host|SNI|fingerprint|TransportKey`,
TTL 5 min):

1. **Capability header** — the client sends `X-Downstream: 1`; a legacy server
   answers without `X-Downstream-Accepted` and the client keeps polling.
2. **Path probe** — the server flushes a hello frame immediately; if the first
   frame arrives within `max(2s, 3× measured TTFB)` the path does not buffer
   responses and stream mode is committed.
3. **Watchdog** — an established stream must see a frame (data or 25 s
   keepalive) within 75 s; two consecutive breaks downgrade the endpoint to
   poll mode.

Set `StreamMode: "poll"` to force the legacy mode, `"stream"` to skip
negotiation. Kicked sessions end their stream **without** the close marker so
the client transparently re-establishes (poll parity).

### Low-level building blocks

`DialXHTTP` / `ListenXHTTP` / `XHTTPConn` remain exported for custom wiring on
top of the protocol (the e2e tests in `tunnel/` double as usage examples).
Logging is silent by default — call `tunnel.SetLogger(...)` or set the
`Logger` field on either config to receive the debug/audit trail.

