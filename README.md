# xhttptunnel

High-Performance Bidirectional Split-HTTP / Meek Streaming Tunnel Server & Client with Session Multiplexing.

## Features

- **Split-HTTP Bidirectional Streaming**: Long-lived uplink POST and a long-lived downlink response — also a POST, carrying `X-Downstream: 1` — with automatic sequence reconstruction.
- **Reliable Packet Ring Buffer**: Bounded, synchronized retransmission and reassembly buffers with backpressure.
- **Auto Self-Signed TLS**: Can generate a pinned RSA certificate for direct TLS deployments.
- **Stun Node Sharing (`gen-uri`)**: One-click encrypted `stun://` share link (plus a plaintext `xhttp://` URI) and terminal ASCII QR code generation for Android & TV.
- **Active Fallback Camouflage**: Proxies requests on paths other than the configured tunnel endpoint to a decoy origin.
- **Embeddable Go SDK**: Client and server live in the [`tunnel`](tunnel/) package — route your own dials through the tunnel, or inject custom socket dialers for interface binding and Android `VpnService.protect()`.

---

## One-Key Management (Linux Server & Client)

### 1. Server Installation (Default)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | sudo bash -s install server
```

The first server installation replaces the published placeholder with a unique
random PSK and stores the configuration as owner-only (`0600`). Existing
placeholder configurations are rejected instead of being started publicly.

### 2. Client Installation (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | sudo bash -s install client
```

### 3. Configuration Options

Every setting resolves through four levels, in decreasing precedence:
**command-line flag > environment variable > interactive prompt > built-in default**.
Anything can be pinned from the CLI, which makes the installer scriptable:

```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/xhttptunnel/main/scripts/install.sh | \
  sudo bash -s install server \
    --host 203.0.113.10 \
    --selfsign-cn www.example.com \
    --fallback https://www.example.com \
    --psk "$(openssl rand -hex 32)" \
    --no-public-targets
```

- **Public IP**: without `--host` the installer probes `api.ipify.org`,
  `ifconfig.me/ip`, `ip.sb/ip`, `myip.dnsabr.com`, `api.ip.sb/ip` and
  `ifconfig.co` (5 s timeout each, first reply wins). If every probe fails the
  install continues with a visible `your-server-ip` placeholder rather than
  aborting; `--no-auto-ip` skips the probe entirely. The resolved host is also
  passed to `gen-uri` as `-host`, and `GEN_URI_HOST` / `GEN_URI_PIN` still take
  precedence over it.
- **PSK**: without `--psk` a server generates a fresh 256-bit token and prints
  it once; a client installs *no* PSK and will not invent one, because a
  freshly generated secret could never authenticate. `--psk ""` opts into
  explicit open mode on either side. Published placeholder tokens are rejected.
- **Target policy**: `--no-public-targets` (the default) writes an
  `allowed_targets` allowlist of `127.0.0.1:` and `localhost:`, so a leaked PSK
  can only reach loopback services. `--allow-public-targets` writes an empty
  list and opens forwarding to any host. `--allowed-targets <list>` (or
  `XHTTPTUNNEL_ALLOWED_TARGETS`) writes the list verbatim, which is how you
  express the middle ground neither preset covers — for example
  `--allowed-targets "tcp://192.168.1.10:, udp://:53"`. Entries are also
  protocol-scoped with a `tcp://` or `udp://` prefix — see `allowed_targets` in
  the config reference for the full grammar. The installer validates the list
  with the same rules as `gen-config`, so a typo fails before the service boots.

The wizard prompts for six things in server mode — public host, port,
`selfsign_cn`, `fallback`, PSK and the target policy — then prints a table of
every resolved value and asks for confirmation. A client install asks for only
three: the public host, the local listen port and the PSK. The target-policy
question is a three-way choice: `n` for loopback only (the default), `y` for
unrestricted, or `t` to type an exact `allowed_targets` list. In client mode the
PSK question defaults to typing it rather than generating one, since a freshly
generated secret could never authenticate. `--non-interactive` skips the
prompts, and it is also selected automatically when stdin is not a terminal, so
piped installs never hang. `--yes` skips just the confirmation prompt.
`install.sh --help` lists all flags.

Other actions: `reconfig [server|client]` re-runs the wizard without touching
the binary or the systemd unit; `uri` / `qr` prints the Stun share URI and QR
code; `start|stop|restart|status|logs` manage the service.

### 4. Upgrade / Uninstall
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

### 5. Generators (`gen-config`, `gen-systemd`, `gen-nginx`)
`install.sh` wraps these three commands; each one is also usable standalone and
all three share one validation and rendering path, so they cannot disagree.

**`gen-config`** (alias `gen-conf`) writes a server or client config. stdout
carries JSON only, so the output can be piped — every message goes to stderr.

```bash
# Server: a random 256-bit PSK is generated and printed to stderr exactly once.
xhttptunnel gen-config -mode server > config.server.json

# Client: keeps the placeholder on purpose. A client must not invent a secret,
# or the file would fail every handshake; the binary refuses to start instead.
xhttptunnel gen-config -mode client > config.client.json

xhttptunnel gen-config -mode server -o /etc/xhttptunnel/config.server.json   # mode 0600
xhttptunnel gen-config -mode server -docs=false                              # drop _description/_fields
```

`-psk-mode` selects the secret: `auto` (default) generates one for a server and
keeps the placeholder for a client; `random` always generates; `placeholder`
emits a template for either; `open` writes an empty PSK. The precedence is
`-psk` / `-psk-file` first — a file keeps the secret off the command line and
out of `ps` — then `-psk-mode`, and `-psk ""` opts into open mode. Publishing an
example token as an explicit `-psk` is a hard error; the placeholder is only an
error when *you* type it — a generator-substituted one warns instead, because
the binary's own check is the hard refusal.

Validation runs before anything is written: `listen`/`target` ports must be
1–65535, `path` and `health_path` must start with `/`, `chunk_size_kb` must be
0 or 16–900, `alpn`/`stream_mode`/`log_level` must be known values, and every
`allowed_targets` entry must be `host:port`, `:port`, `host:`, `[host]` or `*`
— each optionally prefixed `tcp://` or `udp://` to allow only that protocol.
An unbracketed IPv6 literal is rejected, so write `[::1]:22` or `[::1]`. That
check is deliberately stricter than the runtime matcher, which drops an
unparseable entry fail-closed: a typo surfaces at generation time rather than
becoming a rule that looks active but never fires. On a *client* config `target`
must stay bare `host:port` — it travels to the server verbatim as `X-Target`,
and the client selects its protocol from `listen` (`udp://…` opens a UDP
forwarder), not from the target. The server resolves any scheme away from an
incoming `X-Target` before both the allowlist check and the dial, so
`tcp://127.0.0.1:22` from a client would pass a loopback policy and connect
just fine: the prefix you typed is silently ignored, not honoured, so a config
that reads like a protocol selector would be one that does nothing. That is why
`gen-config` refuses it outright rather than leaning on the policy to catch it.
Exits 2 on an invalid config; 0 otherwise, warnings included.

**`gen-systemd`** writes a pure unit — no config JSON appended, so the output
loads with `systemctl` as-is. Only systemd 240+ directives are used (Debian 10
/ Ubuntu 18.04 and newer); `-hardening=false` drops the sandbox block.

```bash
xhttptunnel gen-systemd -mode server -bin /usr/local/bin/xhttptunnel \
  -config /etc/xhttptunnel/config.server.json -user xhttptunnel > xhttptunnel.service
xhttptunnel gen-systemd -mode client -emit-config -force   # unit plus the config it runs
```

Every `ExecStart` argument is quoted, and the config directory is written with
forward slashes regardless of which OS generated the file. `WorkingDirectory`
is pinned to that directory because the self-signed `cert.pem`/`key.pem` are
written to the working directory; with `ProtectSystem=strict` that directory is
also the only writable path. A client unit waits for `network-online.target`,
a server unit for `network.target`. There is no `ExecReload`: the binary has no
SIGHUP handler, so the directive would be a lie.

**`gen-nginx`** writes the origin-side proxy. The default is an `upstream` block
plus a `location` snippet for inside an existing `server{}`; `-server-block`
adds the wrapper, and `-tls` adds the `ssl` listen line — which needs that
wrapper, so `-tls` on its own emits one too.

```bash
xhttptunnel gen-nginx -domain tunnel.example.com -backend 127.0.0.1:8443 \
  -chunk-size-kb 256 -server-block -tls -http2 > /etc/nginx/xhttptunnel.conf
```

`client_max_body_size` is computed as `chunk*1000 + headroom*1024` bytes rounded
up to nginx's 1024-byte `k` — 256 KB plus 128 KB of headroom becomes `378k`,
not `0` (unlimited), which would let one request hold megabytes of body per
connection. `proxy_buffering` and `proxy_request_buffering` are off because the
tunnel streams arbitrarily long bodies, and `proxy_set_header Connection ""` is
set because without it nginx opens a fresh upstream socket per poll, the single
biggest throughput hit on this path. `-scheme auto` picks `https` for a
non-loopback backend or port 443, otherwise `http`; IPv6 backends are bracketed
with or without existing brackets.

**nginx header requirements.** nginx has no `proxy_pass_header` directive.
Request headers are governed by `proxy_pass_request_header`, which is `on` by
default, and response headers by `proxy_hide_header`, which hides nothing by
default. So the tunnel's protocol headers flow through with no configuration at
all:

- *Request* — `X-Auth-Token`, `X-HTTP-Tunnel-Nonce`, `X-HTTP-Tunnel-MAC`,
  `X-HTTP-Tunnel-Body-MAC`, `X-HTTP-Tunnel-Caps`, `X-XHTTP-Proto`, `X-Target`,
  `X-Network`, `X-Session-ID`, `X-Seq`, `X-Ack`, `X-Pad`, `X-Retry`,
  `X-Downstream`, `X-Stream-Resume`, `X-Stream-Probe-Window`, plus
  the camouflage headers `User-Agent`, `Accept`, `Accept-Encoding`,
  `Cache-Control`, `Pragma`, `Content-Type`.
- *Response* — `X-XHTTP-Proto`, `X-Seq`, `X-Ack`, `X-Pad`, `X-Session-ID`,
  `X-HTTP-Tunnel-Caps`, `X-HTTP-Tunnel-Resp-MAC`, `X-Downstream-Accepted`,
  `X-Stream-Uplink-Sync`, `X-Session-Created`, plus
  `Cache-Control`, `Pragma`, `Expires`, `X-Accel-Buffering`.

`X-HTTP-Tunnel-Nonce` and `X-HTTP-Tunnel-MAC` are the v2 credentials. A request
that advertises `X-XHTTP-Proto: 2` commits to the signature and the bare-token
path is closed to it, so it is refused outright rather than downgraded; a
nonce that is missing, malformed, or already seen inside the 120-second
replay window fails validation. If either header is lost in transit the client
simply cannot connect and nothing in the logs points at nginx, so `gen-nginx`
declares it explicitly alongside `X-Auth-Token` — the one place where the
redundancy with `proxy_pass_request_header on` is worth the lines. `X-Pad`
makes a third: a signed request that arrives without it is refused (HTTP 400)
rather than read as carrying no pad at all, so a hop that does not forward the
header cannot forward the request either, and the operator gets a bare 400 with
nothing naming the proxy.

Four headers are still the exception that must be set explicitly, because
nginx's *default* for each is wrong for this tunnel:

| Header | Value | Why the default breaks it |
| :--- | :--- | :--- |
| `Host` | `$host` | nginx defaults to `$proxy_host`, the upstream address, which breaks SNI and virtual-host routing at the origin. |
| `Connection` | `""` | with `proxy_http_version 1.1` this makes nginx reuse the upstream keepalive pool. Left alone nginx sends `Connection: close` and opens a fresh socket per poll — the single biggest throughput hit on this path. |
| `X-Forwarded-For` | `$proxy_add_x_forwarded_for` | the client can send this itself; nginx does not set it by default, so `trust_proxy_headers` would trust whatever the client invented. |
| `X-Real-IP` | `$remote_addr` | same reason. |

Three more things to leave alone: do not enable `gzip` in this `location` (the
tunnel body is opaque bytes and compressing it corrupts the protocol, which is
why the client sends `Accept-Encoding: identity`), do not re-enable
`proxy_buffering` or `proxy_request_buffering`, and keep
`client_max_body_size` at or above `chunk_size_kb` plus the headroom.

The origin also sends `X-Accel-Buffering: no` on every response. nginx reads
that header and disables response buffering for the request, which is a second
line of defence behind `proxy_buffering off` in case someone edits the
`location` and forgets. `Cache-Control` carries `no-store, no-cache,
must-revalidate, max-age=0` on both request and response, plus `no-transform`
on responses; `Pragma: no-cache` is sent on both and `Expires: 0` on responses
only. A plain reverse proxy therefore needs no per-header work either. A CDN in
front is different: none of those headers stops one that is configured to cache
unconditionally, so if a CDN sits between the client and the origin it must be
told not to cache.


### 6. Service Management
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
| `listen` | `string` | `":8443"` | Listen address (`":8443"` for server; `"tcp://127.0.0.1:1080"` for client, where the scheme picks the forwarder protocol — `udp://…` opens a UDP forwarder). |
| `server` | `string` | `""` | Server endpoint URL for client mode (e.g. `"https://example.com:8443/stream"`). |
| `target` | `string` | server `"tcp://127.0.0.1:22"`, client `"127.0.0.1:22"` | Target service address. Server: the scheme is required — it is the dial address and it selects the protocol (`tcp://127.0.0.1:22`, `udp://127.0.0.1:51820`). Client: bare `host:port`, no scheme — it goes to the server verbatim as `X-Target` while the protocol travels separately in `X-Network`, and any scheme you add is stripped before the dial rather than honoured. |
| `default_target` / `forward` | `string` | — | Aliases for `target` (server / client respectively); cross-filled when `target` is set. |
| `path` | `string` | `"/stream"` | Custom Split-HTTP proxy path. |
| `psk` | `string` | none | Pre-shared key / token (aliases `token`/`auth_token`). CLI subcommands require an explicit non-placeholder value; an empty config-file value explicitly enables open mode. |
| `cert` / `key` | `string` | `""` | TLS certificate / private key files. Both empty = cleartext origin (behind a TLS-terminating CDN). |
| `selfsign` | `bool` | `false` | Auto-generate a self-signed TLS certificate if `cert`/`key` are omitted. The sample server config enables it. |
| `selfsign_cn` | `string` | `"www.bing.com"` | Common Name (SNI) for generated certificate. |
| `fallback` | `string` | `""` | Fallback URL for requests whose path does not match the tunnel endpoint. Authentication failures on the tunnel path return `407`. |
| `sni` | `string` | server host | TLS SNI disguise (client). |
| `host` | `string` | server host | HTTP `Host` header disguise (client). |
| `alpn` | `string` | `"auto"` | Transport selection: `h3`, `h2`, `h1`, or `auto` (probe HTTP/3, fall back). |
| `stream_mode` | `string` | `"auto"` | Client downlink transport: `auto` (negotiate), `poll` (legacy long-poll), or `stream` (force streaming downlink). |
| `window_size_mb` | `int` | `0` | Reliable send window per session in MiB: `0` preserves 8 MiB; explicit sizes are 1–64. Available on client and server; the peers do not need matching windows. |
| `buffer_budget_mb` | `int` | `0` | Server admission budget in MiB for active tunnel buffers. `0` preserves the existing session-count limit. A nonzero value reserves each send window, conservative receive capacity and frame scratch before admitting a session; insufficient capacity returns HTTP 503. Excludes HTTP/TLS/QUIC buffers, stacks and total process RSS. |
| `fingerprint` | `string` | `""` | SHA-256 certificate pin, required for self-signed TLS. Empty uses the system CA roots plus SNI hostname verification, which is appropriate for ordinary CDN HTTPS. `gen-uri` reads this field when building a share URI, or derives it from `cert` when the field is empty. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |
| `dump` | `bool` | `false` | Hex-dump tunnelled traffic to stdout (debugging only). |
| `max_sessions` | `int` | `2000` | Server max concurrent sessions. `0` selects the engine default of 2000. |
| `max_sessions_per_ip` | `int` | `0` | Server: cap concurrent sessions from one client address; `0` (engine default) = unlimited. The installer and sample configs ship 50. Bounds one PSK holder's blast radius against the shared registry. Counts the TCP peer address unless `trust_proxy_headers` is on. |
| `max_conns` | `int` | `2000` | Client max concurrent local connections / sessions. `0` selects the engine default of 2000; the installer and the sample configs ship 512. |
| `chunk_size_kb` | `int` | `256` | Upstream payload per poll request (clamped 16–900). Must match on both ends. |
| `padding` | `string` | `"400-600"` | Padding rule for outgoing traffic. `MIN-MAX` pads objects that would reach the wire shorter than `MIN` up into `[MIN,MAX]` and sends longer ones bare; `BELOW:MIN-MAX` sets the threshold explicitly; a comma-separated list is an ordered band list; `off` disables padding. Local egress policy: the peer strips whatever pad arrives, so the ends need not match, and a peer that understands `pad-body` lets the pad move from the frame to the transport so the wire object lands inside the band. Invalid rules fail startup. See [Frame padding](#frame-padding). |
| `idle_timeout` | `int` | `900` | Client: drop a local connection after this many seconds of silence. |
| `allowed_targets` | `[]string` | `[]` | Server: restrict client-requested targets. Each entry is `host:port`, `:port`, `host:`, `[host]` or `*` — an unbracketed IPv6 literal is rejected because its colons are ambiguous, so write `[::1]:22` or `[::1]` — optionally prefixed `tcp://` / `udp://` to admit only that protocol (`udp://:53` = UDP DNS on any host; `tcp://192.168.1.10:` = TCP on any port of that host; a scheme-less `127.0.0.1:` admits either; the prefix is a protocol gate only and is never part of the address that gets dialed). An entry that cannot be parsed matches nothing rather than widening the policy. Enforcement runs at session creation, so a custom `Handler` sees only allowlisted targets too. Empty = allow all. |
| `trust_proxy_headers` | `bool` | `false` | Server: honour `CF-Connecting-IP`/`X-Forwarded-For`/`X-Real-IP` for client-address logging. Enable only behind a trusted proxy that strips them. |
| `health_path` | `string` | `""` | Server: when set (e.g. `/healthz`), expose an unauthenticated JSON stats snapshot (`Server.Stats`) on the tunnel listener. Empty = disabled. Intended for localhost / operator listeners. |
| `min_proto_version` | `int` | `0` | Server: reject (HTTP 426) clients advertising an `X-XHTTP-Proto` below this, to retire an old wire generation or the legacy credential scheme fleet-wide. `0` accepts all clients, including header-less legacy ones. Setting it to `2` forces the signed-nonce scheme: a client advertising version 2 is admitted only by signature, which closes the bare-token fallback. Setting it to `3` additionally retires every generation whose metadata and bodies are outside the signature. |
| `brutal` | object | `{enabled: false}` | Cap the send rate of the tunnel's **TCP** sockets with [TCP Brutal](https://github.com/beef92/tcp-brutal) (a Linux kernel module; inert on other platforms). See [TCP Brutal & bandwidth exchange](#tcp-brutal--bandwidth-exchange). |

For a direct TLS deployment, `:8443` (or `tcp+udp://:8443`) starts HTTPS and HTTP/3 on the same port. Use `tcp://127.0.0.1:8443` for a cleartext CDN origin; without a certificate/key the server intentionally does not bind UDP or advertise HTTP/3.

Size the send window from the bandwidth-delay product, with headroom for ACK
delivery: a 1 Gbit/s path at 100 ms RTT has about 12 MB in flight, so 16 MiB is
a reasonable starting point for measurement. Increasing the window reserves
more memory per active session; it does not increase the bounded receive or
out-of-order queues. For example, use `window_size_mb: 16` and a server
`buffer_budget_mb: 512`, then measure sustained uploads, downloads and
concurrent sessions on the actual path. The admission budget uses conservative
reservations even for idle sessions, and is released when the session closes.
`gen-config` exposes these as `-window-size-mb` and `-buffer-budget-mb`.
`Server.Stats()` and the health snapshot expose `buffer_reserved_bytes` and
`buffer_budget_bytes` when a budget is configured.

Streaming ACKs are coalesced by bytes (32 KiB) and time (10 ms), independently
of keepalives. The downlink response's headers are flushed first; the initial
hello follows admission of the companion POST, so successful Dial proves both
directions were admitted. Active stream I/O deadlines are refreshed rather than
inheriting the HTTP server's absolute request timeout. Reconnects use
exponential backoff with jitter capped at 30 seconds and reset their failure
count after 30 seconds of healthy streaming. A server restart that loses
session state still requires a new application connection; transport resume
preserves an existing session.

`XHTTPConn.SetDeadline`, `SetReadDeadline` and `SetWriteDeadline` apply to
application I/O, including already blocked operations. Clear a deadline with
`time.Time{}` to resume; timeout errors match `os.ErrDeadlineExceeded`. Partial
frame parsing survives a read timeout, and frames that fit the send window are
enqueued atomically so a write timeout cannot leave a partial wire frame.

---

## Quick Start

### 1. Export Stun QR Code & Sharing Link
```bash
xhttptunnel gen-uri -c /etc/xhttptunnel/config.json
```

This prints an encrypted `stun://` share link (with the share PIN the importer asks for), a plaintext `xhttp://` URI, and a terminal ASCII QR code. Pass `-host` for the server's public IP or domain; `-pin` pins the share PIN instead of generating a random one. The port comes from the config's `listen` (with any `tcp://` / `udp://` / `tcp+udp://` prefix stripped), or from `server`'s explicit port; a CDN URL that spells no port means 443, and a client config's `listen` — the local forwarder — is never used as the public port.

**Disguise SNI and Host.** Leave `-sni` empty and the URI takes `selfsign_cn` from the config, which feeds both the TLS SNI and the HTTP `Host` header the node presents to the origin (`customHost` and `serverName` in the shared profile). The value is used regardless of whether `selfsign` is on, since a static certificate paired with a disguise domain still wants it.

**Certificate pin.** `-fingerprint <sha256>` pins the server's certificate, resolving in this order: the `-fingerprint` flag, then the config's `fingerprint` field, then derived automatically from the config's `cert` file. The derived value hashes the raw DER — the same bytes `verifyFingerprint` compares — so it matches `openssl x509 -in cert.pem -outform der | sha256sum` exactly.

The pin reaches the importer through the profile's `verifyCertFingerprint` / `serverCertFingerprint` pair, which is what the Stun client actually verifies against. (An earlier draft wrote a field named `fingerprint`, which is not part of the profile schema: the app dropped it silently, so the QR node fell back to CA verification and a self-signed server could never connect.) Because a pin replaces CA verification outright, the plaintext URI omits `insecure=1` whenever a pin is present — `-insecure` now defaults to off for the same reason.

A pin only helps for a certificate that stays put. `selfsign: true` makes the server generate a fresh certificate into a temp directory at every startup, so nothing stable exists to share: gen-uri prints a warning and emits no pin rather than shipping a fingerprint that breaks after the first restart. Use a static `cert`/`key` pair for a pin that survives restarts, or pass `-fingerprint` to pin the certificate of the current run.

**Share URI shape.** The `sshAddr` field is always bare `host:port`. A `tcp://` prefix in the config's `target` is stripped before it is written, so the profile carries the address the importer needs rather than a scheme that does nothing there — the client's protocol travels separately in `X-Network`, never in the target's scheme. IPv6 origins are bracketed (`[2001:db8::10]:9443`); an unbracketed `2001:db8::10:9443` is not an address any dialer can parse. `tunnelTlsEnabled` is written explicitly as `true` and `alpn` as `auto`, so an imported node tries h3 before h2/h1.1 instead of inheriting the app's h2-only default — otherwise a server listening only on `udp://` would be unreachable after a scan. The link cannot carry SSH credentials: the node imports as `root` with an empty password, so set the real user/password or private key in the app.

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
	PSK:         "deployment-specific-random-secret",
	Fingerprint: "AA:BB:...", // required for a self-signed origin; omit for a CA-backed CDN edge
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
	PSK:       "deployment-specific-random-secret",
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
	PSK:           "deployment-specific-random-secret",
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
srv.Kick(id)     // close one session; the application opens a fresh tunnel
srv.KickAll()    // close every session
```

Logging is per-instance: `ClientConfig.Logger` / `ServerConfig.Logger` receive
only that instance's log lines, so two tunnels in one process can log to
different sinks. Nil inherits the package logger set via `tunnel.SetLogger`.

### Transport modes (downlink)

`DialConfig.StreamMode` / `ClientConfig` default (`"auto"`) upgrades the
downlink from long-poll to a **streaming response** (SSE-style: the server
pushes frames into one response body as they arrive) on h1/h2/h3, paired with a
long-lived POST uplink — so each direction remains a separate HTTP stream and
does not require one request to read and write concurrently. The downlink
request is a POST too, named by `X-Downstream: 1` rather than by its method, so
it is indistinguishable on the wire from the idle polls beside it; a hop that
drops the header hands the origin an ordinary idle poll and the client falls
back on its own. CDN/proxy request and response streaming must remain enabled.
Uplink throughput no longer shares a round trip with each downlink chunk.

Negotiation (three layers, cached per `protocol|host|SNI|fingerprint|TransportKey`,
TTL 5 min):

1. **Capability header** — the client sends `X-Downstream: 1`; a legacy server
   answers without `X-Downstream-Accepted` and the client keeps polling.
2. **Bidirectional readiness + path probe** — after the companion POST passes
   authentication and the per-session admission limit, the server flushes a
   hello frame. If it arrives within `max(5s, 3× measured TTFB)` (capped at
   30 s), both directions are usable and the path does not buffer responses.
3. **Watchdog** — an established stream must see a frame (data or keepalive,
   emitted every 5 s) within 30 s, otherwise it is re-established with resume
   (`X-Ack`), indefinitely and with capped exponential backoff. An established
   session is never demoted to polling: its acknowledged sequence space cannot be
   rebased onto the poll cursor. Only a *failed negotiation* downgrades an
   endpoint.

A failed negotiation downgrades the endpoint for the TTL only after **two
consecutive conclusive** failures. A single sample is not enough, because one
probe can be tripped by a transient edge state (a 429/503 from a CDN, an origin
restarting mid-probe) and every session dialed during the TTL would inherit that
verdict. Two outcomes are explicitly *not* conclusive and never cache anything:

- **Connection setup exceeded the probe window** — a cold TCP/TLS handshake on a
  slow link costs the same seconds a buffering path does, and elapsed time
  cannot tell them apart (`httptrace` separates the phases: if the request never
  reached the origin, nothing is recorded). The session polls, the transport is
  pooled now, and the next dial negotiates again instead of inheriting a
  five-minute downgrade.
- **A non-200 answer from the origin** — the status is named in the fallback log
  line and counted as one sample, but a rate limit or a full origin says nothing
  about whether the path can stream.
- **A session the origin ends before the first byte** — a refused target or a
  session reaped right after admission. The dial fails with that reason rather
  than handing back a connection that is already at EOF, and the endpoint is not
  blamed for the target's refusal.

Downgrades are logged (`endpoint downgraded to long polling after consecutive
failed negotiations`, with the reason and TTL), and concurrent dials that miss
the cache collapse onto one negotiation: the rest wait for its verdict instead of
probing in parallel, so a poll-only path sees one probe per burst rather than one
per connection.

Set `StreamMode: "poll"` to force the legacy mode. `"stream"` requires the
stream handshake to succeed and fails instead of silently falling back. A
transport-only interruption resumes the same server session; if the origin
restarts, reaps, or kicks that session, the client closes the old application
connection explicitly because its acknowledged sequence space cannot be
safely rebased. The application can then open a fresh tunnel.

### Frame padding

Padding shapes every object this process puts on the wire, and each object
carries exactly one pad. The rule measures the object as it lands — headers
included — so a 20-byte keystroke leaves a 400..600-byte object rather than a
payload plus whatever header happened to precede it.

The default `400-600` reads: an object that would reach the wire shorter than
400 bytes is padded so its total lands uniformly at random in 400..600, and
anything already that long is sent as it is. Because the bare range starts
exactly where the band does, both halves occupy the same window on the wire — a
keystroke and a 500-byte record leave the same size, which is the point. The
previous built-in shape (small payloads into 600..1200, bulk always plus
16..127) did not have that property, and it left the control frames a disjoint
38..165-byte cluster.

#### Where the pad goes

The session frames a write before it reaches the ring, so both transports hand
out the same bytes: the streaming envelope wraps a run of them, and the long-poll
body ships a run verbatim. Two layers could pad, and padding at both would stack
— an envelope header on top of an already padded frame overshoots the band by
the header's width. So exactly one of them does:

- **Unnegotiated, with any peer.** The frame layer pads. A frame's own pad field
  lives in the 6-byte header every peer already parses, so this needs no
  handshake and a mixed-version pair gets the full benefit in both directions.
  The envelope then measures the chunk it is about to wrap, its own 22 header
  bytes included, and pads only if the rule still asks for it: with the default
  band the inner pad has already cleared the 400-byte threshold, so the envelope
  adds its header and nothing else and every streamed object sits 22 bytes above
  the band. A band that starts above the chunk's size re-bands it at the
  envelope, so that object lands inside the band with a frame pad it did not
  need — the shape is right, the bytes inside it are wasted.
- **Negotiated.** Both ends advertise `pad-body` in `X-HTTP-Tunnel-Caps`.
  Padding moves out to the transport — the streaming envelope's own pad field,
  or a poll body's leading pad — and the frame layer leaves its pad field at
  zero. The wire object then lands inside the band: 400..600 on both
  transports, with no header to account for because the pad now counts it. The
  send window benefits too, since the ring carries bare frames.

Either way the ends may use different rules: a mismatch changes the traffic
shape, never the payload.

The rule is a short ordered band list; the first matching band wins:

| Rule | Meaning |
| :--- | :--- |
| `off` / `none` | No padding at all. |
| `auto` / `default` / empty | The built-in `400-600`. |
| `MIN-MAX` | Threshold is `MIN`, a wire size: objects that would reach the wire below it land in `[MIN,MAX]`, longer ones are sent bare. |
| `BELOW:MIN-MAX` | The same with an explicit threshold, e.g. `512:600-1199` for the old shape. |
| `A,B,...` | Several bands, matched in increasing threshold order. |

`23:120-200,400:400-600`, for instance, lifts the frame layer's control
objects — a bare 6-byte ack or keepalive — into 120..200 bytes and puts
everything else under 400 into the main band, so the control channel is not the
only traffic on the wire shorter than it.

A threshold is exclusive: a band with threshold `T` catches objects of at most
`T-1` bytes. That is why the numbers read one past the object they are meant to
catch, and why they have to clear its header — `7` catches a 6-byte frame, and
`23` catches a bare 22-byte streaming envelope. A streamed control object is
that envelope plus a frame, so 28 bytes and up: covering it at the transport
layer needs a threshold of `29`, not `23`. A threshold at or below the header
size matches only objects that cannot exist — `1:120-200` pads nothing, because
the smallest frame is already 6 bytes — and a spec is rejected only when the
numbers contradict each other, not when a band is simply unreachable. Thresholds
must increase, and a band's lower bound must be at least `threshold-1`
(otherwise its longest object already exceeds its own target and the pad would
be negative); a spec that breaks either rule fails startup naming the band.

Things worth knowing before changing it:

- **The close marker is padded too.** It used to be a bare six-byte write — the
  only object of that size on the wire, and therefore an exact signature for "a
  tunnel just closed". It is identified by its length field, so padding it is
  invisible to the reader and to older peers.
- **Where the pad is charged depends on the negotiation.** Unnegotiated, the
  session conn frames every write before it reaches the ring, so the ring carries
  frames: a 20-byte write occupies 400..600 bytes of send window and the peer's
  reassembly holds that frame until `XHTTPConn.Read` strips the pad. Negotiated,
  the ring carries bare 26-byte frames and the pad exists only in the envelope or
  the poll body, so the window is sized for payload. Watch `window_size_mb` when
  a rule uses a large band and the peer may be an older one.
- **Padding stops at `MIN`.** Bulk transfer keeps exact sizes. Covering those
  would cost a 20× overhead per record for a size an observer can already
  estimate from the tunnel's throughput.
- **Bands are capped at 65535 bytes**, the width of the pad field. A larger band
  would be truncated on the wire and the reader would then strip the wrong number
  of bytes, handing the application padding as if it were payload — a silent
  corruption, not a shape change.
- **The long-poll transport is covered either way.** Unnegotiated, a poll body is
  a run of padded frames and its `Content-Length` lands in the band like any
  other frame — which is why `WriteUDPFrame` joins its length prefix to the
  payload instead of issuing two writes, since one frame per `Write` is what
  makes that hold. Negotiated, the frames go out bare and the body carries a
  pad in front, so `Content-Length` — the pad plus the frames — still describes
  the object an observer sees.
- **The pad's length travels as a signed, masked header.** It rides in `X-Pad`,
  but never in the clear: it is XORed with the same per-request keystream as
  the counters and it is inside the signed message, so an observer holding it
  cannot subtract it from `Content-Length` to learn the payload exactly, and a
  hop that moves or deletes it also destroys the request's credentials. The
  reader then drops a known number of bytes instead of guessing where the
  padding ended. A signed request must state its pad, including when the
  answer is none: a request that leaves it unsaid — even one signed correctly
  over an absent pad — is refused (HTTP 400) rather than read as carrying no
  pad, because that reading is the one that hands the padding to the
  reassembly as payload. Making the pad self-delimiting in its own bytes was
  the first design tried here and it does not hold: a poll body is a slice of
  the send window, so it can begin at any byte of a frame, and the length in
  front of it is whatever payload happened to be there.
- **Idle polls are POSTs, not GETs.** Every request in a session now has a body
  and the same method, including the ones with nothing to send: an idle poll
  carries a body of nothing but pad, the same way the empty response it waits
  on does. A GET was readable from a long way off — the method differed from
  every other request, and its zero-byte body was the one size no padding rule
  can smooth, because there was nothing there to pad.
- **Both directions of the pad ride on the one capability**: the client pads a
  request body once it has seen the server echo the capability, and the server
  pads a response once the request has advertised it. The client re-reads the
  echo on every response rather than latching on the first one, because a
  session outlives any single node and a fleet mid-upgrade mixes builds — a
  body padded for a node that does not look for the pad would have its padding
  delivered as payload. Losing the echo puts the pad back in the frame, which
  every peer can read.

`gen-config` exposes it as `-padding`. Embedders have two ways in, both landing
on the same process-wide policy:

- **Declaratively**, through `ClientConfig.Padding` or `ServerConfig.Padding`
  (same syntax; empty leaves the current policy alone). An invalid rule is
  rejected by `NewClient`/`NewServer` naming the field.
- **Imperatively**, through `tunnel.SetPadding` at startup, with
  `tunnel.PaddingSpec` reading back the normalised rule (`400:400-600`, `off`).
  An imperative call decides the rule for the process: a config field asking for
  something else later fails at construction (empty, or the same rule, is fine),
  so a deliberate override is never replaced without a word.

A declaration is checked against the rule actually in force rather than against
a history of declarations. Restating the current rule is a no-op — there is
nothing to disagree about — and asking for a different one fails naming whatever
decided it: a `SetPadding` call, or an earlier config. That covers two configs
in one process disagreeing (the second `NewClient`/`NewServer` fails instead of
quietly reshaping the traffic of the instance that declared first — padding is a
property of the process, not of a single client or server) and one config
disagreeing with an explicit override. The same rule spelled differently
(`400-600` vs `400:400-600`, `none` vs `off`) compares equal, since the
comparison uses the compiled band list.

### TCP Brutal & bandwidth exchange

`brutal` caps how fast the tunnel's **TCP** sockets may send, using the
[TCP Brutal](https://github.com/beef92/tcp-brutal) Linux kernel module. It is
an optimisation, never a dependency: a socket failure never fails a tunnel
connection, and the only things that abort startup are configuration mistakes.

```json
"brutal": {
  "enabled": false,
  "rate": 0,
  "cwnd_gain": 20,
  "group_id": 0,
  "group_from_remote": false,
  "bw_exchange": false,
  "bw_advertise": 0,
  "bw_interval": 60
}
```

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `enabled` | `false` | `false` calls `setsockopt` never, so it costs nothing on hosts without the module. |
| `rate` | `0` | Send ceiling in bytes/s. `0` is rejected unless `bw_exchange` supplies one. |
| `cwnd_gain` | `0` → `20` | Congestion window gain in tenths, so `20` = 2.0x. `0` takes the default, above `100` is rejected. |
| `group_id` | `0` | Non-zero members share `rate` as an aggregate ceiling; `0` = per-connection only. |
| `group_from_remote` | `false` | Server only. Derives the group from the peer's address. |
| `bw_exchange` | `false` | Enables the bandwidth exchange protocol. |
| `bw_advertise` | `0` | Bytes/s this side can ingest, offered to the peer. `0` = don't offer anything (the peer's value is still accepted). |
| `bw_interval` | `60` | Minimum gap between exchange attempts, in seconds. |

**Why `group_from_remote` on a server.** A static `group_id` pools *every*
client into one aggregate ceiling, which turns a per-connection cap into a
global one. Servers should set `group_from_remote` instead, which derives the
group from the TCP peer's IP (not the proxy headers — the kernel names a group
by the connection, so a spoofable header would let a client choose its own
group and its own ceiling). A client keeps its static `group_id`, since one
client→server TCP connection already multiplexes all of its sessions.

**Bandwidth exchange.** The exchange reuses the target field with the
reserved address `_BrutalBwExchange`, and adds two headers in the existing
`X-HTTP-Tunnel-*` family:

- `X-HTTP-Tunnel-Bw` — this side's **ingest** ceiling in bytes/s. The rule is
  symmetric on both ends: **the peer's advertised value becomes this side's
  send rate.** A client advertising its downlink makes the server slow its
  uplink to it; the server advertising its ingest capacity makes the client
  slow its uplink to it. The two ends converge on the slower link.
- `X-HTTP-Tunnel-Caps: brutal-bw` — tells a client the server implements the
  exchange, so no protocol version bump is needed.

`rate` is a ceiling the exchange can only **lower**, never raise, which also
bounds a hostile advertisement:

```go
mergeBrutalRate(static, advertised) // advertised == 0 → static; else min(static, advertised)
```

Anything outside `0 < v <= 1e12` is ignored and logged, keeping the old value —
applying zero would stall the connection.

On the server the exchange branch sits **after** authentication (the signed
nonce binds `_BrutalBwExchange` like any other target, with no changes to the
auth machinery) and **before** the allowlist, so the special target is never
rejected as an unparseable address. It registers no session, so it does not
count against `max_sessions` or `max_sessions_per_ip`.

The server keeps a per-group rate table because a group's kernel state exists
only while at least one member is open: once the last member closes the state
vanishes and a new member would otherwise start at kernel defaults. The table
carries the negotiated value across that gap.

**Backwards compatibility.** The protocol surface is purely additive. An older
server rejects `_BrutalBwExchange` as an unparseable target and returns a
non-200; the client treats that as permanent, logs once and stops probing — at
most one session wasted per process, and `offeredProtoVersion` does not move.

**Where it does not apply.** HTTP/3 runs over QUIC/UDP and is never capped;
the server's UDP listener and its server→target backend connections are
untouched. The exchange is skipped entirely when the negotiated protocol is
`h3`.

**Verification.** A successful enable is logged once at `debug` level
(`⚡ [TCP] brutal enabled`). Check the kernel side:

```bash
cat /proc/net/tcp_brutal/rules        # rate / cwnd_gain / group_id per route
ss -ti | grep -A2 'congestion'        # expect brutal on the tunnel socket
```

If a `brutalctl` locked rule owns the route, `setsockopt` returns `EPERM`;
that connection is reported as a success and left with the rule's parameters,
logged once as `🔒 [TCP] a locked TCP Brutal route rule owns this connection`.
On a kernel with no brutal module the tunnel still works uncapped, logged once
as `⚠️ [TCP] TCP Brutal requested but the kernel has no brutal module loaded`.

Group features need a module of version 2.0.0 or newer: that is the first one
whose `struct brutal_params` carries `group_id`. An older module accepts the
`brutal` algorithm name but rejects the 20-byte struct, so there is nothing to
fall back to — the connection runs uncapped and the refusal is logged once.
`group_id`, `group_from_remote` and the per-group rates set by the bandwidth
exchange are unaffected on hosts that do have groups, which is every current
release.

### Protocol versioning & operational hardening

- **Wire-protocol generation.** Every tunnel request carries
  `X-XHTTP-Proto`; the generation a current client announces is 3. A client
  refuses to speak to a server advertising a *newer* generation (a hard error,
  not a poll fallback — a changed frame layout must not be polled by an older
  reader). An operator can force the fleet off a retired generation with
  `min_proto_version`: requests whose advertised version is lower (including
  header-less legacy clients) get HTTP 426. Bumping is deliberately not one
  constant: `tunnelProtoVersion` is what the frame layout and the response
  header track, `authProtoVersion` is the generation that first required a
  signed nonce — the one `min_proto_version` is compared against, so raising the
  offered generation cannot quietly reopen the bare-token path for an operator
  who pinned 2 — and `bodyProtoVersion` marks the generation that signs its
  metadata and bodies. A client announces `offeredProtoVersion`, the highest of
  them.
- **Signed credentials.** The PSK never crosses the wire. Each request carries
  a fresh nonce plus its HMAC-SHA256 over a message that binds the nonce, the
  session id, the network and the target — and, from generation 3, everything
  else the dispatcher acts on (see the next bullet). A captured request
  therefore leaks nothing and cannot be replayed or retargeted: the nonce is
  consumed in a 120 s replay
  window keyed per server, and the session id, network and target are bound
  into the signature, so a signature cannot be lifted onto another session,
  aimed at a different address, or switched to a different transport protocol.
  Legacy
  clients that still send the bare token (`Proxy-Authorization` /
  `X-Auth-Token`) are accepted during the migration window — upgrade servers
  first, then clients — and a client that advertises protocol version 2 is
  admitted only by signature, which is what makes `min_proto_version: 2` a real
  switch for retiring the bare-token path. Both credential headers are scrubbed
  before fallback camouflage forwards a request to the disguise target.
- **Signed metadata and signed bytes.** Generation 3 binds the rest of the
  request into the signature: the sequence numbers that place a body in the
  stream, the length of the pad in front of it, and a digest of the body
  itself. A hop that rewrites any of them is refused instead of being believed
  — it used to be able to move a body within the stream or change the bytes,
  and the request still authenticated, because the counters and the body were
  outside the signed message. The downlink gets the same treatment: a response
  is signed under the nonce of the request that asked for it, so one cannot be
  lifted onto another request. A body that is a continuous stream rather than a
  bounded object says so in the signed message too, and does not sign a digest
  it has no end to take: the kind is drawn by both ends from the same header,
  so a mismatch between them is a refusal rather than a misread.
- **The counters travel masked.** They are XORed with a per-request keystream
  derived from the PSK and the nonce, so an observer holding the nonce and a
  year of traffic has no counters to difference. The mask is applied per
  field: a counter the sender left off the wire is not one, rather than being
  unmasked into the mask bytes.
- **A tampered body closes the session.** A body that does not match its
  signature is not a client bug, and it is not retried: the two ends disagree
  about what was sent, so the session ends and the `body.tampered` event is
  emitted for the operator.
- **CORS is narrowed on request.** Responses answer
  `Access-Control-Allow-Origin: *` by default, because that is what a
  browser-based client behind a CDN needs and what every earlier build sent.
  Set `ServerConfig.CORSOrigin` to one origin when the endpoint is reachable
  from pages you do not control: a wildcard answers a cross-origin fetch from
  anywhere, and the counters in that response are readable without the PSK.
- **Per-IP session cap.** `max_sessions_per_ip` bounds how many live sessions
  one client address may hold, so a single leaked PSK or a compromised host
  cannot exhaust the global `max_sessions` and starve everyone else. Off by
  default; the global cap always still applies.
- **Stats & health endpoint.** `Server.Stats()` returns monotonic counters
  (sessions created / rejected / kicked / reaped, request total, live gauge,
  and `proto_version` — the frame-layout generation the server advertises,
  `tunnelProtoVersion`, which is `1` and not the `X-XHTTP-Proto` generation a
  client announces). Setting
  `health_path` (e.g. `/healthz`) serves them as
  JSON on the tunnel listener — unauthenticated, so point it at a
  localhost/operator address, not the public one.
- **Connection-slot reclamation.** A client `MaxConns` slot is released when
  the tunnel dies **terminally** (peer close marker, auth rejection, server
  session recreation) even if
  the embedder never calls `Close` — a forgotten dead session cannot leak the
  pool dry. A transient server *vanish* intentionally does **not** release it:
  the client keeps reconnecting to resume, so the slot stays reserved while
  recovery is in flight.

HTTP/3 (QUIC) keeps Go's native TLS stack: `quic-go` hard-codes
`tls.QUICClient` in its internal handshake and cannot take a `crypto/tls`
replacement without a forked `quic-go`, so the HTTP/3 client does not carry
the uTLS browser-mimicry the h1/h2 clients do.

HTTP/2 is slower than HTTP/1.1 on request/response traffic. That gap was
probed for a tunable flow-control cause: `x/net/http2` does expose per-stream
and per-connection windows on the server and a client read-frame buffer, but
a controlled same-machine A/B found **no reliable gain** — raising the client
`MaxReadFrameSize` (16 KiB default → 256 KiB) landed within run-to-run noise,
and the h2 benchmark swings several-fold with transient machine load, so single
measurements mislead. No HTTP/2 tuning is applied; the gap is treated as
inherent per-stream overhead and `h1` remains the default fast path. To keep
this investigation reproducible instead of eyeballing noisy `ns/op`, CI runs a
`profiling` job (see `.github/workflows/test.yml`) that captures CPU, block
and memory profiles for `h1/h2/h3` and `ThroughCDN`, publishes them as
downloadable artifacts and an SVG set, and prints pprof top tables (including
block-wait breakdowns) into the run summary.

### Low-level building blocks

`DialXHTTP` / `ListenXHTTP` / `XHTTPConn` remain exported for custom wiring on
top of the protocol (the e2e tests in `tunnel/` double as usage examples).
Logging is silent by default — call `tunnel.SetLogger(...)` or set the
`Logger` field on either config to receive the debug/audit trail.
