package tunnel

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// newHardenedServer starts a Server with the given policy knobs and an echo
// handler, mirroring newLifecycleServer's bind-wait so tests can dial it.
func newHardenedServer(t *testing.T, ctx context.Context, cfg ServerConfig) (*Server, *url.URL, *DialConfig) {
	t.Helper()
	const secret = "harden-secret"
	cfg.Listen = "tcp://127.0.0.1:0"
	cfg.Path = "/stream"
	cfg.PSK = secret
	if cfg.Handler == nil {
		cfg.Handler = func(conn *XHTTPConn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	var addr net.Addr
	for i := 0; i < 200 && addr == nil; i++ {
		if addr = srv.Addr(); addr == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == nil {
		t.Fatal("server did not bind in time")
	}
	serverURL, _ := url.Parse("http://" + addr.String() + "/stream")
	dial := &DialConfig{Password: secret, Path: "/stream", ALPN: "h1", StreamMode: "stream"}
	return srv, serverURL, dial
}

// TestPerIPSessionCap confirms a single client address cannot occupy more
// than MaxSessionsPerIP sessions even though the global cap is higher, and
// that rejections are counted.
func TestPerIPSessionCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, url, dial := newHardenedServer(t, ctx, ServerConfig{
		MaxSessions:      100,
		MaxSessionsPerIP: 1,
	})

	// First session from 127.0.0.1 succeeds and carries traffic.
	c1, err := DialXHTTP(ctx, url, dial, "x:1", "tcp")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer c1.Close()
	if _, err := c1.Write([]byte("hi")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(c1, got); err != nil {
		t.Fatalf("first read: %v", err)
	}

	// A second, distinct session from the same IP must be refused: no new
	// session is registered and the reject counter advances.
	before := srv.Stats().SessionsRejected
	c2, err := DialXHTTP(ctx, url, dial, "y:2", "tcp")
	if err == nil {
		defer c2.Close()
	}
	// The forced-stream dial returns before the second GET reaches the
	// server, so wait for the rejection to be recorded rather than asserting
	// immediately.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Stats().SessionsRejected > before {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Stats().SessionsRejected <= before {
		t.Fatalf("SessionsRejected did not advance on per-IP refusal (%d)", srv.Stats().SessionsRejected)
	}
	if n := srv.ActiveSessions(); n != 1 {
		t.Fatalf("ActiveSessions = %d, want 1 (per-IP cap must block the 2nd session)", n)
	}
}

// TestProtoVersionEchoAndMin confirms the server advertises its protocol
// generation on every tunnel response, and that MinProtoVersion turns an
// under-version request into HTTP 426 before session handling.
func TestProtoVersionEchoAndMin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, url, _ := newHardenedServer(t, ctx, ServerConfig{MinProtoVersion: 1})
	defer srv.Close()

	// A request with no proto header is below the minimum → 426, and the
	// response still carries the server's advertised version.
	resp, err := http.Get(url.String())
	if err != nil {
		t.Fatalf("GET /stream: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("status = %d with MinProto=1 and no client header, want 426", resp.StatusCode)
	}
	if got := resp.Header.Get(ProtoHeader); got != "1" {
		t.Fatalf("proto echo = %q, want 1", got)
	}

	// A correctly-versioned request passes the gate and reaches the (still
	// unsatisfied) session-id check → 400, proving 426 was about version.
	req, _ := http.NewRequest(http.MethodGet, url.String(), nil)
	req.Header.Set(ProtoHeader, "1")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /stream v1: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusUpgradeRequired {
		t.Fatal("correctly-versioned request was still refused with 426")
	}
}

// TestHealthEndpoint serves a JSON stats snapshot on the configured path and
// leaves the tunnel path unaffected.
func TestHealthEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, url, _ := newHardenedServer(t, ctx, ServerConfig{HealthPath: "/healthz"})

	resp, err := http.Get(url.Scheme + "://" + url.Host + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
	var stats TunnelStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode healthz json: %v", err)
	}
	if stats.ProtoVersion != tunnelProtoVersion {
		t.Fatalf("healthz proto_version = %d, want %d", stats.ProtoVersion, tunnelProtoVersion)
	}
	// Stats must agree with the live registry regardless of concurrency.
	if stats.ActiveSessions != srv.ActiveSessions() {
		t.Fatalf("healthz active=%d but ActiveSessions()=%d", stats.ActiveSessions, srv.ActiveSessions())
	}
}

// TestMaxConnsSlotReleasedOnDeath is the point of auto-release: a session that
// dies TERMINALLY (the server ships the close marker) frees its client
// MaxConns slot even if the caller never calls Close, so a forgetful embedder
// cannot leak itself out of capacity. A transient server vanish is NOT used
// here on purpose — that triggers the tunnel's intended infinite reconnect and
// the slot is legitimately held.
func TestMaxConnsSlotReleasedOnDeath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const secret = "harden-secret"
	// A server that ends every session immediately: the client observes a
	// clean close marker ("peer closed"), a terminal death that fires Done.
	srv, err := NewServer(ServerConfig{
		Listen: "tcp://127.0.0.1:0",
		Path:   "/stream",
		PSK:    secret,
		Handler: func(conn *XHTTPConn) {
			conn.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() { _ = srv.ListenAndServe(ctx) }()
	var addr net.Addr
	for i := 0; i < 200 && addr == nil; i++ {
		if addr = srv.Addr(); addr == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == nil {
		t.Fatal("server did not bind in time")
	}
	serverURL, _ := url.Parse("http://" + addr.String() + "/stream")

	c, err := NewClient(ClientConfig{
		ServerURL:  serverURL.String(),
		PSK:        secret,
		ALPN:       "h1",
		StreamMode: "stream",
		MaxConns:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.DialContext(ctx, "tcp", "x:1")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Deliberately NOT closing conn: the terminal death must free the slot.
	defer conn.Close()
	if c.ActiveDials() != 1 {
		t.Fatalf("ActiveDials = %d, want 1 after dial", c.ActiveDials())
	}

	deadline := time.Now().Add(5 * time.Second)
	for c.ActiveDials() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := c.ActiveDials(); n != 0 {
		t.Fatalf("ActiveDials = %d after terminal death, want 0 (slot leaked)", n)
	}
}
