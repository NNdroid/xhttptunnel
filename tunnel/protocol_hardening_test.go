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
	// Admission and the stream hello are synchronized, but the stats update is
	// still observed asynchronously by the test goroutine.
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
// under-version request into HTTP 426. Under strict mode the gates run in
// order: the salt gate (400), then authentication (407), and only then the
// version gate — so 426 is reachable only from a request that already
// authenticated.
func TestProtoVersionEchoAndMin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, serverURL, _ := newHardenedServer(t, ctx, ServerConfig{
		MinProtoVersion: 1,
		AllowedTargets:  []string{"127.0.0.1:9"},
	})
	defer srv.Close()

	// A request with no salt is refused at the salt gate, which runs before
	// the version gate. The response still carries the server's advertised
	// version under the default names — all an unauthenticated client can
	// read.
	resp, err := http.Get(serverURL.String())
	if err != nil {
		t.Fatalf("GET /stream: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d with no salt, want %d (the salt gate answers first)", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get(defaultNamer.name(slotProto)); got != "1" {
		t.Fatalf("proto echo = %q, want 1", got)
	}

	// A correctly-versioned signed request passes both gates and reaches
	// session handling — the allowlist's 403 here, not 426.
	req := signedRequestFor(t, "harden-secret", http.MethodGet, "hardening-sid", "tcp", "127.0.0.1:7", nil)
	if got := authTestStatus(t, serverURL, req); got != http.StatusForbidden {
		t.Fatalf("signed request: status = %d, want %d (past the version gate)", got, http.StatusForbidden)
	}

	// MinProto above the offered generation: the version gate is live. The
	// request authenticates first, then is refused with 426.
	srv2, serverURL2, _ := newHardenedServer(t, ctx, ServerConfig{
		MinProtoVersion: offeredProtoVersion + 1,
		AllowedTargets:  []string{"127.0.0.1:9"},
	})
	defer srv2.Close()
	req2 := signedRequestFor(t, "harden-secret", http.MethodGet, "hardening-sid", "tcp", "127.0.0.1:7", nil)
	if got := authTestStatus(t, serverURL2, req2); got != http.StatusUpgradeRequired {
		t.Fatalf("under-version signed request: status = %d, want %d", got, http.StatusUpgradeRequired)
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
	// A server that ends the session after Dial returns: the client observes a
	// clean close marker ("peer closed"), a terminal death that fires Done.
	endSession := make(chan struct{})
	defer close(endSession)
	srv, err := NewServer(ServerConfig{
		Listen: "tcp://127.0.0.1:0",
		Path:   "/stream",
		PSK:    secret,
		Handler: func(conn *XHTTPConn) {
			select {
			case <-endSession:
			case <-ctx.Done():
			}
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
	endSession <- struct{}{}

	deadline := time.Now().Add(5 * time.Second)
	for c.ActiveDials() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := c.ActiveDials(); n != 0 {
		t.Fatalf("ActiveDials = %d after terminal death, want 0 (slot leaked)", n)
	}
}
