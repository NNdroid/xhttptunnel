package tunnel

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSetChunkSizeKBClamping(t *testing.T) {
	cases := []struct {
		name     string
		in       int
		wantSize int // bytes
	}{
		{"default", 0, 256 * 1000},
		{"in-range", 512, 512 * 1000},
		{"too-small-clamps-to-16k", 1, 16 * 1000},
		{"negative-treats-as-default", -5, 256 * 1000},
		{"too-big-clamps-to-900k", 10000, 900 * 1000},
		{"exact-max", 900, 900 * 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SetChunkSizeKB(tc.in)
			if got := currentMaxSendBufSize(); got != tc.wantSize {
				t.Fatalf("maxsendBufSize = %d, want %d", got, tc.wantSize)
			}
			if got := currentMaxFrameSize(); got != tc.wantSize+framePaddingBudget {
				t.Fatalf("maxframeSize = %d, want %d", got, tc.wantSize+framePaddingBudget)
			}
		})
	}
	// Restore defaults so parallel tests are not affected.
	SetChunkSizeKB(0)
}

func TestNewClientDefaults(t *testing.T) {
	// Zero-value tunables must map onto the documented defaults, and SNI/Host
	// must derive from the server URL when not overridden.
	c, err := NewClient(ClientConfig{ServerURL: "https://cdn.example.test:8443/stream"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.maxConns != defaultMaxClientConns {
		t.Errorf("maxConns = %d, want %d", c.maxConns, defaultMaxClientConns)
	}
	if c.idleTimeout != defaultClientIdleTimeout {
		t.Errorf("idleTimeout = %v, want %v", c.idleTimeout, defaultClientIdleTimeout)
	}
	if c.dialCfg.ALPN != "auto" {
		t.Errorf("ALPN = %q, want auto", c.dialCfg.ALPN)
	}
	if c.dialCfg.SNI != "cdn.example.test" {
		t.Errorf("SNI = %q, want cdn.example.test", c.dialCfg.SNI)
	}
	if c.dialCfg.Host != "cdn.example.test:8443" {
		t.Errorf("Host = %q, want cdn.example.test:8443", c.dialCfg.Host)
	}
	if c.dialCfg.Path != "/stream" {
		t.Errorf("Path = %q, want /stream", c.dialCfg.Path)
	}

	// Explicit overrides win over the derived values.
	c2, err := NewClient(ClientConfig{
		ServerURL:   "https://cdn.example.test/stream",
		SNI:         "sni.example.test",
		Host:        "host.example.test",
		ALPN:        "h2",
		MaxConns:    42,
		ChunkSizeKB: 384,
		// IdleTimeout below one second is indistinguishable from "unset" for
		// the defaulting rule; assert the override with a real value.
		IdleTimeout: 42 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient override: %v", err)
	}
	if c2.dialCfg.SNI != "sni.example.test" || c2.dialCfg.Host != "host.example.test" || c2.dialCfg.ALPN != "h2" {
		t.Errorf("overrides not applied: %+v", c2.dialCfg)
	}
	if c2.maxConns != 42 || c2.idleTimeout != 42*time.Second {
		t.Errorf("tunables not applied: maxConns=%d idle=%v", c2.maxConns, c2.idleTimeout)
	}
	if c2.dialCfg.ChunkSizeKB != 384 {
		t.Errorf("ChunkSizeKB = %d, want 384", c2.dialCfg.ChunkSizeKB)
	}
}

func TestClientChunkSizeIsPerClient(t *testing.T) {
	SetChunkSizeKB(256)
	c1, err := NewClient(ClientConfig{ServerURL: "https://one.example/stream", ChunkSizeKB: 128})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewClient(ClientConfig{ServerURL: "https://two.example/stream", ChunkSizeKB: 512})
	if err != nil {
		t.Fatal(err)
	}
	if c1.dialCfg.ChunkSizeKB != 128 || c2.dialCfg.ChunkSizeKB != 512 {
		t.Fatalf("per-client chunk sizes lost: c1=%d c2=%d", c1.dialCfg.ChunkSizeKB, c2.dialCfg.ChunkSizeKB)
	}
	if got := currentMaxSendBufSize(); got != 256*1000 {
		t.Fatalf("constructing clients changed package default to %d", got)
	}
}

func TestNewClientPropagatesInjectedDialer(t *testing.T) {
	dialer := func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	}
	c, err := NewClient(ClientConfig{
		ServerURL:   "https://cdn.example.test/stream",
		DialContext: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.dialCfg.DialContext == nil {
		t.Fatal("custom TCP dialer was not propagated")
	}
	if c.dialCfg.TransportKey == "" {
		t.Fatal("custom dialer did not receive an isolated transport namespace")
	}
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Error("empty ServerURL must be rejected")
	}
	if _, err := NewClient(ClientConfig{ServerURL: "ftp://example.com/stream"}); err == nil {
		t.Error("non-HTTP scheme must be rejected")
	}
	// An invalid StreamMode must fail loudly, not silently disable (or force)
	// the streaming downlink.
	if _, err := NewClient(ClientConfig{ServerURL: "http://127.0.0.1:1/stream", StreamMode: "strem"}); err == nil || !strings.Contains(err.Error(), "invalid StreamMode") {
		t.Fatalf("invalid StreamMode must be rejected, got err=%v", err)
	}
	for _, ok := range []string{"", "auto", "poll", "stream", "POLL"} {
		if _, err := NewClient(ClientConfig{ServerURL: "http://127.0.0.1:1/stream", StreamMode: ok}); err != nil {
			t.Errorf("StreamMode %q must be accepted: %v", ok, err)
		}
	}
	// StreamMode must reach the dial config used by DialContext.
	c, err := NewClient(ClientConfig{ServerURL: "http://127.0.0.1:1/stream", StreamMode: "poll"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.dialCfg.StreamMode != "poll" {
		t.Fatalf("StreamMode not wired to dial config: %q", c.dialCfg.StreamMode)
	}

	c, err = NewClient(ClientConfig{ServerURL: "http://127.0.0.1:1/stream"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// DialContext only accepts the transports the protocol defines.
	if _, err := c.DialContext(context.Background(), "unix", "/tmp/sock"); err == nil {
		t.Error("unix network must be rejected")
	}
}

func TestServerStateIsolation(t *testing.T) {
	// Two servers must not share a session registry or policy: instance
	// scoping is the reason Server exists alongside the legacy low-level API.
	st1 := newServerState(2)
	st2 := newServerState(0)

	if st1.maxSessions != 2 {
		t.Errorf("st1.maxSessions = %d, want 2", st1.maxSessions)
	}
	if st2.maxSessions != defaultMaxSessions {
		t.Errorf("st2.maxSessions = %d, want %d", st2.maxSessions, defaultMaxSessions)
	}

	st1.setAllowedTargets([]string{"127.0.0.1:22"})
	st2.setAllowedTargets([]string{":8080"})
	if !st1.targetAllowed("127.0.0.1:22") || st1.targetAllowed("10.0.0.1:8080") {
		t.Error("st1 allowlist not honoured")
	}
	if !st2.targetAllowed("10.0.0.1:8080") || st2.targetAllowed("127.0.0.1:22") {
		t.Error("st2 allowlist not honoured")
	}

	// Registry capacity: st1 caps at 2 sessions, st2 at the default.
	for i := 0; i < 2; i++ {
		if !st1.addSession(string(rune('a'+i)), newMeekVirtualConn("s1", nil, nil, nil)) {
			t.Fatalf("st1 rejected session %d below capacity", i)
		}
	}
	if st1.addSession("overflow", newMeekVirtualConn("over", nil, nil, nil)) {
		t.Error("st1 admitted a session beyond capacity")
	}
	if !st2.addSession("free", newMeekVirtualConn("s2", nil, nil, nil)) {
		t.Error("st2 must have its own registry capacity")
	}

	st1.stop()
	if _, ok := st1.getSession("a"); ok {
		t.Error("st1.stop must sweep registered sessions")
	}
	// The default state must never be stopped by instance lifecycle calls.
	st1.stop()
	st2.stop()
}
