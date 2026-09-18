package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"
)

// startDenyingServer brings up a server whose allowlist excludes the target
// the tests dial for (127.0.0.1:22), so every session attempt answers 403.
func startDenyingServer(t *testing.T) (*url.URL, string) {
	t.Helper()
	const path = "/stream"
	srv, err := NewServer(ServerConfig{
		Listen:         "tcp://127.0.0.1:0",
		Path:           path,
		PSK:            "denied-secret",
		AllowedTargets: []string{"tcp://192.0.2.1:"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })

	var addr string
	for i := 0; i < 1000 && addr == ""; i++ {
		select {
		case e := <-serveErr:
			t.Fatalf("server failed to start: %v", e)
		default:
		}
		if a := srv.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not bind in time")
	}
	serverURL, err := url.Parse("http://" + addr + path)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return serverURL, path
}

// TestStreamProbeTargetDeniedDoesNotFallBackToPoll locks in the fix for a
// 403 fallthrough: the stream probe used to emit TargetDenied and then return
// errStreamUnavailable, so DialXHTTP read that as "streaming is unsupported
// here" and degraded to long polling — which polls the same handler, gets the
// same 403, and retries it once per second forever. Policy will not change
// while we sit there, so the dial must abort instead.
//
// StreamMode stays "auto" on purpose: that is the configuration where the old
// code handed back a live-looking connection while the poll pump hammered 403s
// in the background.
func TestStreamProbeTargetDeniedDoesNotFallBackToPoll(t *testing.T) {
	serverURL, path := startDenyingServer(t)

	dial := &DialConfig{
		Password:     "denied-secret",
		Path:         path,
		ALPN:         "h1",
		StreamMode:   "auto",
		TransportKey: fmt.Sprintf("denied-%d", helperSeq.Add(1)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := DialXHTTP(ctx, serverURL, dial, "127.0.0.1:22", "tcp")
	elapsed := time.Since(started)

	if err == nil {
		conn.Close()
		t.Fatal("dialing a denied target returned a connection")
	}
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("dial error = %v, want errTargetDenied (expired instead: %v)",
			err, errors.Is(err, context.DeadlineExceeded))
	}
	if elapsed > 5*time.Second {
		t.Errorf("dial took %v; a policy refusal must abort, not degrade to a retry loop", elapsed)
	}
}

// TestPollPumpTargetDeniedStopsThePump covers the other half: with the stream
// path disabled the dial returns a connection eagerly and the poll pump runs in
// the background. A 403 must stop that pump instead of retrying it once a
// second forever.
func TestPollPumpTargetDeniedStopsThePump(t *testing.T) {
	serverURL, path := startDenyingServer(t)

	emit, drain := collectEvents(16)
	dial := &DialConfig{
		Password:     "denied-secret",
		Path:         path,
		ALPN:         "h1",
		StreamMode:   "poll",
		events:       newEventHub(emit),
		TransportKey: fmt.Sprintf("pollpoll-%d", helperSeq.Add(1)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := DialXHTTP(ctx, serverURL, dial, "127.0.0.1:22", "tcp")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	started := time.Now()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, rerr := conn.Read(make([]byte, 16)); rerr == nil {
		conn.Close()
		t.Fatal("read succeeded on a denied target; the pump should have stopped")
	}
	if d := time.Since(started); d > 5*time.Second {
		t.Errorf("pump took %v to stop", d)
	}
	conn.Close()

	var denied, died bool
	for _, ev := range drain(500 * time.Millisecond) {
		switch ev.Kind() {
		case "target.denied":
			denied = true
		case "tunnel.died":
			died = true
		}
	}
	if !denied {
		t.Error("TargetDenied event was not emitted")
	}
	if !died {
		t.Error("TunnelDied event was not emitted alongside the pump abort")
	}
}

// TestStreamProbeAuthStillFailsFast records the existing 401/407 behaviour next
// to the new 403 behaviour, so the two cannot drift apart again.
func TestStreamProbeAuthStillFailsFast(t *testing.T) {
	const (
		secret = "auth-fast-secret"
		path   = "/stream"
	)
	srv, err := NewServer(ServerConfig{Listen: "tcp://127.0.0.1:0", Path: path, PSK: secret})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })

	var addr string
	for i := 0; i < 1000 && addr == ""; i++ {
		if a := srv.Addr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not bind in time")
	}
	serverURL, err := url.Parse("http://" + addr + path)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	dial := &DialConfig{
		// Wrong PSK: the server answers 407.
		Password:     "wrong-secret",
		Path:         path,
		ALPN:         "h1",
		StreamMode:   "auto",
		TransportKey: fmt.Sprintf("authfast-%d", helperSeq.Add(1)),
	}

	conn, err := DialXHTTP(ctx, serverURL, dial, "127.0.0.1:22", "tcp")
	if err == nil {
		conn.Close()
		t.Fatal("dialing with a wrong PSK returned a connection")
	}
	if !errors.Is(err, errAuthRejected) {
		t.Fatalf("dial error = %v, want errAuthRejected", err)
	}
}
