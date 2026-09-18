package tunnel

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTargetAllowlistPolicyByProtocol proves that a scheme prefix on an
// allowed_targets entry takes effect over a real listener, not only inside the
// matcher: the same address is reachable over TCP and refused over UDP, because
// the client's X-Network header is what the entry is compared against.
func TestTargetAllowlistPolicyByProtocol(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echo, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	var mu sync.Mutex
	var kinds []string
	srv, err := NewServer(ServerConfig{
		Listen:         "tcp://127.0.0.1:0",
		Path:           "/stream",
		PSK:            "scheme-secret",
		AllowedTargets: []string{"tcp://" + echo},
		EventHandler: func(ev SessionEvent) {
			mu.Lock()
			kinds = append(kinds, ev.Kind())
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
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
		t.Fatal("the server never reported its address")
	}
	serverURL, err := url.Parse("http://" + addr.String() + "/stream")
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	dialCfg := &DialConfig{Password: "scheme-secret", Path: "/stream", ALPN: "h1"}

	// Same address, TCP: the tcp:// entry admits it and the built-in bridge
	// must carry bytes both ways.
	conn, err := DialXHTTP(ctx, serverURL, dialCfg, echo, "tcp")
	if err != nil {
		t.Fatalf("tcp dial was refused by a tcp:// allowlist entry: %v", err)
	}
	defer conn.Close()
	payload := []byte("scheme-scoped allowlist")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over the admitted target: %v", err)
	}
	got, err := readFullBefore(conn, len(payload), 10*time.Second)
	if err != nil {
		t.Fatalf("read over the admitted target: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tcp echo = %q, want %q", got, payload)
	}

	// Same address, UDP: the entry restricts the protocol, so the server must
	// refuse the session instead of dialing.
	udpConn, udpErr := DialXHTTP(ctx, serverURL, dialCfg, echo, "udp")
	if udpErr == nil {
		defer udpConn.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		denied := false
		for _, k := range kinds {
			if k == "target.denied" {
				denied = true
			}
		}
		mu.Unlock()
		if denied {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	k := append([]string(nil), kinds...)
	mu.Unlock()
	t.Fatalf("a udp request was not denied by a tcp:// entry; events: %s", strings.Join(k, ","))
}

// TestClientTargetSchemeIsStripped proves that a scheme-prefixed client target
// is tolerated rather than fatal: the server resolves the prefix away before
// both the allowlist check and the dial, so "tcp://host:port" from a client
// passes a scheme-less loopback allowlist and the bridge carries bytes. Left
// unstripped the dialer would receive "tcp://host:port" and fail with "too many
// colons in address". gen-config still refuses the prefix, because it is
// decoration -- the client's protocol comes from X-Network.
func TestClientTargetSchemeIsStripped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echo, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	srv, err := NewServer(ServerConfig{
		Listen:         "tcp://127.0.0.1:0",
		Path:           "/stream",
		PSK:            "scheme-secret",
		AllowedTargets: []string{"127.0.0.1:"},
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
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
		t.Fatal("the server never reported its address")
	}
	serverURL, err := url.Parse("http://" + addr.String() + "/stream")
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{Password: "scheme-secret", Path: "/stream", ALPN: "h1"}, "tcp://"+echo, "tcp")
	if err != nil {
		t.Fatalf("a scheme-prefixed client target was refused by a bare loopback allowlist: %v", err)
	}
	defer conn.Close()
	payload := []byte("scheme on the client target is stripped")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over the stripped target: %v", err)
	}
	got, err := readFullBefore(conn, len(payload), 10*time.Second)
	if err != nil {
		t.Fatalf("read over the stripped target: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}
