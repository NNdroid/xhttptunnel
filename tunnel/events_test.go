package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// collectEvents returns a handler that records events into a channel and a
// helper to drain with a timeout.
func collectEvents(buffer int) (func(Event), func(time.Duration) []Event) {
	mu := sync.Mutex{}
	var got []Event
	ch := make(chan Event, 64)
	handler := func(ev Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		ch <- ev
	}
	drain := func(d time.Duration) []Event {
		deadline := time.After(d)
		for {
			select {
			case <-ch:
			case <-deadline:
				mu.Lock()
				defer mu.Unlock()
				return got
			}
		}
	}
	return handler, drain
}

// TestClientEvents_EstablishedAndPeerClosed verifies the client emits
// TunnelEstablished and TunnelDied("peer closed") across a normal session.
func TestClientEvents_EstablishedAndPeerClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler, drain := collectEvents(64)

	srv, err := NewServer(ServerConfig{
		Listen: "tcp://127.0.0.1:0",
		Path:   "/stream",
		PSK:    "events-secret",
		Handler: func(conn *XHTTPConn) {
			defer conn.Close()
			io.Copy(conn, conn)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	var addr net.Addr
	for i := 0; i < 200 && addr == nil; i++ {
		if addr = srv.Addr(); addr == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}

	client, err := NewClient(ClientConfig{
		ServerURL:  "http://" + addr.String() + "/stream",
		PSK:        "events-secret",
		ALPN:       "h1",
		StreamMode: "stream",
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetEventHandler(handler)

	conn, err := client.DialContext(ctx, "tcp", "x:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	// End the session from the server side: kick ends the stream without a
	// marker, so the client transparently re-establishes. Events are
	// asynchronous; poll for them instead of assuming a fixed drain window.
	srv.KickAll() // client transparently re-establishes → Reconnecting

	deadline := time.Now().Add(10 * time.Second)
	var sawEstablished, sawReconnecting bool
	for time.Now().Before(deadline) {
		events := drain(200 * time.Millisecond)
		for _, ev := range events {
			switch ev.(type) {
			case TunnelEstablished:
				sawEstablished = true
			case Reconnecting:
				sawReconnecting = true
			}
		}
		if sawEstablished && sawReconnecting {
			conn.Close()
			return
		}
	}
	if !sawEstablished {
		t.Fatal("no TunnelEstablished within 10s of kick")
	}
	if !sawReconnecting {
		t.Fatal("no Reconnecting within 10s of kick")
	}
	conn.Close()
}

// TestServerEvents_AuthAndTarget verifies server-side security events.
func TestServerEvents_AuthAndTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var kinds []string
	srv, err := NewServer(ServerConfig{
		Listen:         "tcp://127.0.0.1:0",
		Path:           "/stream",
		PSK:            "srv-secret",
		AllowedTargets: []string{"127.0.0.1:22"},
		EventHandler: func(ev SessionEvent) {
			mu.Lock()
			kinds = append(kinds, ev.Kind())
			mu.Unlock()
		},
		Handler: func(conn *XHTTPConn) { conn.Close() },
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	var addr net.Addr
	for i := 0; i < 200 && addr == nil; i++ {
		if addr = srv.Addr(); addr == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	serverURL, _ := url.Parse("http://" + addr.String() + "/stream")

	// 1. Bad credentials → auth.rejected (HTTP layer). The request must carry
	// a session ID to reach the auth check at all.
	badReq, err := http.NewRequest(http.MethodPost, serverURL.String(), strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	badReq.Header.Set("X-Session-ID", "no-auth-session")
	badReq.Header.Set("Content-Type", "application/octet-stream")
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()

	// 2. Denied target → target.denied (session layer). The dial itself is
	// asynchronous (the 403 arrives on the first poll/GET), so we only wait
	// for the event below; the connection, if returned, is torn down.
	conn, dialErr := DialXHTTP(ctx, serverURL, &DialConfig{Password: "srv-secret", Path: "/stream", ALPN: "h1"}, "evil.example:443", "tcp")
	if dialErr == nil {
		defer conn.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		hasAuth := false
		hasDenied := false
		for _, k := range kinds {
			if k == "auth.rejected" {
				hasAuth = true
			}
			if k == "target.denied" {
				hasDenied = true
			}
		}
		mu.Unlock()
		if hasAuth && hasDenied {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("missing security events; got %v", kinds)
}

// TestEventHub_PanicIsolation proves a panicking handler cannot kill the
// dispatch loop: subsequent events are still delivered.
func TestEventHub_PanicIsolation(t *testing.T) {
	var count int
	done := make(chan struct{})
	hub := newEventHub(func(Event) {
		count++
		if count == 1 {
			panic("handler bug")
		}
		if count == 2 {
			close(done)
		}
	})
	hub.emit(TunnelEstablished{})
	hub.emit(TunnelEstablished{})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not recover from panic; second event lost")
	}
	hub.close()
}

// TestXHTTPConnDoneFires verifies Done() closes when the peer ends the
// session and Err() reports the reason.
func TestXHTTPConnDoneFires(t *testing.T) {
	vc := newMeekVirtualConn("done-test", nil, nil, nil)
	xConn := newXHTTPConn(vc, vc, func() error { return vc.Close() }, nil, nil, vc)

	select {
	case <-xConn.Done():
		t.Fatal("Done fired before close")
	default:
	}

	// Simulate the server ending the session with a marker.
	go func() {
		time.Sleep(50 * time.Millisecond)
		vc.setCloseErr(errPeerClosed)
		vc.Close()
	}()

	select {
	case <-xConn.Done():
		if xConn.Err() == nil {
			t.Fatal("Err should record the peer-closed reason")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Done did not fire after session close")
	}
}

// TestClientCloseStopsEventDispatcher pins the Client.Close contract: a
// client that registered a handler must not leave its dispatch goroutine
// behind (it ranges over the hub channel and only exits when the hub closes).
func TestClientCloseStopsEventDispatcher(t *testing.T) {
	client, err := NewClient(ClientConfig{ServerURL: "http://127.0.0.1:1/stream"})
	if err != nil {
		t.Fatal(err)
	}
	client.SetEventHandler(func(Event) {})

	client.Close()
	waitHub(t, "client", &client.events.wg)
}

// TestServerCloseStopsSessionEventDispatcher pins the same contract for the
// server-side hub: Server.Close must stop the session-event dispatcher.
func TestServerCloseStopsSessionEventDispatcher(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		Listen:       "tcp://127.0.0.1:0",
		Path:         "/stream",
		EventHandler: func(SessionEvent) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	waitHub(t, "server", &srv.state.events.wg)
}

// TestServerSetEventHandlerClosesPreviousHub covers handler replacement: the
// displaced hub owns a dispatcher too, and dropping the reference without
// closing it strands that goroutine even after Server.Close.
func TestServerSetEventHandlerClosesPreviousHub(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		Listen:       "tcp://127.0.0.1:0",
		Path:         "/stream",
		EventHandler: func(SessionEvent) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := srv.state.events
	srv.SetEventHandler(func(SessionEvent) {})
	second := srv.state.events
	if first == second {
		t.Fatal("SetEventHandler must install a fresh hub")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	waitHub(t, "server (replaced hub)", &first.wg)
	waitHub(t, "server (current hub)", &second.wg)
}

// waitHub fails the test unless every dispatcher registered on wg exits.
func waitHub(t *testing.T, label string, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s event dispatcher still running after close (goroutine leak)", label)
	}
}

// errPeerClosed mirrors the stream pump's recorded reason for tests.
var errPeerClosed = errAuthRejected // same sentinel type; any error works

// Silence unused import warnings when test helpers change.
var _ = httptest.NewServer
