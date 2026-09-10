package tunnel_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/NNdroid/xhttptunnel/tunnel"
)

// TestMountedHandler_BridgesSessions proves Server.Handler() works when the
// Split-HTTP endpoint is mounted inside an externally owned http.Server: the
// client dials through the external server, and sessions flow into the
// configured ServerConfig.Handler (here: echoing bytes back).
func TestMountedHandler_BridgesSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := tunnel.NewServer(tunnel.ServerConfig{
		Path: "/stream",
		PSK:  "mounted-secret",
		Handler: func(conn *tunnel.XHTTPConn) {
			defer conn.Close()
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					if _, werr := conn.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	// The external HTTP server the embedder owns.
	mux := http.NewServeMux()
	mux.Handle("/stream", srv.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "sessions=%d", srv.ActiveSessions())
	})
	external := httptest.NewServer(mux)
	defer external.Close()

	serverURL, err := url.Parse(external.URL + "/stream")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	client, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerURL: serverURL.String(),
		PSK:       "mounted-secret",
		ALPN:      "h1",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	conn, err := client.DialContext(ctx, "tcp", "echo-target-does-not-matter:1")
	if err != nil {
		t.Fatalf("dial through mounted tunnel: %v", err)
	}
	payload := []byte("hello through a mounted handler")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
	if srv.ActiveSessions() < 1 {
		t.Fatal("ActiveSessions should report the live session")
	}

	// Tear the session down BEFORE the servers: the streaming downlink
	// handler lives as long as its session, so httptest's external.Close
	// would wait forever for an in-flight response that only ends when the
	// tunnel connection closes. Closing the conn ends the uplink, the server
	// closes the session, and both server teardowns then find nothing
	// in-flight. (LIFO defer order alone cannot express this.)
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for srv.ActiveSessions() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ActiveSessions() > 0 {
		t.Fatalf("session did not drain after conn.Close: %d left", srv.ActiveSessions())
	}
}

// ExampleClient_dialContext shows how to route an entire http.Client through
// the tunnel.
func ExampleClient_dialContext() {
	c, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerURL:   "https://cdn.example.com:8443/stream",
		PSK:         "my-secret-token",
		Fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
	})
	if err != nil {
		log.Fatal(err)
	}

	transport := &http.Transport{DialContext: c.DialContext}
	resp, err := (&http.Client{Transport: transport}).Get("http://127.0.0.1:22/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(os.Stdout, resp.Body)
}

// ExampleServer_mounted shows how to host the Split-HTTP endpoint inside an
// application's own http.Server.
func ExampleServer_mounted() {
	srv, err := tunnel.NewServer(tunnel.ServerConfig{
		Path:          "/stream",
		PSK:           "my-secret-token",
		DefaultTarget: "tcp://127.0.0.1:22",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	mux := http.NewServeMux()
	mux.Handle("/stream", srv.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ordinary website camouflage")
	})

	server := &http.Server{Addr: ":443", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}
