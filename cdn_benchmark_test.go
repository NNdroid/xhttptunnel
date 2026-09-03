package main

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"testing"
)

// BenchmarkXHTTPTunnel_ThroughCDN_72KB measures the steady-state data path,
// excluding setup and protocol negotiation. The local httptest reverse proxy
// retains the same request/response path and header handling as a CDN origin.
func BenchmarkXHTTPTunnel_ThroughCDN_72KB(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoAddr, closeEcho := startTCPEchoServer(b)
	defer closeEcho()
	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "benchmark-secret", "", "", "")
	if err != nil {
		b.Fatalf("start origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(b, ctx, origin)

	cdn := newCDNTestServer(b, "http://"+origin.Addr().String(), nil)
	defer cdn.Close()
	cdnURL, err := url.Parse(cdn.server.URL + "/stream")
	if err != nil {
		b.Fatalf("parse CDN URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, cdnURL, &Config{
		Password: "benchmark-secret",
		Path:     "/stream",
		ALPN:     "h1",
	}, echoAddr, "tcp")
	if err != nil {
		b.Fatalf("dial through CDN: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("benchmark-payload-"), 4096) // 72KB
	received := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := conn.Write(payload); err != nil || n != len(payload) {
			b.Fatalf("write %d/%d bytes through CDN: %v", n, len(payload), err)
		}
		if _, err := io.ReadFull(conn, received); err != nil {
			b.Fatalf("read echo through CDN: %v", err)
		}
		if !bytes.Equal(received, payload) {
			b.Fatal("echo payload mismatch")
		}
	}
}
