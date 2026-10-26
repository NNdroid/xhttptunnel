package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"testing"
	"time"
)

// benchTunnelThroughCDNWeakNetwork measures steady-state echo throughput
// through a simulated CDN edge with configurable delay, jitter, and loss.
// The pattern mirrors BenchmarkXHTTPTunnel_ThroughCDN_72KB: setup is
// outside the timer, the echo round-trip is inside, and StreamMode is poll
// because the buffered httptest proxy stalls the stream probe.
func benchTunnelThroughCDNWeakNetwork(b *testing.B, delay, jitter time.Duration, lossRate float64) {
	b.Helper()
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
	if delay > 0 {
		cdn.delay = delay
	}
	cdn.jitter = jitter
	cdn.lossRate = lossRate
	defer cdn.Close()
	cdnURL, err := url.Parse(cdn.server.URL + "/stream")
	if err != nil {
		b.Fatalf("parse CDN URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, cdnURL, &DialConfig{
		Password:   "benchmark-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll",
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

func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Delay50ms(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 50*time.Millisecond, 0, 0)
}
func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Delay100ms(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 100*time.Millisecond, 0, 0)
}
func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Delay200ms(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 200*time.Millisecond, 0, 0)
}
func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Jitter50ms(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 50*time.Millisecond, 50*time.Millisecond, 0)
}
func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Jitter100ms(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 50*time.Millisecond, 100*time.Millisecond, 0)
}
func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Loss5pct(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 0, 0, 0.05)
}
func BenchmarkXHTTPTunnel_ThroughCDN_72KB_Loss10pct(b *testing.B) {
	benchTunnelThroughCDNWeakNetwork(b, 0, 0, 0.10)
}
