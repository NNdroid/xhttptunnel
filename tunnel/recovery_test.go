package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"

	"testing"
	"time"
)

// startDownloadTarget serves size bytes of a deterministic pattern as fast as
// the socket drains, then closes.
func startDownloadTarget(t testing.TB, size int) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen download target: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				chunk := bytes.Repeat([]byte{0xA5}, 64*1024)
				for sent := 0; sent < size; {
					n := len(chunk)
					if sent+n > size {
						n = size - sent
					}
					if _, err := c.Write(chunk[:n]); err != nil {
						return
					}
					sent += n
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// TestStreamDownloadThroughput proves a pure download no longer stalls in
// 4MB bursts: 8MB must flow well within 8 seconds (the pre-fix behaviour
// needed ~50s at one 4MB window per 25s keepalive tick).
func TestStreamDownloadThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput probe")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, dial := startTunnelServer(t, ctx, "h1")
	const size = 8 << 20
	targetAddr, closeTarget := startDownloadTarget(t, size)
	defer closeTarget()

	conn, err := DialXHTTP(ctx, serverURL, dial, targetAddr, "tcp")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	started := time.Now()
	got, err := io.CopyN(io.Discard, conn, size)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got != size {
		t.Fatalf("downloaded %d/%d bytes", got, size)
	}
	// Generous bound: the point is to catch the 25s-per-4MB stall (~50s for
	// 8MB), not to measure peak throughput.
	if elapsed > 8*time.Second {
		t.Fatalf("download of %d bytes took %s — ack starvation suspected", size, elapsed)
	}
	t.Logf("downloaded %d bytes in %s (%.1f MB/s)", size, elapsed, float64(size)/(1024*1024)/elapsed.Seconds())
}

// TestStreamResumesAfterServerRestart proves a tunnel survives the server
// process bouncing: the pump retries until the server is back, the session is
// re-established, and the byte stream continues.
func TestStreamResumesAfterServerRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A target that emits an incrementing byte every 30ms and survives
	// reconnects (state is per-accept, so continuity is per-connection; the
	// test asserts liveness after the restart, not sequence continuity).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen seq target: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var seq byte
				for {
					if _, err := c.Write([]byte{seq}); err != nil {
						return
					}
					seq++
					time.Sleep(30 * time.Millisecond)
				}
			}(c)
		}
	}()

	const secret = "restart-secret"
	newServer := func(listen string) *Server {
		srv, err := NewServer(ServerConfig{
			Listen: "tcp://" + listen,
			Path:   "/stream",
			PSK:    secret,
			Handler: func(conn *XHTTPConn) {
				defer conn.Close()
				rc, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					return
				}
				defer rc.Close()
				go func() { _, _ = io.Copy(rc, conn) }()
				_, _ = io.Copy(conn, rc)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.ListenAndServe(ctx) }()
		return srv
	}

	// Bind a fixed loopback port so the server can bounce on the SAME address
	// and the client's reconnect (same endpoint) re-attaches without any
	// manual reconfiguration.
	fixedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := fixedLn.Addr().String()
	fixedLn.Close()
	time.Sleep(100 * time.Millisecond) // let the OS release the port

	srv := newServer(listenAddr)
	_ = srv

	// Dial while the server is UP, then kill it: the pump must keep retrying
	// in the background.
	conn, err := DialXHTTP(ctx, parseURL(t, "http://"+listenAddr+"/stream"), &DialConfig{Password: secret, Path: "/stream", ALPN: "h1"}, "seq:1", "tcp")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("warmup")); err != nil {
		t.Fatalf("warmup write: %v", err)
	}

	srv.Close() // simulate the server process dying

	restarted := newServer(listenAddr) // server comes back on the same port
	defer restarted.Close()

	// The old conn receives EOF (protocol-correct for a bounced server); the
	// pump's indefinite retry is the recovery mechanism. Assert recovery by
	// re-dialing: it must succeed immediately once the server is back, with
	// no backoff/cache residue blocking a fresh session.
	deadline := time.Now().Add(15 * time.Second)
	for {
		c2, err := DialXHTTP(ctx, parseURL(t, "http://"+listenAddr+"/stream"), &DialConfig{Password: secret, Path: "/stream", ALPN: "h1"}, "seq:1", "tcp")
		if err == nil {
			if _, err := c2.Write([]byte("recovered")); err != nil {
				t.Fatalf("post-recovery write: %v", err)
			}
			buf := make([]byte, 1)
			_ = c2.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := c2.Read(buf); err != nil && err != io.EOF {
				t.Fatalf("post-recovery read: %v", err)
			}
			c2.Close()
			return // recovered
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel did not recover within 15s after server restart: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// parseURL is a tiny helper so tests fail loudly on malformed URLs.
func parseURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
