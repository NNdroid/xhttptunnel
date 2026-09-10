package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

// startUDPEchoServer runs a plain UDP echo target for the throughput
// benchmarks (a datagram in, the same datagram out).
func startUDPEchoServer(t testing.TB) (addr string, closeFn func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	go func() {
		buf := make([]byte, maxUDPFrameSize)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

// benchTunnelTCP measures steady-state TCP throughput through a tunnel to a
// plain echo target over one reused connection, for a given ALPN.
func benchTunnelTCP(b *testing.B, alpn string, size int) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, dial := startTunnelServer(b, ctx, alpn)
	echoAddr, closeEcho := startTCPEchoServer(b)
	defer closeEcho()

	conn, err := DialXHTTP(ctx, serverURL, dial, echoAddr, "tcp")
	if err != nil {
		b.Fatalf("dial %s tunnel: %v", alpn, err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("tcp-throughput-"), size/13+1)[:size]
	recv := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(conn, recv); err != nil {
			b.Fatalf("read: %v", err)
		}
		if !bytes.Equal(recv, payload) {
			b.Fatal("echo mismatch")
		}
	}
}

// benchTunnelUDP measures steady-state UDP throughput (one datagram per
// iteration) through a tunnel to a UDP echo target over one reused session.
func benchTunnelUDP(b *testing.B, alpn string, size int) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, dial := startTunnelServer(b, ctx, alpn)
	echoAddr, closeEcho := startUDPEchoServer(b)
	defer closeEcho()

	conn, err := DialXHTTP(ctx, serverURL, dial, echoAddr, "udp")
	if err != nil {
		b.Fatalf("dial %s udp tunnel: %v", alpn, err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("udp-throughput-"), size/13+1)[:size]
	recv := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := WriteUDPFrame(conn, payload); err != nil {
			b.Fatalf("write frame: %v", err)
		}
		n, err := ReadUDPFrameInto(conn, recv)
		if err != nil {
			b.Fatalf("read frame: %v", err)
		}
		if n != size || !bytes.Equal(recv[:n], payload) {
			b.Fatalf("echo mismatch: got %d bytes, want %d", n, size)
		}
	}
}

func BenchmarkXHTTPTunnel_TCP_h1(b *testing.B) { benchTunnelTCP(b, "h1", 64*1024) }
func BenchmarkXHTTPTunnel_TCP_h2(b *testing.B) { benchTunnelTCP(b, "h2", 64*1024) }
func BenchmarkXHTTPTunnel_TCP_h3(b *testing.B) { benchTunnelTCP(b, "h3", 64*1024) }

func BenchmarkXHTTPTunnel_UDP_h1(b *testing.B) { benchTunnelUDP(b, "h1", 4*1024) }
func BenchmarkXHTTPTunnel_UDP_h2(b *testing.B) { benchTunnelUDP(b, "h2", 4*1024) }
func BenchmarkXHTTPTunnel_UDP_h3(b *testing.B) { benchTunnelUDP(b, "h3", 4*1024) }
