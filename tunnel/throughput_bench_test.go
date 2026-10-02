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

// Unlike the echo benchmarks, these send continuously in one direction and
// wait for actual delivery to the far side. They expose ACK/window stalls.
func benchStreamOneWay(b *testing.B, alpn string, upload bool) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	start := make(chan struct{})
	targetDone := make(chan error, 1)
	const size = 64 * 1024
	count := int64(b.N) * size
	payload := bytes.Repeat([]byte{0x5a}, size)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		select {
		case <-start:
		case <-ctx.Done():
			return
		}
		if upload {
			_, err = io.CopyN(io.Discard, c, count)
		} else {
			for i := 0; i < b.N; i++ {
				if _, err = c.Write(payload); err != nil {
					break
				}
			}
		}
		targetDone <- err
		<-ctx.Done()
	}()
	u, cfg := startTunnelServer(b, ctx, alpn)
	cfg.StreamMode = "stream"
	c, err := DialXHTTP(ctx, u, cfg, ln.Addr().String(), "tcp")
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	close(start)
	if upload {
		for i := 0; i < b.N; i++ {
			if _, err := c.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
	} else {
		if _, err := io.CopyN(io.Discard, c, count); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-targetDone; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
}

func BenchmarkStreamUpload_h1(b *testing.B)   { benchStreamOneWay(b, "h1", true) }
func BenchmarkStreamUpload_h2(b *testing.B)   { benchStreamOneWay(b, "h2", true) }
func BenchmarkStreamUpload_h3(b *testing.B)   { benchStreamOneWay(b, "h3", true) }
func BenchmarkStreamDownload_h1(b *testing.B) { benchStreamOneWay(b, "h1", false) }
func BenchmarkStreamDownload_h2(b *testing.B) { benchStreamOneWay(b, "h2", false) }
func BenchmarkStreamDownload_h3(b *testing.B) { benchStreamOneWay(b, "h3", false) }
