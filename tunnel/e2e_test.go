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

func TestXHTTPTunnel_E2E_TCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Start the echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen echo: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start the XHTTP server
	serverLnAddr := "127.0.0.1:0"
	token := "test-secret"
	path := "/stream"

	xl, err := ListenXHTTP(ctx, serverLnAddr, path, token, "", "", "")
	if err != nil {
		t.Fatalf("Failed to listen XHTTP: %v", err)
	}
	defer xl.Close()

	go func() {
		for {
			conn, err := xl.Accept(ctx)
			if err != nil {
				return
			}
			go func(xc *XHTTPConn) {
				defer xc.Close()
				rc, err := net.Dial("tcp", xc.TargetAddr())
				if err != nil {
					return
				}
				defer rc.Close()
				go io.Copy(rc, xc)
				io.Copy(xc, rc)
			}(conn.(*XHTTPConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. Client dials the tunnel
	serverURL, _ := url.Parse("http://" + xl.Addr().String() + path)
	cfg := &DialConfig{
		Password: token,
		Path:     path,
		ALPN:     "h1",
	}

	clientConn, err := DialXHTTP(ctx, serverURL, cfg, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer clientConn.Close()

	// 4. Send data and verify the echo
	testData := []byte("Hello XHTTP Tunnel E2E Test!")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("Client write failed: %v", err)
	}

	recvBuf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, recvBuf); err != nil {
		t.Fatalf("Client read failed: %v", err)
	}

	if !bytes.Equal(recvBuf, testData) {
		t.Fatalf("Echo mismatch: got %q, expected %q", string(recvBuf), string(testData))
	}
	t.Logf("✅ TCP E2E Echo Test Passed!")
}

// TestXHTTPTunnel_E2E_BulkIntegrity pushes several megabytes through the
// tunnel in both directions at once.
//
// It exists to catch pooled-buffer recycling bugs. The send buffers come from
// a shared sync.Pool and are handed to the HTTP transport as request and
// response bodies; HTTP/2 and HTTP/3 stream those bodies concurrently with
// the response, so a buffer returned to the pool too early gets rewritten
// underneath the transport. That only shows up as corruption under sustained
// load with several pump workers in flight — never on a single small echo.
func TestXHTTPTunnel_E2E_BulkIntegrity(t *testing.T) {
	// h2 matters as much as h1 here: an h2 transport streams the request body
	// concurrently with the response, which is exactly the window in which a
	// too-early buffer recycle corrupts the upload.
	// Ports are bound dynamically (":0"): the session registry and reaper are
	// process-global, so re-running this test (e.g. -count=2) must not rebind a
	// fixed port that a previous iteration's server may still hold — doing so
	// makes the client connect to a stale server with no bridge goroutine and
	// hang.
	for _, alpn := range []string{"h1", "h2"} {
		t.Run(alpn, func(t *testing.T) {
			bulkIntegrityOver(t, alpn, "127.0.0.1:0")
		})
	}
}

func bulkIntegrityOver(t *testing.T, alpn, serverLnAddr string) {
	t.Helper()

	const (
		size    = 4 << 20 // 4MB, well past one chunk so the pump scales up
		pattern = 0xA5
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen echo: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	xl, err := ListenXHTTP(ctx, serverLnAddr, "/stream", "test-secret", "", "", "")
	if err != nil {
		t.Fatalf("Failed to listen XHTTP: %v", err)
	}
	defer xl.Close()

	go func() {
		for {
			conn, err := xl.Accept(ctx)
			if err != nil {
				return
			}
			go func(xc *XHTTPConn) {
				defer xc.Close()
				rc, err := net.Dial("tcp", xc.TargetAddr())
				if err != nil {
					return
				}
				defer rc.Close()
				go io.Copy(rc, xc)
				io.Copy(xc, rc)
			}(conn.(*XHTTPConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	serverURL, _ := url.Parse("http://" + xl.Addr().String() + "/stream")
	clientConn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password: "test-secret",
		Path:     "/stream",
		ALPN:     alpn,
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(120 * time.Second))

	// A non-trivial pattern: all-zero payloads hide offset and reuse bugs.
	up := make([]byte, size)
	for i := range up {
		up[i] = byte(i%251) ^ pattern
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(clientConn, bytes.NewReader(up))
		writeErr <- err
	}()

	down := make([]byte, size)
	if _, err := io.ReadFull(clientConn, down); err != nil {
		t.Fatalf("read back %d/%d bytes: %v", len(down), size, err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("uplink write failed: %v", err)
	}
	if !bytes.Equal(up, down) {
		for i := range up {
			if up[i] != down[i] {
				t.Fatalf("echo mismatch at byte %d: got 0x%02x, want 0x%02x", i, down[i], up[i])
			}
		}
		t.Fatal("echo mismatch")
	}
	t.Logf("✅ Bulk integrity over %s: %d bytes echoed byte-exact in both directions", alpn, size)
}

func TestXHTTPTunnel_E2E_UDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Start the UDP echo server
	echoPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen udp echo: %v", err)
	}
	defer echoPC.Close()
	echoAddr := echoPC.LocalAddr().String()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoPC.ReadFrom(buf)
			if err != nil {
				return
			}
			echoPC.WriteTo(buf[:n], addr)
		}
	}()

	// 2. Start the XHTTP server
	serverLnAddr := "127.0.0.1:0"
	token := "test-secret"
	path := "/stream"

	xl, err := ListenXHTTP(ctx, serverLnAddr, path, token, "", "", "")
	if err != nil {
		t.Fatalf("Failed to listen XHTTP: %v", err)
	}
	defer xl.Close()

	go func() {
		for {
			conn, err := xl.Accept(ctx)
			if err != nil {
				return
			}
			go func(xc *XHTTPConn) {
				defer xc.Close()
				rc, err := net.Dial("udp", xc.TargetAddr())
				if err != nil {
					return
				}
				defer rc.Close()

				go func() {
					uBuf := make([]byte, maxUDPFrameSize)
					for {
						n, err := ReadUDPFrameInto(xc, uBuf)
						if err != nil {
							return
						}
						rc.Write(uBuf[:n])
					}
				}()

				dBuf := make([]byte, maxUDPFrameSize)
				for {
					n, err := rc.Read(dBuf)
					if err != nil {
						return
					}
					WriteUDPFrame(xc, dBuf[:n])
				}
			}(conn.(*XHTTPConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. Client dials the tunnel
	serverURL, _ := url.Parse("http://" + xl.Addr().String() + path)
	cfg := &DialConfig{
		Password: token,
		Path:     path,
		ALPN:     "h1",
	}

	clientConn, err := DialXHTTP(ctx, serverURL, cfg, echoAddr, "udp")
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer clientConn.Close()

	// 4. Send a UDP frame and verify the echo
	testData := []byte("Hello UDP Frame via XHTTP Tunnel!")
	if err := WriteUDPFrame(clientConn, testData); err != nil {
		t.Fatalf("Client WriteUDPFrame failed: %v", err)
	}

	recvBuf := make([]byte, maxUDPFrameSize)
	n, err := ReadUDPFrameInto(clientConn, recvBuf)
	if err != nil {
		t.Fatalf("Client ReadUDPFrameInto failed: %v", err)
	}

	if !bytes.Equal(recvBuf[:n], testData) {
		t.Fatalf("UDP echo mismatch: got %q, expected %q", string(recvBuf[:n]), string(testData))
	}
	t.Logf("✅ UDP E2E Echo Test Passed!")
}
