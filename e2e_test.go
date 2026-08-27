package main

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

	// 1. 启动 Echo 服务端
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

	// 2. 启动 XHTTP 服务端
	serverLnAddr := "127.0.0.1:28881"
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
			go func(xc *xhttpFramedConn) {
				defer xc.Close()
				rc, err := net.Dial("tcp", xc.targetAddr)
				if err != nil {
					return
				}
				defer rc.Close()
				go io.Copy(rc, xc)
				io.Copy(xc, rc)
			}(conn.(*xhttpFramedConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. 客户端拨号
	serverURL, _ := url.Parse("http://" + serverLnAddr + path)
	cfg := &Config{
		Password: token,
		Path:     path,
		ALPN:     "h1",
	}

	clientConn, err := DialXHTTP(ctx, serverURL, cfg, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer clientConn.Close()

	// 4. 发送数据并验证回显
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

func TestXHTTPTunnel_E2E_UDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. 启动 Echo UDP 服务端
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

	// 2. 启动 XHTTP 服务端
	serverLnAddr := "127.0.0.1:28882"
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
			go func(xc *xhttpFramedConn) {
				defer xc.Close()
				rc, err := net.Dial("udp", xc.targetAddr)
				if err != nil {
					return
				}
				defer rc.Close()

				go func() {
					uBuf := make([]byte, maxUDPFrameSize)
					for {
						n, err := readUDPFrameInto(xc, uBuf)
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
					writeUDPFrame(xc, dBuf[:n])
				}
			}(conn.(*xhttpFramedConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. 客户端拨号
	serverURL, _ := url.Parse("http://" + serverLnAddr + path)
	cfg := &Config{
		Password: token,
		Path:     path,
		ALPN:     "h1",
	}

	clientConn, err := DialXHTTP(ctx, serverURL, cfg, echoAddr, "udp")
	if err != nil {
		t.Fatalf("DialXHTTP failed: %v", err)
	}
	defer clientConn.Close()

	// 4. 发送 UDP Frame 并验证回显
	testData := []byte("Hello UDP Frame via XHTTP Tunnel!")
	if err := writeUDPFrame(clientConn, testData); err != nil {
		t.Fatalf("Client writeUDPFrame failed: %v", err)
	}

	recvBuf := make([]byte, maxUDPFrameSize)
	n, err := readUDPFrameInto(clientConn, recvBuf)
	if err != nil {
		t.Fatalf("Client readUDPFrameInto failed: %v", err)
	}

	if !bytes.Equal(recvBuf[:n], testData) {
		t.Fatalf("UDP echo mismatch: got %q, expected %q", string(recvBuf[:n]), string(testData))
	}
	t.Logf("✅ UDP E2E Echo Test Passed!")
}
