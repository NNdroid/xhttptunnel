package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	initLogger("error")
}

type testCluster struct {
	targetURL string
	serverURL string
}

func setupTestCluster(t *testing.T) *testCluster {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	targetAddr := targetLn.Addr().String()
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello from target!"))
		})
		mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes.Repeat([]byte("A"), 1024*1024))
		})
		http.Serve(targetLn, mux)
	}()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	serverAddr := serverLn.Addr().String()
	_, port, _ := net.SplitHostPort(serverAddr)
	serverLn.Close()

	go func() {
		runServer("127.0.0.1:"+port, "/stream", "tcp://"+targetAddr, "test-psk", "", "", false)
	}()
	time.Sleep(300 * time.Millisecond)

	return &testCluster{
		targetURL: targetAddr,
		serverURL: fmt.Sprintf("http://127.0.0.1:%s/stream", port),
	}
}

func TestBasicProxy(t *testing.T) {
	cluster := setupTestCluster(t)
	u, _ := url.Parse(cluster.serverURL)
	cfg := &Config{Path: u.Path, SNI: "127.0.0.1", Host: "127.0.0.1", Password: "test-psk", ALPN: "h1"}

	conn, err := DialXHTTP(u, cfg, cluster.targetURL, "tcp")
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}
	defer conn.Close()

	reqStr := "GET /hello HTTP/1.1\r\nHost: " + cluster.targetURL + "\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("Failed to write to tunnel: %v", err)
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("Failed to read from tunnel: %v", err)
	}

	respStr := string(respBytes)
	if !strings.Contains(respStr, "200 OK") {
		t.Errorf("Unexpected response: %s", respStr)
	}

	if xfc, ok := conn.(*xhttpFramedConn); ok {
		xfc.WriteCloseFrame()
	}
}

func TestHighConcurrency(t *testing.T) {
	cluster := setupTestCluster(t)
	u, _ := url.Parse(cluster.serverURL)
	cfg := &Config{Path: u.Path, SNI: "127.0.0.1", Password: "test-psk", ALPN: "h1"}

	concurrency := 100
	var wg sync.WaitGroup
	var successCount int32

	start := time.Now()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		time.Sleep(2 * time.Millisecond) // 防洪水保护，让系统有时间处理握手
		go func() {
			defer wg.Done()
			conn, err := DialXHTTP(u, cfg, cluster.targetURL, "tcp")
			if err != nil {
				return
			}
			defer conn.Close()
			defer func() {
				if xfc, ok := conn.(*xhttpFramedConn); ok {
					xfc.WriteCloseFrame()
				}
			}()

			reqStr := "GET /big HTTP/1.1\r\nHost: " + cluster.targetURL + "\r\nConnection: close\r\n\r\n"
			conn.Write([]byte(reqStr))

			respBytes, err := io.ReadAll(conn)
			if err == nil && len(respBytes) > 1024*1000 {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)
	t.Logf("Completed %d concurrent requests in %v. Success rate: %d/%d", concurrency, duration, successCount, concurrency)
}
