package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestXHTTPTunnel_JSONConfigParsing(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Test Server Config Parsing with Token Alias and Unified Target
	serverJSON := `{
		"mode": "server",
		"listen": ":18443",
		"path": "/my-stream",
		"target": "tcp://127.0.0.1:2222",
		"token": "secret_psk_token",
		"selfsign": true,
		"selfsign_cn": "test.bing.com",
		"fallback": "https://www.bing.com",
		"log_level": "debug",
		"max_sessions": 3000
	}`
	serverPath := filepath.Join(tempDir, "server.json")
	if err := os.WriteFile(serverPath, []byte(serverJSON), 0644); err != nil {
		t.Fatalf("write server.json failed: %v", err)
	}

	sCfg, err := loadConfigFile(serverPath)
	if err != nil {
		t.Fatalf("load server config failed: %v", err)
	}
	if sCfg.Mode != "server" || sCfg.Listen != ":18443" || sCfg.Path != "/my-stream" || sCfg.Target != "tcp://127.0.0.1:2222" || sCfg.PSK != "secret_psk_token" || !sCfg.SelfSign || sCfg.SelfSignCN != "test.bing.com" || sCfg.Fallback != "https://www.bing.com" || sCfg.LogLevel != "debug" || sCfg.MaxSessions != 3000 {
		t.Fatalf("parsed server config mismatch: %+v", sCfg)
	}

	// 2. Test Client Config Parsing with Unified Target & AuthToken Alias
	clientJSON := `{
		"mode": "client",
		"listen": "tcp://127.0.0.1:3333",
		"server": "https://example.com:8443/my-stream",
		"target": "127.0.0.1:22",
		"auth_token": "secret_psk_token",
		"sni": "example.com",
		"host": "example.com",
		"alpn": "h2",
		"fingerprint": "AA:BB:CC",
		"log_level": "warn",
		"max_conns": 500
	}`
	clientPath := filepath.Join(tempDir, "client.json")
	if err := os.WriteFile(clientPath, []byte(clientJSON), 0644); err != nil {
		t.Fatalf("write client.json failed: %v", err)
	}

	cCfg, err := loadConfigFile(clientPath)
	if err != nil {
		t.Fatalf("load client config failed: %v", err)
	}
	if cCfg.Mode != "client" || cCfg.Listen != "tcp://127.0.0.1:3333" || cCfg.ServerURL != "https://example.com:8443/my-stream" || cCfg.Target != "127.0.0.1:22" || cCfg.PSK != "secret_psk_token" || cCfg.SNI != "example.com" || cCfg.ALPN != "h2" || cCfg.Fingerprint != "AA:BB:CC" || cCfg.LogLevel != "warn" || cCfg.MaxConns != 500 {
		t.Fatalf("parsed client config mismatch: %+v", cCfg)
	}
}

func TestXHTTPTunnel_LiveE2E_FromJSONConfig(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Echo Backend Target
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend failed: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Find free port for Server
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy failed: %v", err)
	}
	serverPort := dummyLn.Addr().(*net.TCPAddr).Port
	dummyLn.Close()
	serverListen := fmt.Sprintf("127.0.0.1:%d", serverPort)

	// 3. Create Server JSON Config (Cleartext)
	psk := "json_psk_xhttp_test"
	serverConf := fmt.Sprintf(`{
		"mode": "server",
		"listen": "%s",
		"path": "/stream",
		"target": "tcp://%s",
		"psk": "%s",
		"log_level": "debug"
	}`, serverListen, backendAddr, psk)
	serverConfPath := filepath.Join(tempDir, "server_e2e.json")
	if err := os.WriteFile(serverConfPath, []byte(serverConf), 0644); err != nil {
		t.Fatalf("write server_e2e.json failed: %v", err)
	}

	// 4. Start Server from loaded Config
	sCfg, err := loadConfigFile(serverConfPath)
	if err != nil {
		t.Fatalf("load server_e2e.json failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runServer(ctx, sCfg.Listen, sCfg.Path, sCfg.Target, sCfg.PSK, "", "", false, "")
	time.Sleep(100 * time.Millisecond)

	// 5. Find free port for Client
	clientDummy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client dummy failed: %v", err)
	}
	clientPort := clientDummy.Addr().(*net.TCPAddr).Port
	clientDummy.Close()
	clientListen := fmt.Sprintf("127.0.0.1:%d", clientPort)

	// 6. Create Client JSON Config
	clientConf := fmt.Sprintf(`{
		"mode": "client",
		"listen": "tcp://%s",
		"server": "http://%s/stream",
		"target": "%s",
		"token": "%s",
		"alpn": "h1",
		"log_level": "debug"
	}`, clientListen, serverListen, backendAddr, psk)
	clientConfPath := filepath.Join(tempDir, "client_e2e.json")
	if err := os.WriteFile(clientConfPath, []byte(clientConf), 0644); err != nil {
		t.Fatalf("write client_e2e.json failed: %v", err)
	}

	// 7. Start Client from loaded Config
	cCfg, err := loadConfigFile(clientConfPath)
	if err != nil {
		t.Fatalf("load client_e2e.json failed: %v", err)
	}
	go runClient(ctx, cCfg.Listen, cCfg.ServerURL, cCfg.Target, cCfg.PSK, cCfg.SNI, cCfg.Host, cCfg.ALPN, false, "")
	time.Sleep(150 * time.Millisecond)

	// 8. Connect to Client Listener & Test Echo
	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("dial client failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("Hello XHTTPTunnel via JSON Configuration!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write to client tunnel failed: %v", err)
	}

	resp := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read from client tunnel failed: %v", err)
	}

	if string(resp) != string(testData) {
		t.Fatalf("echo mismatch: got %q, want %q", string(resp), string(testData))
	}

	t.Logf("✅ Live E2E XHTTPTunnel via JSON Config PASSED!")
}

func TestApplyChunkSizeClamping(t *testing.T) {
	cases := []struct {
		name     string
		in       int
		wantSize int // bytes
	}{
		{"default", 0, 256 * 1000},
		{"in-range", 512, 512 * 1000},
		{"too-small-clamps-to-16k", 1, 16 * 1000},
		{"negative-treats-as-default", -5, 256 * 1000},
		{"too-big-clamps-to-900k", 10000, 900 * 1000},
		{"exact-max", 900, 900 * 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applyChunkSize(tc.in)
			if maxsendBufSize != tc.wantSize {
				t.Fatalf("maxsendBufSize = %d, want %d", maxsendBufSize, tc.wantSize)
			}
			if maxframeSize != maxsendBufSize+framePaddingBudget {
				t.Fatalf("maxframeSize = %d, want %d", maxframeSize, maxsendBufSize+framePaddingBudget)
			}
		})
	}
	// Restore defaults so parallel tests are not affected.
	applyChunkSize(0)
}

func TestApplyServerOptions(t *testing.T) {
	// allowed_targets + trust_proxy_headers are wired through to the globals.
	applyServerOptions(&FileConfig{
		AllowedTargets:    []string{"127.0.0.1:22", ":8080", "db:"},
		TrustProxyHeaders: true,
	})
	if len(allowedTargets) != 3 {
		t.Fatalf("allowedTargets = %v, want 3 entries", allowedTargets)
	}
	if !trustProxyHeaders {
		t.Fatal("trustProxyHeaders not applied")
	}
	// targetAllowed must honour the allowlist forms.
	if !targetAllowed("127.0.0.1:22") {
		t.Error("exact host:port should be allowed")
	}
	if !targetAllowed("10.0.0.5:8080") {
		t.Error(":port form should allow any host on that port")
	}
	if !targetAllowed("db:5432") {
		t.Error("host: form should allow any port on that host")
	}
	if targetAllowed("evil.com:443") {
		t.Error("non-listed target must be rejected")
	}
	// Empty allowlist = allow all. At startup the global is nil; an empty
	// config must not restrict anything.
	allowedTargets = nil
	if !targetAllowed("anything:1") {
		t.Error("empty allowlist must allow everything")
	}
	// Restore defaults: the E2E suite creates servers via ListenXHTTP directly
	// (bypassing applyServerOptions) and relies on allow-all.
	allowedTargets = nil
	trustProxyHeaders = false
}

func TestApplyClientOptions(t *testing.T) {
	// idle_timeout is applied as a duration.
	applyClientOptions(&FileConfig{IdleTimeout: 42})
	if clientIdleTimeout != 42*time.Second {
		t.Fatalf("clientIdleTimeout = %v, want %v", clientIdleTimeout, 42*time.Second)
	}
	// Zero (unset) keeps the default.
	applyClientOptions(&FileConfig{})
	if clientIdleTimeout != 42*time.Second {
		t.Fatalf("clientIdleTimeout changed when field unset: %v", clientIdleTimeout)
	}
	// Restore the default to avoid leaking state into other tests.
	applyClientOptions(&FileConfig{IdleTimeout: 900})
}
