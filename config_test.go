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

	"github.com/NNdroid/xhttptunnel/tunnel"
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

	serverErr := make(chan error, 1)
	go func() { serverErr <- runServer(ctx, sCfg.Listen, sCfg.Path, sCfg.Target, sCfg.PSK, "", "", false, "") }()
	if err := waitStarted(serverErr, 100*time.Millisecond); err != nil {
		t.Fatalf("server failed to start: %v", err)
	}

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
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- runClient(ctx, cCfg.Listen, cCfg.ServerURL, cCfg.Target, cCfg.PSK, cCfg.SNI, cCfg.Host, cCfg.ALPN, false, "")
	}()
	if err := waitStarted(clientErr, 150*time.Millisecond); err != nil {
		t.Fatalf("client failed to start: %v", err)
	}

	// 8. Connect to Client Listener & Test Echo
	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("dial client failed: %v", err)
	}
	defer conn.Close()
	// Bound the echo read so a stalled tunnel fails the test instead of
	// hanging it until the package timeout.
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

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

func TestLegacyServerPolicyHelpers(t *testing.T) {
	// The package-level helpers wire the low-level ListenXHTTP state; Server
	// instances carry their own copy via ServerConfig fields.
	tunnel.SetAllowedTargets([]string{"127.0.0.1:22", ":8080", "db:"})
	tunnel.SetTrustProxyHeaders(true)
	if targets := tunnel.AllowedTargets(); len(targets) != 3 {
		t.Fatalf("AllowedTargets = %v, want 3 entries", targets)
	}
	if !tunnel.TrustProxyHeaders() {
		t.Fatal("trust proxy headers not applied")
	}
	// TargetAllowed must honour the allowlist forms.
	if !tunnel.TargetAllowed("127.0.0.1:22") {
		t.Error("exact host:port should be allowed")
	}
	if !tunnel.TargetAllowed("10.0.0.5:8080") {
		t.Error(":port form should allow any host on that port")
	}
	if !tunnel.TargetAllowed("db:5432") {
		t.Error("host: form should allow any port on that host")
	}
	if tunnel.TargetAllowed("evil.com:443") {
		t.Error("non-listed target must be rejected")
	}
	// Empty allowlist = allow all. At startup the list is nil; an empty
	// config must not restrict anything.
	tunnel.SetAllowedTargets(nil)
	if !tunnel.TargetAllowed("anything:1") {
		t.Error("empty allowlist must allow everything")
	}
	// Restore defaults so parallel tests are not affected.
	tunnel.SetAllowedTargets(nil)
	tunnel.SetTrustProxyHeaders(false)
}

func TestApplyClientDefaults(t *testing.T) {
	// Structural defaults fill in when the config omits them.
	cfg := &FileConfig{}
	applyClientDefaults(cfg)
	if cfg.Listen != "tcp://127.0.0.1:1080" {
		t.Errorf("Listen = %q, want tcp://127.0.0.1:1080", cfg.Listen)
	}
	if cfg.ServerURL != "https://127.0.0.1:8443/stream" {
		t.Errorf("ServerURL = %q, want the default endpoint", cfg.ServerURL)
	}
	if cfg.Target != "127.0.0.1:22" {
		t.Errorf("Target = %q, want 127.0.0.1:22", cfg.Target)
	}
	if cfg.ALPN != "auto" {
		t.Errorf("ALPN = %q, want auto", cfg.ALPN)
	}

	// Explicit values win, and the Forward alias backs Target up.
	cfg2 := &FileConfig{Listen: "tcp://127.0.0.1:9999", Forward: "10.0.0.1:80"}
	applyClientDefaults(cfg2)
	if cfg2.Listen != "tcp://127.0.0.1:9999" || cfg2.Target != "10.0.0.1:80" || cfg2.ALPN != "auto" {
		t.Errorf("explicit config clobbered: %+v", cfg2)
	}
}

func TestApplyServerDefaultsSelfSign(t *testing.T) {
	// applyServerDefaults generates cert.pem/key.pem into the working
	// directory — exactly the files a real selfsign deployment uses. Run the
	// test in a throwaway directory so it can never clobber the repo's own
	// certificates.
	t.Chdir(t.TempDir())

	scfg := &FileConfig{SelfSign: true}
	if err := applyServerDefaults(scfg); err != nil {
		t.Fatalf("applyServerDefaults: %v", err)
	}
	if scfg.Listen != ":8443" || scfg.Path != "/stream" || scfg.Target != "tcp://127.0.0.1:22" {
		t.Errorf("server defaults mismatch: %+v", scfg)
	}
	if scfg.Cert != "cert.pem" || scfg.Key != "key.pem" {
		t.Errorf("selfsign files = %q/%q, want cert.pem/key.pem", scfg.Cert, scfg.Key)
	}
	if _, err := os.Stat(scfg.Cert); err != nil {
		t.Errorf("selfsign did not write %s: %v", scfg.Cert, err)
	}
	if _, err := os.Stat(scfg.Key); err != nil {
		t.Errorf("selfsign did not write %s: %v", scfg.Key, err)
	}
}

// waitStarted gives a blocking serve goroutine a grace period to fail fast
// (bad listen address, certificate error). A nil return means the server is
// still running; a non-nil error means startup failed.
func waitStarted(errCh <-chan error, grace time.Duration) error {
	select {
	case err := <-errCh:
		return err
	case <-time.After(grace):
		return nil
	}
}

// The config-file idle_timeout → client mapping is covered by
// tunnel.TestNewClientDefaults; the structural default coverage lives in
// TestApplyClientDefaults above.
