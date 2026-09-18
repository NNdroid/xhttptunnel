package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestPlaceholderPSKDetection(t *testing.T) {
	for _, psk := range []string{"my-secret-token", " change-me-before-use ", "replace-with-a-random-secret"} {
		if !isPlaceholderPSK(psk) {
			t.Errorf("published placeholder %q was accepted", psk)
		}
	}
	for _, psk := range []string{"", "deployment-specific-secret"} {
		if isPlaceholderPSK(psk) {
			t.Errorf("legitimate PSK %q was rejected", psk)
		}
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
	cases := []struct {
		name     string
		explicit bool
		cfgPath  string
		wantCert string
		wantKey  string
	}{
		{
			name:     "a flag-only run falls back to the working directory",
			wantCert: "cert.pem",
			wantKey:  "key.pem",
		},
		{
			name:     "the pair is written beside the config file",
			cfgPath:  "confdir/config.server.json",
			wantCert: filepath.Join("confdir", "cert.pem"),
			wantKey:  filepath.Join("confdir", "key.pem"),
		},
		{
			name:     "a configured cert/key path is honoured as the generation target",
			explicit: true,
			cfgPath:  "confdir/config.server.json",
			wantCert: filepath.Join("confdir", "cert.crt"),
			wantKey:  filepath.Join("confdir", "cert.key"),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Run in a throwaway directory so the test can never clobber the
			// repo's own certificates.
			work := t.TempDir()
			t.Chdir(work)
			// A config file's own directory exists in reality; create it so the
			// generation target resolves the same way.
			if tc.cfgPath != "" {
				if err := os.MkdirAll(filepath.Dir(tc.cfgPath), 0700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			}

			cert, key := "", ""
			if tc.explicit {
				cert, key = tc.wantCert, tc.wantKey
			}
			scfg := &FileConfig{SelfSign: true, SelfSignCN: "www.bing.com", Cert: cert, Key: key}
			if err := applyServerDefaults(scfg, tc.cfgPath); err != nil {
				t.Fatalf("applyServerDefaults: %v", err)
			}
			if scfg.Listen != ":8443" || scfg.Path != "/stream" || scfg.Target != "tcp://127.0.0.1:22" {
				t.Errorf("server defaults mismatch: %+v", scfg)
			}
			if scfg.Cert != tc.wantCert || scfg.Key != tc.wantKey {
				t.Errorf("selfsign paths = %q/%q, want %q/%q", scfg.Cert, scfg.Key, tc.wantCert, tc.wantKey)
			}
			for _, p := range []string{scfg.Cert, scfg.Key} {
				if _, err := os.Stat(p); err != nil {
					t.Errorf("selfsign did not write %s: %v", p, err)
				}
			}
		})
	}
}

// TestApplyServerDefaultsSelfSignReusesExistingPair pins the second half of
// the "no hardcoded paths" fix: a deployment that wants a stable fingerprint
// needs the same certificate on every boot, so an existing pair must be loaded
// rather than regenerated over.
func TestApplyServerDefaultsSelfSignReusesExistingPair(t *testing.T) {
	t.Chdir(t.TempDir())

	cfg := &FileConfig{SelfSign: true, SelfSignCN: "www.bing.com"}
	if err := applyServerDefaults(cfg, "config.server.json"); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	fp1, err := tunnel.CertFingerprint(cfg.Cert)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	first := *cfg

	again := &FileConfig{SelfSign: true, SelfSignCN: "www.bing.com"}
	if err := applyServerDefaults(again, "config.server.json"); err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if again.Cert != first.Cert || again.Key != first.Key {
		t.Errorf("certificate paths moved between boots: %q/%q -> %q/%q", first.Cert, first.Key, again.Cert, again.Key)
	}
	fp2, err := tunnel.CertFingerprint(again.Cert)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if fp1 != fp2 {
		t.Errorf("the self-signed pair is not stable across restarts: %s -> %s", fp1, fp2)
	}
}

func TestApplyServerDefaultsSelfSignRefusesHalfPair(t *testing.T) {
	t.Chdir(t.TempDir())

	cfg := &FileConfig{SelfSign: true, SelfSignCN: "www.bing.com"}
	if err := applyServerDefaults(cfg, "config.server.json"); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if err := os.Remove(cfg.Key); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	again := &FileConfig{SelfSign: true, SelfSignCN: "www.bing.com"}
	if err := applyServerDefaults(again, "config.server.json"); err == nil {
		t.Error("a half-present pair must be refused, not overwritten: regenerating would destroy the operator's certificate")
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

// captureStdout returns whatever fn printed to stdout. The reader must run in
// its own goroutine: the QR code alone is ~57KB, which blocks fn() against the
// pipe buffer before a sequential read would ever start.
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return ""
	}
	done := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	return string(<-done)
}

// TestGenURIFromServerConfig covers the two ways a freshly installed server
// produced a share link nobody could scan: the disguise domain stayed in
// selfsign_cn and never reached the URI's SNI, and the target arrived as
// "tcp://127.0.0.1:22" where the importer expects a bare address.
func TestGenURIFromServerConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.server.json")
	cfg := `{
		"mode": "server",
		"listen": ":9443",
		"path": "/stream",
		"target": "tcp://127.0.0.1:22",
		"psk": "shared-secret",
		"selfsign": true,
		"selfsign_cn": "www.sushiwei.com",
		"fallback": "https://www.sushiwei.com"
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out := captureStdout(func() {
		runGenURI([]string{"-c", cfgPath, "-host", "1.2.3.4", "-port", "9443"})
	})

	if !strings.Contains(out, "sni=www.sushiwei.com") {
		t.Errorf("the share URI carries no SNI from selfsign_cn")
	}
	if !strings.Contains(out, "1.2.3.4:9443") {
		t.Errorf("the share URI lost the server address")
	}
	for _, bad := range []string{"tcp%3A%2F%2F", "tcp://127.0.0.1:22"} {
		if strings.Contains(out, bad) {
			t.Errorf("the share URI leaks a scheme-prefixed target %q", bad)
		}
	}
}
