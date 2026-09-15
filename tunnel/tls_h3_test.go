package tunnel

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestListenXHTTP_HTTP3RequiresTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A cleartext origin is the normal CDN-origin deployment. It should not
	// reserve UDP or advertise an H3 capability it cannot serve.
	listener, err := ListenXHTTP(ctx, "tcp+udp://127.0.0.1:0", "/stream", "", "", "", "")
	if err != nil {
		t.Fatalf("start cleartext listener: %v", err)
	}
	defer listener.Close()
	if !listener.srvTCP || listener.ln == nil {
		t.Fatal("cleartext listener did not start TCP")
	}
	if listener.srvUDP || listener.uln != nil {
		t.Fatal("cleartext listener unexpectedly reserved UDP/H3")
	}

	if _, err := ListenXHTTP(ctx, "udp://127.0.0.1:0", "/stream", "", "", "", ""); err == nil {
		t.Fatal("cleartext udp:// listener must be rejected because H3 requires TLS")
	}
	if _, err := ListenXHTTP(ctx, "tcp://127.0.0.1:0", "/stream", "", "only-cert.pem", "", ""); err == nil {
		t.Fatal("partial TLS configuration must be rejected")
	}
}

func TestXHTTPTunnel_E2E_TLSHTTP3(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	if err := GenerateSelfSignedCert(certFile, keyFile, "localhost"); err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "tcp+udp://127.0.0.1:0", "/stream", "h3-test-secret", certFile, keyFile, "")
	if err != nil {
		t.Fatalf("start TLS/H3 origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	if !origin.srvTCP || !origin.srvUDP || origin.ln == nil || origin.uln == nil {
		t.Fatal("TLS listener must start both HTTPS and HTTP/3")
	}
	tcpPort := origin.ln.Addr().(*net.TCPAddr).Port
	udpPort := origin.uln.LocalAddr().(*net.UDPAddr).Port
	if tcpPort != udpPort {
		t.Fatalf("HTTPS port %d and H3 UDP port %d must match", tcpPort, udpPort)
	}

	serverURL, err := url.Parse("https://" + origin.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("parse H3 URL: %v", err)
	}
	if insecureConn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password: "h3-test-secret",
		Path:     "/stream",
		SNI:      "localhost",
		ALPN:     "h3",
	}, echoAddr, "tcp"); err == nil {
		insecureConn.Close()
		t.Fatal("self-signed HTTPS without a fingerprint must fail certificate verification")
	}
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password:               "h3-test-secret",
		Path:                   "/stream",
		SNI:                    "localhost",
		ALPN:                   "h3",
		CertificateFingerprint: testCertificateFingerprint(t, certFile),
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial HTTP/3 tunnel: %v", err)
	}
	defer conn.Close()

	payload := []byte("HTTP/3 over TLS tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over HTTP/3 tunnel: %v", err)
	}
	got, err := readFullBefore(conn, len(payload), 15*time.Second)
	if err != nil {
		t.Fatalf("read HTTP/3 echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("HTTP/3 echo = %q, want %q", got, payload)
	}
}

func TestSelfSignedTLSRequiresFingerprintH1H2(t *testing.T) {
	for _, alpn := range []string{"h1", "h2"} {
		t.Run(alpn, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			certDir := t.TempDir()
			certFile := filepath.Join(certDir, "cert.pem")
			keyFile := filepath.Join(certDir, "key.pem")
			if err := GenerateSelfSignedCert(certFile, keyFile, "localhost"); err != nil {
				t.Fatal(err)
			}
			echoAddr, closeEcho := startTCPEchoServer(t)
			defer closeEcho()
			origin, err := ListenXHTTP(ctx, "tcp://127.0.0.1:0", "/stream", "tls-test-secret", certFile, keyFile, "")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			serveAcceptedTCPEcho(t, ctx, origin)
			serverURL, err := url.Parse("https://" + origin.Addr().String() + "/stream")
			if err != nil {
				t.Fatal(err)
			}
			base := DialConfig{
				Password: "tls-test-secret", Path: "/stream", SNI: "localhost", ALPN: alpn,
				TransportKey: "tls-pin-" + alpn,
			}
			conn, err := DialXHTTP(ctx, serverURL, &base, echoAddr, "tcp")
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("self-signed HTTPS without a fingerprint passed certificate verification")
			}
			base.CertificateFingerprint = testCertificateFingerprint(t, certFile)
			conn, err = DialXHTTP(ctx, serverURL, &base, echoAddr, "tcp")
			if err != nil {
				t.Fatalf("pinned self-signed TLS dial: %v", err)
			}
			conn.Close()
		})
	}
}

func TestSelectTransportReusesHTTP3(t *testing.T) {
	transportMu.Lock()
	original := transportCache
	transportCache = make(map[string]http.RoundTripper)
	transportMu.Unlock()
	defer func() {
		transportMu.Lock()
		for _, transport := range transportCache {
			if h3, ok := transport.(*http3.Transport); ok {
				_ = h3.Close()
			}
		}
		transportCache = original
		transportMu.Unlock()
	}()

	cfg := &DialConfig{SNI: "cdn.example.test", ALPN: "h3"}
	protos := buildNextProtos(cfg.ALPN)
	first, ownedFirst := selectTransport("h3", cfg, protos, true, "127.0.0.1:443")
	second, ownedSecond := selectTransport("h3", cfg, protos, true, "127.0.0.1:443")
	if ownedFirst || ownedSecond {
		t.Fatal("HTTP/3 transport must be shared, not owned by one session")
	}
	if first != second {
		t.Fatal("HTTP/3 transport was not reused for the same endpoint")
	}
}
