package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// helperSeq hands every startTunnelServer call a distinct TransportKey.
var helperSeq atomic.Uint64

// startTunnelServer brings up a Server for the given ALPN and returns the
// client-side dial parameters. h3 needs a TLS + UDP origin (HTTP/3 runs over
// QUIC); h1 and h2 run against a cleartext origin (h2c for h2).
func startTunnelServer(t testing.TB, ctx context.Context, alpn string) (*url.URL, *DialConfig) {
	t.Helper()
	const (
		secret = "matrix-secret"
		path   = "/stream"
	)

	cfg := ServerConfig{Listen: "tcp://127.0.0.1:0", Path: path, PSK: secret}
	scheme := "http"
	dial := &DialConfig{Password: secret, Path: path, ALPN: alpn}

	if alpn == "h3" {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "cert.pem")
		keyFile := filepath.Join(dir, "key.pem")
		if err := GenerateSelfSignedCert(certFile, keyFile, "localhost"); err != nil {
			t.Fatalf("generate test certificate: %v", err)
		}
		cfg.Listen = "tcp+udp://127.0.0.1:0"
		cfg.CertFile, cfg.KeyFile = certFile, keyFile
		scheme = "https"
		dial.SNI = "localhost"
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer(%s): %v", alpn, err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })

	// A unique TransportKey per helper call keeps the shared transport cache
	// from handing a previous run's (dead) connection to this one: sequential
	// servers often recycle the same ephemeral port, and a stale pooled QUIC
	// connection only errors out after its idle timeout — which a timed
	// benchmark would happily report as a 30s outlier.
	dial.TransportKey = fmt.Sprintf("helper-%d", helperSeq.Add(1))

	var addr net.Addr
	for i := 0; i < 1000 && addr == nil; i++ {
		select {
		case err := <-serveErr:
			t.Fatalf("server (%s) failed to start: %v", alpn, err)
		default:
		}
		addr = srv.Addr()
		if addr == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if addr == nil {
		t.Fatalf("server (%s) did not bind in time", alpn)
	}

	serverURL, err := url.Parse(fmt.Sprintf("%s://%s%s", scheme, addr.String(), path))
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return serverURL, dial
}

// TestXHTTPTunnel_ProtocolMatrix_HTTPTarget routes a TCP tunnel session to a
// real HTTP server and reuses the SAME tunnel connection for 10 sequential
// HTTP/1.1 keep-alive requests, once per ALPN (h1/h2/h3). It proves the tunnel
// preserves a request/response byte stream and survives connection reuse.
func TestXHTTPTunnel_ProtocolMatrix_HTTPTarget(t *testing.T) {
	for _, alpn := range []string{"h1", "h2", "h3"} {
		t.Run(alpn, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			serverURL, dial := startTunnelServer(t, ctx, alpn)

			hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "response-%s", r.Header.Get("X-Req"))
			}))
			defer hs.Close()
			targetAddr := mustHostPort(t, hs.URL)

			conn, err := DialXHTTP(ctx, serverURL, dial, targetAddr, "tcp")
			if err != nil {
				t.Fatalf("dial HTTP target through %s tunnel: %v", alpn, err)
			}
			defer conn.Close()

			// One bufio.Reader over the whole connection: HTTP/1.1 keep-alive
			// means the 10 responses arrive back-to-back on a single stream.
			br := bufio.NewReader(conn)
			for i := 1; i <= 10; i++ {
				req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: tunnel.test\r\nX-Req: %d\r\n\r\n", i)
				if _, err := conn.Write([]byte(req)); err != nil {
					t.Fatalf("request %d write: %v", i, err)
				}
				resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
				if err != nil {
					t.Fatalf("request %d read response: %v", i, err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatalf("request %d read body: %v", i, err)
				}
				if want := fmt.Sprintf("response-%d", i); string(body) != want {
					t.Fatalf("request %d body = %q, want %q", i, body, want)
				}
			}
		})
	}
}

// TestXHTTPTunnel_ProtocolMatrix_DNSTarget routes a UDP tunnel session to a
// real DNS server and reuses the SAME tunnel session for 10 queries, once per
// ALPN. Each query is a well-formed A record request and each response is
// verified to be a matching DNS reply, so this exercises the UDP datagram
// framing end to end (not just an opaque echo).
func TestXHTTPTunnel_ProtocolMatrix_DNSTarget(t *testing.T) {
	for _, alpn := range []string{"h1", "h2", "h3"} {
		t.Run(alpn, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			serverURL, dial := startTunnelServer(t, ctx, alpn)
			dnsAddr, closeDNS := startDNSServer(t)
			defer closeDNS()

			conn, err := DialXHTTP(ctx, serverURL, dial, dnsAddr, "udp")
			if err != nil {
				t.Fatalf("dial DNS target through %s tunnel: %v", alpn, err)
			}
			defer conn.Close()

			respBuf := make([]byte, 512)
			for i := 0; i < 10; i++ {
				id := uint16(0x1000 + i)
				query := buildDNSQuery(t, id, "example.com.")
				if err := WriteUDPFrame(conn, query); err != nil {
					t.Fatalf("query %d write: %v", i, err)
				}
				n, err := ReadUDPFrameInto(conn, respBuf)
				if err != nil {
					t.Fatalf("query %d read: %v", i, err)
				}
				assertDNSAnswer(t, respBuf[:n], id, "127.0.0.1")
			}
		})
	}
}

// startTCPSinkServer accepts TCP connections and discards all input. Useful
// for uplink-only scenarios where no downlink ever flows.
func startTCPSinkServer(t testing.TB) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sink: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64*1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// startDNSServer runs a minimal authoritative DNS responder on UDP: for any
// query it returns a single A record pointing at 127.0.0.1, echoing the
// transaction ID and question.
func startDNSServer(t testing.TB) (addr string, closeFn func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildDNSResponse(t, buf[:n])
			if resp == nil {
				continue
			}
			if _, err := pc.WriteTo(resp, from); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

func buildDNSQuery(t testing.TB, id uint16, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("start questions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("add question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("finish dns query: %v", err)
	}
	return msg
}

func buildDNSResponse(t testing.TB, query []byte) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q); err != nil {
		return nil
	}
	if err := b.StartAnswers(); err != nil {
		return nil
	}
	if err := b.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, Type: dnsmessage.TypeA, TTL: 60},
		dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
	); err != nil {
		return nil
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

func assertDNSAnswer(t testing.TB, msg []byte, wantID uint16, wantIP string) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		t.Fatalf("parse dns response: %v", err)
	}
	if !h.Response {
		t.Fatalf("response flag not set (id=%d)", wantID)
	}
	if h.ID != wantID {
		t.Fatalf("response id = %d, want %d", h.ID, wantID)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	rh, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("read answer header: %v", err)
	}
	if rh.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want A", rh.Type)
	}
	a, err := p.AResource()
	if err != nil {
		t.Fatalf("read A resource: %v", err)
	}
	if got := net.IP(a.A[:]).String(); got != wantIP {
		t.Fatalf("answer = %s, want %s", got, wantIP)
	}
}

func mustHostPort(t testing.TB, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}
