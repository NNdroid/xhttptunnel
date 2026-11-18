package tunnel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// wireRequest captures the first request a test proxy sees. The proxy handler
// runs on httptest's goroutines while the assertions run on the test goroutine,
// so both the capture and the read must go through the same lock.
type wireRequest struct {
	mu     sync.Mutex
	header http.Header
	query  string
}

func (c *wireRequest) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.header == nil {
		c.header = r.Header.Clone()
		c.query = r.URL.RawQuery
	}
}

func (c *wireRequest) snapshot() (http.Header, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.header == nil {
		return nil, ""
	}
	return c.header.Clone(), c.query
}

// TestEndToEndDerivedNamesOnTheWire drives a real PSK client through a
// recording proxy to a real PSK origin, and asserts the request that actually
// hit the wire carried the URL salt and per-session derived names, not the
// constants.
func TestEndToEndDerivedNamesOnTheWire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const secret = "e2e-derived-secret"
	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", secret, "", "", "")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)
	originURL, _ := url.Parse("http://" + origin.Addr().String() + "/stream")

	var first wireRequest
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.record(r)
		r.RequestURI = ""
		r.URL.Scheme = originURL.Scheme
		r.URL.Host = originURL.Host
		r.Host = originURL.Host
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, "origin unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		for k, vv := range resp.Header {
			if http.CanonicalHeaderKey(k) == "Content-Length" {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	}))
	defer proxy.Close()

	serverURL, _ := url.Parse(proxy.URL + "/stream")
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password: secret, Path: "/stream", ALPN: "h1", StreamMode: "poll",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("derived-name-ping")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), string(payload)) {
		t.Fatalf("echo mismatch: %q", got)
	}

	firstHeader, firstQuery := first.snapshot()
	if firstHeader == nil {
		t.Fatal("proxy never saw a request")
	}
	if !strings.Contains(firstQuery, "s=") {
		t.Fatalf("derived request carried no URL salt: %q", firstQuery)
	}
	// The constant names must not appear on the wire.
	for _, c := range []string{"X-Trace", "X-Route", "X-Net", "X-Ver", "X-Pos", "X-Req-Id", "X-Req-Sig"} {
		if v := firstHeader.Get(c); v != "" {
			t.Fatalf("constant header %s leaked to the wire (%q)", c, v)
		}
	}
	// A derived name must be present and not equal to a constant.
	namer := deriveHeaderNamer(secret, firstQueryValue(t, firstQuery))
	if firstHeader.Get(namer.name(slotTarget)) == "" {
		t.Fatal("the derived target header was not on the wire")
	}
	if firstHeader.Get(namer.name(slotAuthMAC)) == "" {
		t.Fatal("the derived signature header was not on the wire")
	}
	t.Logf("wire query=%q derived-target=%q derived-mac=%q", firstQuery, firstHeader.Get(namer.name(slotTarget)), firstHeader.Get(namer.name(slotAuthMAC)))
}

// TestStrictModeRequiresPSK pins the strict-mode contract at the low-level
// entry points: a client without a PSK is refused at dial time and a listener
// without a token refuses to start. Neither side may silently produce a
// tunnel whose every request the other end would reject — that is what a
// token-less ListenXHTTP did before this check existed, because the strict
// session handler refuses every request that carries no URL salt.
func TestStrictModeRequiresPSK(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, _ := url.Parse("http://127.0.0.1:1/stream")
	_, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Path: "/stream", ALPN: "h1", StreamMode: "poll",
	}, "127.0.0.1:9", "tcp")
	if err == nil {
		t.Fatal("a password-less dial was accepted")
	}
	if !strings.Contains(err.Error(), "PSK is required") {
		t.Fatalf("dial error does not name the missing PSK: %v", err)
	}

	_, err = ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "", "", "", "")
	if err == nil {
		t.Fatal("a token-less listener was accepted")
	}
	if !strings.Contains(err.Error(), "PSK is required") {
		t.Fatalf("listen error does not name the missing PSK: %v", err)
	}
}

func firstQueryValue(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse("http://x?" + raw)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	return u.Query().Get(saltParam)
}
