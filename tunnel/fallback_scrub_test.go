package tunnel

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFallbackProxyScrubTunnelState locks in that camouflage traffic never
// carries protocol state to the disguise target. X-Auth-Token is the raw
// pre-shared key, and it is deliberately not hop-by-hop: Proxy-Authorization
// is stripped by ReverseProxy, which is precisely why the duplicate exists,
// so it would be wrong to rely on the transport to strip it too.
func TestFallbackProxyScrubTunnelState(t *testing.T) {
	var got http.Header
	var gotBody string
	var gotMethod string
	var gotCL int64
	disguise := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		gotMethod = r.Method
		gotCL = r.ContentLength
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read forwarded body: %v", err)
		}
		gotBody = string(b)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer disguise.Close()

	h := buildSessionHandler(nil, newServerState(1), "/stream", "", disguise.URL)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()

	frame := []byte{0x00, 0x01, 0x02, 0x10, 0xaa, 0xbb}
	req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/", strings.NewReader(string(frame)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Auth-Token", "my-secret-token")
	req.Header.Set("Proxy-Authorization", "Bearer my-secret-token")
	req.Header.Set(SessionIDHeader, "5449801b132c8bf037f2a5f0be822e91")
	req.Header.Set(TargetHeader, "127.0.0.1:22222")
	req.Header.Set(NetworkHeader, "tcp")
	req.Header.Set(ProtoHeader, "1")
	req.Header.Set("User-Agent", "curl/8.0.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// The disguise target's status is passed through untouched: that is the
	// camouflage, and a client seeing a foreign 403 is exactly what motivated
	// this test.
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 from the disguise target, got %d", resp.StatusCode)
	}

	for _, hdr := range tunnelRequestHeaders {
		if v := got.Get(hdr); v != "" {
			t.Errorf("leaked %s=%q to the disguise target", hdr, v)
		}
	}
	if got.Get("X-Auth-Token") != "" {
		t.Errorf("pre-shared key leaked to the disguise target: %q", got.Get("X-Auth-Token"))
	}
	if got.Get("Proxy-Authorization") != "" {
		t.Errorf("Proxy-Authorization leaked to the disguise target: %q", got.Get("Proxy-Authorization"))
	}
	if strings.Contains(gotBody, string(frame[4:])) || len(gotBody) > 0 {
		t.Errorf("tunnel frame body leaked to the disguise target: %q", gotBody)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("forwarded method = %s, want %s (method is kept for camouflage)", gotMethod, http.MethodPost)
	}
	if gotCL != 0 {
		t.Errorf("forwarded Content-Length = %d, want 0", gotCL)
	}
	if got.Get("User-Agent") == "" {
		t.Error("ordinary web headers must survive the scrub")
	}
}

// TestScrubDropsEveryProtocolHeader is the guard the test above cannot be.
// That one asks whether scrubbing removed the names on the scrub list, which is
// true by construction: it iterates the same list it is checking. This one
// names the headers independently, so removing an entry from the list fails
// here while passing there.
//
// X-Offset, X-Features and X-Ingest travelled to the disguise
// target for exactly as long as this test did not exist — the only check was
// the one derived from the list they were missing from.
func TestScrubDropsEveryProtocolHeader(t *testing.T) {
	// Written out rather than read from tunnelRequestHeaders: an independent
	// copy that has to be kept in agreement is the whole point.
	sent := []string{
		AuthNonceHeader, AuthMACHeader, AuthBodyMACHeader,
		PadHeader, CapsHeader, BwHeader, ProtoHeader,
		"X-Auth-Token",
		TargetHeader, NetworkHeader, SessionIDHeader,
		SeqHeader, AckHeader, RetryHeader, DownstreamHeader,
		StreamResumeHeader, StreamProbeWindowHeader,
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.invalid/", strings.NewReader("frame bytes"))
	for _, h := range sent {
		req.Header.Set(h, "probe")
	}
	// The protocol no longer has a namespace prefix that catches an unlisted
	// header at runtime; the registry completeness test
	// (TestEveryProtocolHeaderIsScrubbedOrResponseOnly) takes that role. So the
	// check here is the opposite side of the same guarantee: a header that is
	// legitimately response-only must NOT be scrubbed off a request it does not
	// belong on, while a request-borne one must.
	req.Header.Set(AuthRespMACHeader, "probe")
	// Ordinary browser headers, which camouflage depends on keeping.
	req.Header.Set("User-Agent", "curl/8.0.0")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	scrubTunnelRequest(req, "")

	for _, h := range sent {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("%s survived the scrub: %q", h, v)
		}
	}
	if v := req.Header.Get(AuthRespMACHeader); v == "" {
		t.Error("a response-only header must not be scrubbed off a request it does not belong on")
	}
	if req.Header.Get("User-Agent") == "" || req.Header.Get("Accept-Language") == "" {
		t.Error("ordinary headers must survive the scrub")
	}
	// The response-only header plus the two browser headers.
	if len(req.Header) != 3 {
		t.Errorf("scrubbed request still carries %d headers: %v", len(req.Header), req.Header)
	}
}

// TestScrubTunnelRequestNoBody is the guard against a future refactor: the
// scrubber must be safe to run on a request that already carries no body, and
// it must not panic on http.NoBody.
func TestScrubTunnelRequestNoBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	req.Header.Set("X-Auth-Token", "my-secret-token")
	req.Header.Set("User-Agent", "curl/8.0.0")

	scrubTunnelRequest(req, "")

	if req.Body != http.NoBody {
		t.Errorf("Body = %T, want http.NoBody", req.Body)
	}
	if req.ContentLength != 0 {
		t.Errorf("Content-Length = %d, want 0", req.ContentLength)
	}
	if req.GetBody != nil {
		t.Error("GetBody must be cleared so a retry cannot resurrect the body")
	}
	if req.Header.Get("X-Auth-Token") != "" {
		t.Error("X-Auth-Token not removed")
	}
	if req.Header.Get("User-Agent") != "curl/8.0.0" {
		t.Error("User-Agent must survive the scrub")
	}
}

// TestFallbackServesMissingSaltOnTunnelPath locks in that an unauthorized
// request landing on the tunnel path — here, no session salt at all — is
// proxied to the decoy when one is configured, instead of being answered with a
// bare 400. Before this, only a path mismatch triggered the fallback, so a
// browser that hit the tunnel path saw a 400 rather than the camouflage site.
func TestFallbackServesMissingSaltOnTunnelPath(t *testing.T) {
	disguise := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DISGUISE-SITE"))
	}))
	defer disguise.Close()

	xl := &XHTTPListener{connCh: make(chan *XHTTPConn, 256), expectedToken: "test-token"}
	h := buildSessionHandler(xl, newServerState(1), "/stream", "test-token", disguise.URL)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (decoy)", resp.StatusCode)
	}
	if string(body) != "DISGUISE-SITE" {
		t.Fatalf("body = %q, want the decoy site", string(body))
	}
}

// TestNoFallbackReturns400OnTunnelPath is the counter-case: without a decoy, a
// salt-less request on the tunnel path still gets the compact 400.
func TestNoFallbackReturns400OnTunnelPath(t *testing.T) {
	xl := &XHTTPListener{connCh: make(chan *XHTTPConn, 256), expectedToken: "test-token"}
	h := buildSessionHandler(xl, newServerState(1), "/stream", "test-token", "")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestFallbackServesBadAuthOnTunnelPath extends the policy to the auth failure
// case: a request that carries a salt but fails authentication is also proxied
// to the decoy, so a probe with a guessed session id sees a normal site rather
// than an auth error.
func TestFallbackServesBadAuthOnTunnelPath(t *testing.T) {
	disguise := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DISGUISE-SITE"))
	}))
	defer disguise.Close()

	xl := &XHTTPListener{connCh: make(chan *XHTTPConn, 256), expectedToken: "test-token"}
	h := buildSessionHandler(xl, newServerState(1), "/stream", "test-token", disguise.URL)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()

	// Salt present but no signed generation → authentication fails.
	resp, err := http.Get("http://" + ln.Addr().String() + "/stream?s=some-made-up-id")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (decoy)", resp.StatusCode)
	}
	if string(body) != "DISGUISE-SITE" {
		t.Fatalf("body = %q, want the decoy site", string(body))
	}
}
