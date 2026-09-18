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
	req.Header.Set("X-Session-ID", "5449801b132c8bf037f2a5f0be822e91")
	req.Header.Set("X-Target", "127.0.0.1:22222")
	req.Header.Set("X-Network", "tcp")
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

// TestScrubTunnelRequestNoBody is the guard against a future refactor: the
// scrubber must be safe to run on a request that already carries no body, and
// it must not panic on http.NoBody.
func TestScrubTunnelRequestNoBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	req.Header.Set("X-Auth-Token", "my-secret-token")
	req.Header.Set("User-Agent", "curl/8.0.0")

	scrubTunnelRequest(req)

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
