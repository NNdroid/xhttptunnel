package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

const authTestPSK = "auth-test-secret"

// ---------------------------------------------------------------------------
// Signing primitives
// ---------------------------------------------------------------------------

func TestAuthMACRoundTrip(t *testing.T) {
	msg := authMessage("nonce-1", "session-A", "127.0.0.1:8080")
	got := authMAC("k1", msg)
	if got == "" {
		t.Fatal("authMAC returned an empty digest")
	}
	if !validHex(got, sha256.Size) {
		t.Fatalf("authMAC = %q, want %d hex chars", got, sha256.Size*2)
	}
	if !authMACMatches("k1", msg, got) {
		t.Fatal("authMACMatches rejected the digest it just produced")
	}
}

func TestAuthMACMatchesRejectsWrongKeyAndTamper(t *testing.T) {
	msg := authMessage("n", "s", "t")
	good := authMAC("key-A", msg)

	if authMACMatches("key-B", msg, good) {
		t.Error("authMACMatches accepted a digest from a different key")
	}
	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[len(tampered)-1] ^= 0x01
	if authMACMatches("key-A", tampered, good) {
		t.Error("authMACMatches accepted a digest for a tampered message")
	}
}

func TestAuthMACMatchesRejectsMalformed(t *testing.T) {
	msg := authMessage("n", "s", "t")
	good := authMAC("k", msg)

	for _, want := range []string{
		"",                        // absent
		good[:63],                 // truncated
		good + "0",                // too long
		"zzzz",                    // not hex
		good[:2] + " " + good[2:], // injected whitespace
	} {
		if authMACMatches("k", msg, want) {
			t.Errorf("authMACMatches accepted malformed digest %q", want)
		}
	}
	// A well-formed digest for a different key must not validate.
	if authMACMatches("other", msg, good) {
		t.Error("authMACMatches accepted another key's digest")
	}
}

// TestAuthMessageFieldSeparation pins the NUL-delimited canonical form: the
// concatenation of the three fields must never collide with a different
// fielding. A whitespace separator would collide, since spaces are legal
// inside a session id and a target.
func TestAuthMessageFieldSeparation(t *testing.T) {
	cases := []struct {
		name string
		a    [3]string
		b    [3]string
	}{
		{"session absorbed into nonce", [3]string{"ab", "c", "d"}, [3]string{"abc", "", "d"}},
		{"target absorbed into session", [3]string{"a", "bc", "d"}, [3]string{"a", "b", "cd"}},
		{"trailing empty vs folded", [3]string{"a", "b", ""}, [3]string{"a", "", "b"}},
		{"space inside a field", [3]string{"a b", "c", "d"}, [3]string{"a", "b c", "d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authMessage(tc.a[0], tc.a[1], tc.a[2]); bytes.Equal(got, authMessage(tc.b[0], tc.b[1], tc.b[2])) {
				t.Errorf("authMessage collided: %v and %v render identically", tc.a, tc.b)
			}
		})
	}

	// The domain prefix is what stops this MAC from being valid as the digest
	// of some other application that reuses the same PSK as a general key.
	if got := authMessage("n", "s", "t"); len(got) < len(authDomain)+3 {
		t.Errorf("authMessage = %q, domain prefix appears to be missing", got)
	}
}

func TestNewAuthNonceShapeAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1024)
	for i := 0; i < 1024; i++ {
		n, err := newAuthNonce()
		if err != nil {
			t.Fatalf("newAuthNonce: %v", err)
		}
		if !validAuthNonce(n) {
			t.Fatalf("newAuthNonce = %q, want %d hex chars", n, authNonceBytes*2)
		}
		if seen[n] {
			t.Fatalf("newAuthNonce repeated %q within %d draws", n, i+1)
		}
		seen[n] = true
	}
}

func TestValidHex(t *testing.T) {
	for _, tc := range []struct {
		in string
		n  int
		ok bool
	}{
		{"", 0, true},
		{"", 16, false},
		{"0123456789abcdef0123456789abcdef", 16, true},
		{"0123456789ABCDEF0123456789ABCDEF", 16, true},
		{"0123456789abcdef0123456789abcde", 16, false},
		{"0123456789abcdef0123456789abcdef0", 16, false},
		{"0123456789abcdef0123456789abcdef", 32, false},
		{"0123456789abcdef0123456789abcdfg", 16, false},
		{" 0123456789abcdef0123456789abcdef", 16, false},
	} {
		if got := validHex(tc.in, tc.n); got != tc.ok {
			t.Errorf("validHex(%q, %d) = %v, want %v", tc.in, tc.n, got, tc.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------

func TestNonceWindowRejectsReplay(t *testing.T) {
	w := newNonceWindow()
	if !w.mark("n-1") {
		t.Fatal("first use of a nonce was rejected")
	}
	if w.mark("n-1") {
		t.Fatal("replayed nonce was accepted")
	}
	// A different nonce is unaffected by the first one's entry.
	if !w.mark("n-2") {
		t.Fatal("an unrelated nonce was rejected")
	}
}

func TestNonceWindowExpiresNonce(t *testing.T) {
	w := newNonceWindow()
	c := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return c }

	// A nanosecond TTL would not work here: any two calls are spaced by more
	// than a nanosecond, so the "replay" mark would already see an expired
	// entry and report it as fresh. The clock is stepped instead.
	if !w.mark("n-1") {
		t.Fatal("the first use of a nonce was rejected")
	}
	if w.mark("n-1") {
		t.Fatal("a replay inside the window was accepted")
	}
	// Past the TTL the same nonce is spendable again: it is no longer inside
	// the window where a replay could still reach a live session.
	c = c.Add(w.ttl + time.Nanosecond)
	if !w.mark("n-1") {
		t.Fatal("a nonce older than the TTL was still treated as a replay")
	}
	// Spending it put it back inside the window.
	if w.mark("n-1") {
		t.Fatal("mark after expiry reported a fresh nonce")
	}
}

func TestNonceWindowSingleWinnerUnderConcurrency(t *testing.T) {
	const workers = 64
	w := newNonceWindow()

	var wg sync.WaitGroup
	winners := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			winners <- w.mark("contested-nonce")
		}()
	}
	wg.Wait()
	close(winners)

	n := 0
	for ok := range winners {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("nonces accepted under %d concurrent contenders = %d, want exactly 1", workers, n)
	}
}

func TestNonceWindowSweepsWhenOverCapacity(t *testing.T) {
	w := newNonceWindow()
	c := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return c }
	w.maxLen = 4

	for i := 0; i < 4; i++ {
		if !w.mark(strconv.Itoa(i)) {
			t.Fatalf("mark %d was refused", i)
		}
	}
	if len(w.seen) != 4 {
		t.Fatalf("window = %d entries, want 4", len(w.seen))
	}

	// Everything is expired by now. The next insert trips the capacity guard and
	// the sweep drops the dead entries instead of letting the map grow.
	c = c.Add(authNonceTTL)
	if !w.mark("4") {
		t.Fatal("mark 4 was refused")
	}
	if len(w.seen) != 1 {
		t.Errorf("window = %d entries after the sweep, want 1", len(w.seen))
	}
}

// ---------------------------------------------------------------------------
// Client-side header helper
// ---------------------------------------------------------------------------

func TestSetAuthHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := setAuthHeaders(req, "psk", "session-A", "127.0.0.1:8080"); err != nil {
		t.Fatalf("setAuthHeaders: %v", err)
	}
	nonce := req.Header.Get(AuthNonceHeader)
	mac := req.Header.Get(AuthMACHeader)
	if !validAuthNonce(nonce) {
		t.Fatalf("nonce header = %q, want %d hex chars", nonce, authNonceBytes*2)
	}
	if !validHex(mac, sha256.Size) {
		t.Fatalf("MAC header = %q, want %d hex chars", mac, sha256.Size*2)
	}
	// The MAC must be verifiable against the same session id and target that
	// the request itself carries. That is the binding the server checks.
	if !authMACMatches("psk", authMessage(nonce, "session-A", "127.0.0.1:8080"), mac) {
		t.Fatal("the MAC does not cover the request's own session and target")
	}

	// Two requests from the same PSK must carry different nonces.
	req2, _ := http.NewRequest(http.MethodGet, "http://example/", nil)
	if err := setAuthHeaders(req2, "psk", "session-A", "127.0.0.1:8080"); err != nil {
		t.Fatalf("setAuthHeaders: %v", err)
	}
	if req2.Header.Get(AuthNonceHeader) == nonce {
		t.Fatal("two consecutive requests reused a nonce")
	}
}

func TestSetAuthHeadersEmptyPassword(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example/", nil)
	if err := setAuthHeaders(req, "", "session-A", "127.0.0.1:8080"); err != nil {
		t.Fatalf("setAuthHeaders with an empty password: %v", err)
	}
	if req.Header.Get(AuthNonceHeader) != "" || req.Header.Get(AuthMACHeader) != "" {
		t.Fatal("an open tunnel must not carry signed credentials")
	}
}

// ---------------------------------------------------------------------------
// Server behaviour over real HTTP
// ---------------------------------------------------------------------------

// authTestServer brings up a real server whose allowlist denies the target the
// requests below ask for. A denied target answers 403 without polling, so 403
// is the marker for "authentication passed" and 407 is "authentication failed".
func authTestServer(t *testing.T, ctx context.Context, cfg ServerConfig) *url.URL {
	t.Helper()
	cfg.Listen = "tcp://127.0.0.1:0"
	cfg.Path = "/t"
	cfg.PSK = authTestPSK
	cfg.AllowedTargets = []string{"127.0.0.1:9"}
	if cfg.Handler == nil {
		cfg.Handler = func(c *XHTTPConn) { defer c.Close() }
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("server did not bind in time")
	}
	return &url.URL{Scheme: "http", Host: srv.Addr().String(), Path: "/t"}
}

// authHeaders builds a signed v2 request against the fixed session and target.
// signingKey lets a case mint a digest under the wrong PSK.
func authHeaders(t *testing.T, signingKey string) map[string]string {
	t.Helper()
	const session, target = "auth-test-sid", "127.0.0.1:7"
	nonce, err := newAuthNonce()
	if err != nil {
		t.Fatalf("newAuthNonce: %v", err)
	}
	return map[string]string{
		"X-Session-ID":  session,
		"X-Target":      target,
		ProtoHeader:     strconv.Itoa(offeredProtoVersion),
		AuthNonceHeader: nonce,
		AuthMACHeader:   authMAC(signingKey, authMessage(nonce, session, target)),
	}
}

func authTestStatus(t *testing.T, base *url.URL, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestServerAuthorizeMatrix(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"signed v2 accepted", authHeaders(t, authTestPSK), http.StatusForbidden},
		{
			"legacy bare token accepted",
			map[string]string{"X-Session-ID": "auth-test-sid", "X-Target": "127.0.0.1:7", "X-Auth-Token": authTestPSK},
			http.StatusForbidden,
		},
		{
			"legacy bearer accepted",
			map[string]string{"X-Session-ID": "auth-test-sid", "X-Target": "127.0.0.1:7", "Proxy-Authorization": "Bearer " + authTestPSK},
			http.StatusForbidden,
		},
		{"wrong PSK rejected", authHeaders(t, "attacker-key"), http.StatusProxyAuthRequired},
		{
			"v2 with no credentials rejected",
			map[string]string{"X-Session-ID": "auth-test-sid", "X-Target": "127.0.0.1:7", ProtoHeader: "2"},
			http.StatusProxyAuthRequired,
		},
		// A v2 client may not keep replayable credentials: this is what makes
		// min_proto_version=2 a real switch instead of a label.
		{
			"v2 advertising a bare token rejected",
			map[string]string{"X-Session-ID": "auth-test-sid", "X-Target": "127.0.0.1:7", ProtoHeader: "2", "X-Auth-Token": authTestPSK},
			http.StatusProxyAuthRequired,
		},
		{
			"legacy client with a bad signature still falls back",
			func() map[string]string {
				h := authHeaders(t, "wrong")
				h[ProtoHeader] = "1"
				h["X-Auth-Token"] = authTestPSK
				return h
			}(),
			http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authTestStatus(t, base, tc.headers); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestServerReplayRejectedEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	h := authHeaders(t, authTestPSK)
	if got := authTestStatus(t, base, h); got != http.StatusForbidden {
		t.Fatalf("original request: status = %d, want %d (auth passes)", got, http.StatusForbidden)
	}
	if got := authTestStatus(t, base, h); got != http.StatusProxyAuthRequired {
		t.Fatalf("replayed request: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	if got := authTestStatus(t, base, h); got != http.StatusProxyAuthRequired {
		t.Fatalf("third replay: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	// A freshly signed request still works, so the rejection is about the
	// nonce and not a tripwire on the whole server.
	if got := authTestStatus(t, base, authHeaders(t, authTestPSK)); got != http.StatusForbidden {
		t.Fatalf("fresh request after replay: status = %d, want %d", got, http.StatusForbidden)
	}
}

func TestServerRejectsResignedAndRetargeted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	h := authHeaders(t, authTestPSK)
	if got := authTestStatus(t, base, h); got != http.StatusForbidden {
		t.Fatalf("original: status = %d, want %d", got, http.StatusForbidden)
	}

	// Aim the same signature at an address the sender also has access to. The
	// target is bound into the digest, so this must not authenticate.
	retargeted := map[string]string{
		"X-Session-ID":  h["X-Session-ID"],
		"X-Target":      "127.0.0.1:80",
		ProtoHeader:     h[ProtoHeader],
		AuthNonceHeader: h[AuthNonceHeader],
		AuthMACHeader:   h[AuthMACHeader],
	}
	if got := authTestStatus(t, base, retargeted); got != http.StatusProxyAuthRequired {
		t.Fatalf("retargeted request: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}

	// The same signature presented for a different session id.
	resession := map[string]string{
		"X-Session-ID":  "someone-elses-session",
		"X-Target":      h["X-Target"],
		ProtoHeader:     h[ProtoHeader],
		AuthNonceHeader: h[AuthNonceHeader],
		AuthMACHeader:   h[AuthMACHeader],
	}
	if got := authTestStatus(t, base, resession); got != http.StatusProxyAuthRequired {
		t.Fatalf("re-sessoned request: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
}

func TestServerRejectsMalformedSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	cases := map[string]map[string]string{
		"no nonce": func() map[string]string {
			h := authHeaders(t, authTestPSK)
			delete(h, AuthNonceHeader)
			return h
		}(),
		"non-hex nonce": func() map[string]string {
			h := authHeaders(t, authTestPSK)
			h[AuthNonceHeader] = "not-a-nonce"
			return h
		}(),
		"short nonce": func() map[string]string {
			h := authHeaders(t, authTestPSK)
			h[AuthNonceHeader] = "0123456789abcdef"
			return h
		}(),
		"no MAC": func() map[string]string {
			h := authHeaders(t, authTestPSK)
			delete(h, AuthMACHeader)
			return h
		}(),
		"garbled MAC": func() map[string]string {
			h := authHeaders(t, authTestPSK)
			h[AuthMACHeader] = "zz" + h[AuthMACHeader][2:]
			return h
		}(),
		"truncated MAC": func() map[string]string {
			h := authHeaders(t, authTestPSK)
			h[AuthMACHeader] = h[AuthMACHeader][:63]
			return h
		}(),
	}
	for name, h := range cases {
		if got := authTestStatus(t, base, h); got != http.StatusProxyAuthRequired {
			t.Errorf("%s: status = %d, want %d", name, got, http.StatusProxyAuthRequired)
		}
	}
}

func TestServerMinProtoTwoClosesLegacy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{MinProtoVersion: 2})

	// A legacy client sends no version at all, so it is below the minimum.
	if got := authTestStatus(t, base, map[string]string{
		"X-Session-ID": "auth-test-sid", "X-Target": "127.0.0.1:7", "X-Auth-Token": authTestPSK,
	}); got != http.StatusUpgradeRequired {
		t.Fatalf("legacy client: status = %d, want %d", got, http.StatusUpgradeRequired)
	}
	// A signed client satisfies it.
	if got := authTestStatus(t, base, authHeaders(t, authTestPSK)); got != http.StatusForbidden {
		t.Fatalf("signed client: status = %d, want %d", got, http.StatusForbidden)
	}
}

func TestMinProtoTwoIsEnforcedAfterLegacyIsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{MinProtoVersion: 2})

	// The only way past the version gate without signing is a v2 announcement,
	// and a v2 announcement must sign. Together those two rules close the
	// bare-token path entirely.
	if got := authTestStatus(t, base, map[string]string{
		"X-Session-ID": "auth-test-sid", "X-Target": "127.0.0.1:7", ProtoHeader: "2", "X-Auth-Token": authTestPSK,
	}); got != http.StatusProxyAuthRequired {
		t.Fatalf("v2 without a signature: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
}

// ---------------------------------------------------------------------------
// Fallback camouflage must not forward the credential
// ---------------------------------------------------------------------------

func TestScrubStripsSignedHeaders(t *testing.T) {
	for _, h := range []string{AuthNonceHeader, AuthMACHeader} {
		if !containsString(tunnelRequestHeaders, h) {
			t.Errorf("%s is not in the scrub list; it would be forwarded to the disguise target", h)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example/", nil)
	req.Header.Set(AuthNonceHeader, "0123456789abcdef0123456789abcdef")
	req.Header.Set(AuthMACHeader, "ab")
	req.Header.Set("X-Auth-Token", authTestPSK)
	scrubTunnelRequest(req)

	for _, h := range []string{AuthNonceHeader, AuthMACHeader, "X-Auth-Token"} {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("%s survived the scrub: %q", h, v)
		}
	}
}
