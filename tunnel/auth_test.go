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
	msg := authMessage("nonce-1", "session-A", "tcp", "127.0.0.1:8080")
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
	msg := authMessage("n", "s", "tcp", "t")
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
	msg := authMessage("n", "s", "tcp", "t")
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
// concatenation of the four fields must never collide with a different
// fielding. A whitespace separator would collide, since spaces are legal
// inside a session id, a network, and a target.
func TestAuthMessageFieldSeparation(t *testing.T) {
	cases := []struct {
		name string
		a    [4]string
		b    [4]string
	}{
		{"session absorbed into nonce", [4]string{"ab", "c", "tcp", "d"}, [4]string{"abc", "", "tcp", "d"}},
		{"network absorbed into session", [4]string{"a", "bc", "tcp", "d"}, [4]string{"a", "b", "ctcp", "d"}},
		{"target absorbed into network", [4]string{"a", "b", "ctcp", "d"}, [4]string{"a", "b", "tcp", "cd"}},
		{"trailing empty vs folded", [4]string{"a", "b", "tcp", ""}, [4]string{"a", "b", "", "tcp"}},
		{"space inside a field", [4]string{"a b", "c", "tcp", "d"}, [4]string{"a", "b c", "tcp", "d"}},
		{"space inside network", [4]string{"a", "b", "t cp", "d"}, [4]string{"a", "b", "t", "cpd"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authMessage(tc.a[0], tc.a[1], tc.a[2], tc.a[3]); bytes.Equal(got, authMessage(tc.b[0], tc.b[1], tc.b[2], tc.b[3])) {
				t.Errorf("authMessage collided: %v and %v render identically", tc.a, tc.b)
			}
		})
	}

	// The domain prefix is what stops this MAC from being valid as the digest
	// of some other application that reuses the same PSK as a general key.
	if got := authMessage("n", "s", "tcp", "t"); len(got) < len(authDomain)+4 {
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
	// The nonces below all share the first character, so they land in one
	// shard and the capacity guard fires on that shard alone.
	shard := &w.shards[nonceShardIndex("0a")]
	shard.maxLen = 4

	for _, n := range []string{"0a", "0b", "0c", "0d"} {
		if !w.mark(n) {
			t.Fatalf("mark %q was refused", n)
		}
	}
	if len(shard.seen) != 4 {
		t.Fatalf("window = %d entries, want 4", len(shard.seen))
	}

	// Everything is expired by now. The next insert trips the capacity guard and
	// the sweep drops the dead entries instead of letting the map grow.
	c = c.Add(authNonceTTL)
	if !w.mark("0e") {
		t.Fatal("mark 0e was refused")
	}
	if len(shard.seen) != 1 {
		t.Errorf("window = %d entries after the sweep, want 1", len(shard.seen))
	}
}

// ---------------------------------------------------------------------------
// Client-side header helper
// ---------------------------------------------------------------------------

func TestSignRequest(t *testing.T) {
	testAuth := requestAuth{
		sessionID: "session-A",
		network:   "tcp",
		target:    "127.0.0.1:8080",
		method:    http.MethodGet,
		proto:     offeredProtoVersion,
	}
	req, err := http.NewRequest(http.MethodGet, "http://example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := signRequest(req, "psk", testAuth, defaultHeaderNamer())
	if err != nil {
		t.Fatalf("signRequest: %v", err)
	}
	mac := req.Header.Get(AuthMACHeader)
	if !validAuthNonce(nonce) {
		t.Fatalf("nonce header = %q, want %d hex chars", nonce, authNonceBytes*2)
	}
	if !validHex(mac, sha256.Size) {
		t.Fatalf("MAC header = %q, want %d hex chars", mac, sha256.Size*2)
	}
	// A signed request states how much pad it carries even when the answer
	// is none, and the pad it states is the masked one: what is signed has
	// to be what is on the wire.
	if got := req.Header.Get(PadHeader); got == "" {
		t.Fatal("a signed request states its pad, including when it carries none")
	}
	m := maskFor(reqMaskDomain, "psk", nonce)
	wire := counters{pad: strconv.Itoa(int(maskU16(0, m, 16)))}
	// The MAC must be verifiable against everything the request itself
	// carries. That is the binding the server checks.
	if !authMACMatches("psk", v3Message(nonce, testAuth, wire), mac) {
		t.Fatal("the MAC does not cover the request's own session, network and target")
	}

	// Two requests from the same PSK must carry different nonces.
	req2, _ := http.NewRequest(http.MethodGet, "http://example/", nil)
	nonce2, err := signRequest(req2, "psk", testAuth, defaultHeaderNamer())
	if err != nil {
		t.Fatalf("signRequest: %v", err)
	}
	if nonce2 == nonce {
		t.Fatal("two consecutive requests reused a nonce")
	}
	if req2.Header.Get(AuthMACHeader) == req.Header.Get(AuthMACHeader) {
		t.Fatal("two consecutive requests produced the same MAC: the nonce is not being signed")
	}
}

func TestSignRequestEmptyPassword(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example/", nil)
	nonce, err := signRequest(req, "", requestAuth{sessionID: "session-A"}, defaultHeaderNamer())
	if err != nil {
		t.Fatalf("signRequest with an empty password: %v", err)
	}
	if nonce != "" || req.Header.Get(AuthNonceHeader) != "" || req.Header.Get(AuthMACHeader) != "" {
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

// authTestSession is the fixed session the matrix signs for. In derived mode
// it is the URL salt every request carries; it is also what the header names
// are derived from, so a case that rewrites one of them has to derive the
// names the same way the helper did.
const authTestSession = "auth-test-sid"

// authTestNamer returns the namer a request under the fixed session derives
// when signed with the given key. A case that mangles a header of a request
// built by authRequest gets the header name from here, the same way the
// client would have written it.
func authTestNamer(signingKey string) headerNamer {
	return deriveHeaderNamer(signingKey, authTestSession)
}

// authRequest builds a signed request the way a current client does: derived
// header names, the session id as the ?s= URL salt, and the signature under
// the same namer. signingKey lets a case mint a request under the wrong PSK —
// which derives the wrong names too, exactly as a client configured with the
// wrong key would, so the server cannot even find the signature to reject.
func authRequest(t *testing.T, signingKey string) *http.Request {
	t.Helper()
	return signedRequestFor(t, signingKey, http.MethodGet, authTestSession, "tcp", "127.0.0.1:7", nil)
}

// signedRequestFor signs the given request description the way the client
// does and returns the request it would have sent. Building it through
// signRequest rather than assembling the MAC by hand is what keeps a test
// honest: a request that advertises the current generation has to be signed
// the way that generation signs, or the test is only pinning that the server
// rejects its own forgery.
//
// The request is built under derived names — the strict mode the server runs
// in — with the session id riding the URL salt rather than a header.
func signedRequestFor(t *testing.T, signingKey, method, session, network, target string, extra map[string]string) *http.Request {
	t.Helper()
	namer := deriveHeaderNamer(signingKey, session)
	req, err := http.NewRequest(method, "http://tunnel.invalid/stream", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	q := req.URL.Query()
	q.Set(saltParam, session)
	req.URL.RawQuery = q.Encode()
	req.Header.Set(namer.name(slotNetwork), network)
	req.Header.Set(namer.name(slotTarget), target)
	// The generation this request advertises, which is what decides whether
	// the server holds it to its signature at all.
	req.Header.Set(namer.name(slotProto), strconv.Itoa(offeredProtoVersion))
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	if _, err := signRequest(req, signingKey, requestAuth{
		sessionID: session,
		network:   network,
		target:    target,
		method:    method,
		proto:     offeredProtoVersion,
		bodyKind:  bodyKindFor(req),
		// Signed as carrying nothing: an empty body has a digest, and it is
		// not the same as no digest at all.
		body: []byte{},
	}, namer); err != nil {
		t.Fatalf("signRequest: %v", err)
	}
	return req
}

// constantNameRequest builds the request a legacy client sends: constant
// header names, the session id in a header rather than the URL salt, and no
// signature unless extra adds one. Strict mode refuses every one of these,
// which is what makes the mode a real cutover rather than a preference.
func constantNameRequest(t *testing.T, extra map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://tunnel.invalid/stream", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(SessionIDHeader, authTestSession)
	req.Header.Set(NetworkHeader, "tcp")
	req.Header.Set(TargetHeader, "127.0.0.1:7")
	req.Header.Set(ProtoHeader, strconv.Itoa(offeredProtoVersion))
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return req
}

// authTestStatus replays a built request against the test server and returns
// the status. The request keeps its query (the derived mode's ?s= salt) and
// gets the server's host and path; everything else travels as the helper or
// the case built it.
func authTestStatus(t *testing.T, base *url.URL, req *http.Request) int {
	t.Helper()
	u := *base
	u.RawQuery = req.URL.RawQuery
	req.URL = &u
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
		name string
		req  *http.Request
		want int
	}{
		{"signed v2 accepted", authRequest(t, authTestPSK), http.StatusForbidden},
		// Strict mode refuses a constant-name request before it looks at any
		// credential: without the URL salt there is no session id to derive
		// names from, and that is the answer that closes the legacy path.
		{
			"constant-name bare token rejected at the salt gate",
			constantNameRequest(t, map[string]string{"X-Auth-Token": authTestPSK}),
			http.StatusBadRequest,
		},
		{
			"constant-name bearer rejected at the salt gate",
			constantNameRequest(t, map[string]string{"Proxy-Authorization": "Bearer " + authTestPSK}),
			http.StatusBadRequest,
		},
		{"wrong PSK rejected", authRequest(t, "attacker-key"), http.StatusProxyAuthRequired},
		{
			"v2 with no credentials rejected",
			func() *http.Request {
				req := authRequest(t, authTestPSK)
				req.Header.Del(authTestNamer(authTestPSK).name(slotAuthMAC))
				return req
			}(),
			http.StatusProxyAuthRequired,
		},
		// A v2 client may not keep replayable credentials: this is what makes
		// min_proto_version=2 a real switch instead of a label. Strict mode
		// has no bare-token path at all, so the token does not rescue an
		// unsigned request.
		{
			"v2 advertising a bare token rejected",
			func() *http.Request {
				req := authRequest(t, authTestPSK)
				n := authTestNamer(authTestPSK)
				req.Header.Del(n.name(slotAuthMAC))
				req.Header.Del(n.name(slotAuthNonce))
				req.Header.Set("X-Auth-Token", authTestPSK)
				return req
			}(),
			http.StatusProxyAuthRequired,
		},
		{
			"constant-name request with a bad signature still rejected",
			constantNameRequest(t, map[string]string{
				ProtoHeader:    "1",
				"X-Auth-Token": authTestPSK,
				AuthMACHeader:  "deadbeef",
			}),
			http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authTestStatus(t, base, tc.req); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestStrictModeRefusesConstantNames pins the cutover itself: whatever the
// credential, a request written under the constant names is not a request
// this build speaks. With the salt it fails authentication (the names do not
// resolve to a signature); without it, it never gets that far.
func TestStrictModeRefusesConstantNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	// Constant names carrying a valid signature minted the old way: the salt
	// is present, so the request reaches authentication — where the derived
	// names the server reads find no signature at all.
	req := constantNameRequest(t, map[string]string{"X-Auth-Token": authTestPSK})
	q := req.URL.Query()
	q.Set(saltParam, authTestSession)
	req.URL.RawQuery = q.Encode()
	if got := authTestStatus(t, base, req); got != http.StatusProxyAuthRequired {
		t.Fatalf("constant names with a salt: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}

	// Derived names without the salt: the session id cannot be recovered, and
	// the request is refused before authentication is attempted.
	req = authRequest(t, authTestPSK)
	req.URL.RawQuery = ""
	if got := authTestStatus(t, base, req); got != http.StatusBadRequest {
		t.Fatalf("derived names without a salt: status = %d, want %d", got, http.StatusBadRequest)
	}
}

func TestServerReplayRejectedEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	req := authRequest(t, authTestPSK)
	if got := authTestStatus(t, base, req); got != http.StatusForbidden {
		t.Fatalf("original request: status = %d, want %d (auth passes)", got, http.StatusForbidden)
	}
	if got := authTestStatus(t, base, req); got != http.StatusProxyAuthRequired {
		t.Fatalf("replayed request: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	if got := authTestStatus(t, base, req); got != http.StatusProxyAuthRequired {
		t.Fatalf("third replay: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	// A freshly signed request still works, so the rejection is about the
	// nonce and not a tripwire on the whole server.
	if got := authTestStatus(t, base, authRequest(t, authTestPSK)); got != http.StatusForbidden {
		t.Fatalf("fresh request after replay: status = %d, want %d", got, http.StatusForbidden)
	}
}

func TestServerRejectsResignedAndRetargeted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	req := authRequest(t, authTestPSK)
	if got := authTestStatus(t, base, req); got != http.StatusForbidden {
		t.Fatalf("original: status = %d, want %d", got, http.StatusForbidden)
	}

	// Aim the same signature at an address the sender also has access to. The
	// target is bound into the digest, so this must not authenticate.
	n := authTestNamer(authTestPSK)
	retargeted := authRequest(t, authTestPSK)
	retargeted.Header.Set(n.name(slotTarget), "127.0.0.1:80")
	retargeted.Header.Set(n.name(slotAuthNonce), req.Header.Get(n.name(slotAuthNonce)))
	retargeted.Header.Set(n.name(slotAuthMAC), req.Header.Get(n.name(slotAuthMAC)))
	if got := authTestStatus(t, base, retargeted); got != http.StatusProxyAuthRequired {
		t.Fatalf("retargeted request: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}

	// The same signature presented for a different session id. In derived
	// mode the session id is the salt, so this also derives different header
	// names — the request arrives as an unsigned one under names the server
	// generates from the new salt.
	resession := authRequest(t, authTestPSK)
	q := resession.URL.Query()
	q.Set(saltParam, "someone-elses-session")
	resession.URL.RawQuery = q.Encode()
	if got := authTestStatus(t, base, resession); got != http.StatusProxyAuthRequired {
		t.Fatalf("re-sessoned request: status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
}

func TestServerRejectsMalformedSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{})

	n := authTestNamer(authTestPSK)
	cases := map[string]func() *http.Request{
		"no nonce": func() *http.Request {
			req := authRequest(t, authTestPSK)
			req.Header.Del(n.name(slotAuthNonce))
			return req
		},
		"non-hex nonce": func() *http.Request {
			req := authRequest(t, authTestPSK)
			req.Header.Set(n.name(slotAuthNonce), "not-a-nonce")
			return req
		},
		"short nonce": func() *http.Request {
			req := authRequest(t, authTestPSK)
			req.Header.Set(n.name(slotAuthNonce), "0123456789abcdef")
			return req
		},
		"no MAC": func() *http.Request {
			req := authRequest(t, authTestPSK)
			req.Header.Del(n.name(slotAuthMAC))
			return req
		},
		"garbled MAC": func() *http.Request {
			req := authRequest(t, authTestPSK)
			mac := req.Header.Get(n.name(slotAuthMAC))
			req.Header.Set(n.name(slotAuthMAC), "zz"+mac[2:])
			return req
		},
		"truncated MAC": func() *http.Request {
			req := authRequest(t, authTestPSK)
			mac := req.Header.Get(n.name(slotAuthMAC))
			req.Header.Set(n.name(slotAuthMAC), mac[:63])
			return req
		},
	}
	for name, build := range cases {
		if got := authTestStatus(t, base, build()); got != http.StatusProxyAuthRequired {
			t.Errorf("%s: status = %d, want %d", name, got, http.StatusProxyAuthRequired)
		}
	}
}

func TestServerMinProtoTwoClosesLegacy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{MinProtoVersion: 2})

	// A constant-name request is refused at the salt gate, before the version
	// gate ever sees it: that is what "legacy closed" means under strict mode.
	if got := authTestStatus(t, base, constantNameRequest(t, map[string]string{
		"X-Auth-Token": authTestPSK,
	})); got != http.StatusBadRequest {
		t.Fatalf("constant-name client: status = %d, want %d", got, http.StatusBadRequest)
	}
	// A signed client satisfies the version gate.
	if got := authTestStatus(t, base, authRequest(t, authTestPSK)); got != http.StatusForbidden {
		t.Fatalf("signed client: status = %d, want %d", got, http.StatusForbidden)
	}
}

func TestMinProtoTwoIsEnforcedAfterLegacyIsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := authTestServer(t, ctx, ServerConfig{MinProtoVersion: 2})

	// The only way past the salt gate is a derived-name request, and the only
	// way past authentication is a v2+ signature. Together those two rules
	// close the bare-token path entirely: a token rides along on a request
	// that signs, or the request does not get in.
	req := authRequest(t, authTestPSK)
	n := authTestNamer(authTestPSK)
	req.Header.Del(n.name(slotAuthMAC))
	req.Header.Del(n.name(slotAuthNonce))
	req.Header.Set("X-Auth-Token", authTestPSK)
	if got := authTestStatus(t, base, req); got != http.StatusProxyAuthRequired {
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
	scrubTunnelRequest(req, "")

	for _, h := range []string{AuthNonceHeader, AuthMACHeader, "X-Auth-Token"} {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("%s survived the scrub: %q", h, v)
		}
	}
}
