package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestXHTTPTunnel_E2E_ThroughCDN exercises the complete client -> CDN ->
// origin path.  In particular it verifies the headers that keep a CDN from
// caching/buffering a split-HTTP stream, and that a short-lived CDN/WAF error
// does not lose a queued tunnel payload.
func TestXHTTPTunnel_E2E_ThroughCDN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "cdn-test-secret", "", "", "")
	if err != nil {
		t.Fatalf("start origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	// The fake CDN injects two long-poll timeouts and then rejects an upload.
	// 524 is Cloudflare's non-standard timeout status. The rejected POST must
	// be rewound to the server ACK and replayed with X-Retry, or the payload
	// would be silently skipped.
	cdn := newCDNTestServer(t, "http://"+origin.Addr().String(), []cdnFault{
		{phase: cdnPhasePoll, status: http.StatusGatewayTimeout},
		{phase: cdnPhasePoll, status: 524},
		{phase: cdnPhaseUpload, status: http.StatusTooManyRequests},
	})
	defer cdn.Close()
	cdn.setPhase(cdnPhaseSetup)
	// The fixture holds the session key so it can tell a request that moves
	// the stream from one that does not. It is the only way left to tell, and
	// a test is entitled to know; an observer is not.
	cdn.psk = "cdn-test-secret"

	cdnURL, err := url.Parse(cdn.server.URL + "/stream")
	if err != nil {
		t.Fatalf("parse CDN URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, cdnURL, &DialConfig{
		Password:   "cdn-test-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll", // this test targets poll resilience; stream probe would eat the injected faults
		// A client normally presents the public CDN hostname rather than the
		// origin address. The simulator records this value before proxying.
		Host: "cdn.example.test",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial through CDN: %v", err)
	}
	defer conn.Close()
	// The session is up: from here every request is a long poll, and the two
	// edge timeouts are aimed at one.
	cdn.setPhase(cdnPhasePoll)
	cdn.waitForPollFaults(t)

	payload := bytes.Repeat([]byte("cdn-path-payload-"), 16*1024)
	// The upload begins: the edge can now tell a request that moves the
	// stream from one that does not, so the rate limit lands on a request
	// carrying data rather than on an idle poll that happens to be in flight.
	cdn.setPhase(cdnPhaseUpload)
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()

	got, err := readFullBefore(conn, len(payload), 20*time.Second)
	if err != nil {
		t.Logf("CDN request trace at timeout: %s", cdn.trace())
		t.Fatalf("read echo through CDN: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write through CDN: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed while recovering from CDN responses")
	}

	cdn.assert(t)
}

// TestXHTTPTunnel_E2E_ThroughCDNWithLatency verifies that ordinary edge
// latency does not affect sequence reconstruction. The delay is injected at
// the CDN boundary for every request, including the two independent split
// HTTP directions.
func TestXHTTPTunnel_E2E_ThroughCDNWithLatency(t *testing.T) {
	const edgeDelay = 35 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "latency-test-secret", "", "", "")
	if err != nil {
		t.Fatalf("start origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	cdn := newCDNTestServer(t, "http://"+origin.Addr().String(), nil, edgeDelay)
	defer cdn.Close()
	cdnURL, err := url.Parse(cdn.server.URL + "/stream")
	if err != nil {
		t.Fatalf("parse CDN URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, cdnURL, &DialConfig{
		Password:   "latency-test-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll", // measures long-poll latency behaviour specifically
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial delayed CDN: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("latency-safe-payload-"), 24*1024)
	started := time.Now()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through delayed CDN: %v", err)
	}
	got, err := readFullBefore(conn, len(payload), 15*time.Second)
	if err != nil {
		t.Fatalf("read through delayed CDN: %v; %s", err, cdn.trace())
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed while traversing delayed CDN")
	}
	if elapsed := time.Since(started); elapsed < edgeDelay {
		t.Fatalf("tunnel completed in %s despite a %s edge delay", elapsed, edgeDelay)
	}
	cdn.assertDelayApplied(t, 2)
}

// startTCPEchoServer starts a deliberately plain TCP target. It makes this
// test about the HTTP/CDN leg only, while still proving that the tunnel keeps
// its byte stream intact end to end.
func startTCPEchoServer(t testing.TB) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveAcceptedTCPEcho(t testing.TB, ctx context.Context, listener *XHTTPListener) {
	t.Helper()
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				xconn, ok := conn.(*XHTTPConn)
				if !ok {
					t.Errorf("accepted unexpected connection type %T", conn)
					return
				}
				target, err := net.Dial("tcp", xconn.TargetAddr())
				if err != nil {
					t.Errorf("dial echo target %q: %v", xconn.TargetAddr(), err)
					return
				}
				defer target.Close()
				go func() { _, _ = io.Copy(target, xconn) }()
				_, _ = io.Copy(xconn, target)
			}(conn)
		}
	}()
}

// cdnTestServer is a small reverse proxy with enough behaviour to simulate
// the parts of a CDN that matter to the tunnel. It observes both sides of the
// proxy, injects a finite list of transient edge responses, and adds the
// client-IP headers that a real CDN sends to the origin.
type cdnTestServer struct {
	server *httptest.Server
	proxy  *httputil.ReverseProxy

	mu    sync.Mutex
	phase string
	// psk lets the fixture read the uplink sequence in the clear. The wire
	// form is masked per request, which is the point: two requests carrying
	// the same position do not look alike, and a hop is not meant to be able
	// to tell whether a request advanced the stream. The test holds the key.
	psk                string
	lastSeq            uint64
	seenRequestSeq     []uint64
	pendingFaults      []cdnFault
	injectedStatuses   []int
	seenRequestHeaders []http.Header
	seenRequestHost    []string
	seenRequestMethod  []string
	seenRequestLength  []int64
	seenRequestInfo    []string
	seenResponseHeader []http.Header
	seenResponseInfo   []string
	delay              time.Duration
	jitter             time.Duration // max random variance added to delay (0 = none)
	lossRate           float64       // probability of returning 504 per request (0 = none)
	delayedRequests    int

	pollFaultsReady     chan struct{}
	pollFaultsReadyOnce sync.Once
	rejectedPostIndex   int
	rejectedPostSeq     uint64
}

// The phases of a session the CDN can be told to break. Every request in a
// session is a POST now, and it is not only the method that is the same: a
// padded poll body and a padded upload are the same size, on purpose, so
// there is nothing on the wire left to tell them apart. The fixture is
// therefore told which phase it is in, which is the thing an observer cannot
// know and a test is entitled to say.
const (
	// cdnPhaseSetup is the dial. Nothing is refused while the session is
	// still being established.
	cdnPhaseSetup = "setup"
	// cdnPhasePoll is the idle phase, where every request carries nothing.
	cdnPhasePoll = "poll"
	// cdnPhaseUpload is the phase in which the client has a payload to send.
	cdnPhaseUpload = "upload"
)

type cdnFault struct {
	phase  string
	status int
}

func newCDNTestServer(t testing.TB, origin string, faults []cdnFault, delays ...time.Duration) *cdnTestServer {
	t.Helper()
	originURL, err := url.Parse(origin)
	if err != nil {
		t.Fatalf("parse origin URL: %v", err)
	}

	cdn := &cdnTestServer{
		pendingFaults:     append([]cdnFault(nil), faults...),
		pollFaultsReady:   make(chan struct{}),
		rejectedPostIndex: -1,
	}
	if len(delays) > 0 {
		cdn.delay = delays[0]
	}
	proxy := httputil.NewSingleHostReverseProxy(originURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Closing the virtual connection cancels any in-flight long poll. That
		// is normal test teardown, not a failed origin request.
		if errors.Is(err, context.Canceled) {
			return
		}
		t.Errorf("CDN proxy request failed: %v", err)
		http.Error(w, "CDN origin unavailable", http.StatusBadGateway)
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// A CDN must use the origin Host while the client-facing Host remains
		// observable above, before it enters the reverse proxy.
		req.Host = originURL.Host
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		cdn.mu.Lock()
		cdn.seenResponseHeader = append(cdn.seenResponseHeader, resp.Header.Clone())
		cdn.seenResponseInfo = append(cdn.seenResponseInfo, fmt.Sprintf("%d seq=%s ack=%s len=%s", resp.StatusCode, resp.Header.Get("X-Seq"), resp.Header.Get("X-Ack"), resp.Header.Get("Content-Length")))
		cdn.mu.Unlock()
		return nil
	}
	cdn.proxy = proxy
	cdn.server = httptest.NewServer(http.HandlerFunc(cdn.serveHTTP))
	return cdn
}

// setPhase tells the fixture which part of the session it is breaking. It
// starts in the setup phase so the dial is never the thing that fails.
func (c *cdnTestServer) setPhase(phase string) {
	c.mu.Lock()
	c.phase = phase
	c.mu.Unlock()
}

// plainUplinkSeq recovers the uplink position this request reports, in the
// clear. The wire form is masked with a per-request keystream, so a request
// that carries the same bytes as the one before it does not look like it:
// that is what takes the sequence numbers out of the observer's hands, and
// it is why this fixture has to hold the key to see them.
func (c *cdnTestServer) plainUplinkSeq(h http.Header) uint64 {
	nonce, wire := h.Get(AuthNonceHeader), h.Get("X-Seq")
	if nonce == "" || wire == "" || c.psk == "" {
		return 0
	}
	seq, _, _, err := decodeCounters(maskFor(reqMaskDomain, c.psk, nonce), counters{seq: wire})
	if err != nil {
		return 0
	}
	return seq
}

func (c *cdnTestServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.seenRequestHeaders = append(c.seenRequestHeaders, r.Header.Clone())
	c.seenRequestHost = append(c.seenRequestHost, r.Host)
	c.seenRequestMethod = append(c.seenRequestMethod, r.Method)
	c.seenRequestLength = append(c.seenRequestLength, r.ContentLength)
	c.seenRequestInfo = append(c.seenRequestInfo, fmt.Sprintf("%s seq=%s ack=%s len=%d", r.Method, r.Header.Get("X-Seq"), r.Header.Get("X-Ack"), r.ContentLength))
	seq := c.plainUplinkSeq(r.Header)
	c.seenRequestSeq = append(c.seenRequestSeq, seq)
	// An upload is a request that reports further along the stream than the
	// one before it. An idle poll sits still. That is the only difference
	// left between them, and it is invisible without the key.
	advanced := seq != c.lastSeq
	c.lastSeq = seq

	var injected *cdnFault
	if len(c.pendingFaults) > 0 && c.pendingFaults[0].phase == c.phase &&
		(c.pendingFaults[0].phase != cdnPhaseUpload || advanced) {
		fault := c.pendingFaults[0]
		c.pendingFaults = c.pendingFaults[1:]
		c.injectedStatuses = append(c.injectedStatuses, fault.status)
		if fault.phase == cdnPhaseUpload {
			c.rejectedPostIndex = len(c.seenRequestMethod) - 1
			c.rejectedPostSeq = seq
		}
		if len(c.pendingFaults) == 0 || c.pendingFaults[0].phase != cdnPhasePoll {
			c.pollFaultsReadyOnce.Do(func() { close(c.pollFaultsReady) })
		}
		injected = &fault
	}
	delay := c.delay
	if delay > 0 {
		c.delayedRequests++
	}
	if c.jitter > 0 {
		delay += time.Duration(mrand.Int63n(int64(c.jitter)))
	}
	loss := c.lossRate
	c.mu.Unlock()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}
	if loss > 0 && mrand.Float64() < loss {
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
		return
	}
	if injected != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(injected.status)
		_, _ = fmt.Fprintf(w, "simulated CDN status %d", injected.status)
		return
	}

	// Model the headers added by Cloudflare/reverse proxies after a request
	// has reached the edge. They are passed only to the origin, never trusted
	// from the caller in this test.
	r.Header.Set("CF-Connecting-IP", "198.51.100.24")
	r.Header.Set("X-Real-IP", "198.51.100.24")
	r.Header.Set("X-Forwarded-For", "198.51.100.24")
	c.proxy.ServeHTTP(w, r)
}

func (c *cdnTestServer) Close() { c.server.Close() }

func (c *cdnTestServer) assertDelayApplied(t testing.TB, minRequests int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delay == 0 || c.delayedRequests < minRequests {
		t.Fatalf("CDN delay was applied to %d requests, want at least %d", c.delayedRequests, minRequests)
	}
}

func (c *cdnTestServer) waitForPollFaults(t *testing.T) {
	t.Helper()
	select {
	case <-c.pollFaultsReady:
	case <-time.After(5 * time.Second):
		t.Fatalf("CDN did not inject initial long-poll failures: %s", c.trace())
	}
}

func (c *cdnTestServer) trace() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	const keep = 8
	requests := c.seenRequestInfo
	responses := c.seenResponseInfo
	if len(requests) > keep {
		requests = requests[len(requests)-keep:]
	}
	if len(responses) > keep {
		responses = responses[len(responses)-keep:]
	}
	return fmt.Sprintf("requestCount=%d lastRequests=%v injected=%v responseCount=%d lastOriginResponses=%v", len(c.seenRequestInfo), requests, c.injectedStatuses, len(c.seenResponseInfo), responses)
}

// readFullBefore gives this concurrent end-to-end test a real deadline.
// This also covers generic io.Reader fixtures that do not expose net.Conn
// deadlines, and gives the test a bound independent of transport teardown.
func readFullBefore(r io.Reader, length int, timeout time.Duration) ([]byte, error) {
	result := make(chan error, 1)
	data := make([]byte, length)
	go func() {
		_, err := io.ReadFull(r, data)
		result <- err
	}()
	select {
	case err := <-result:
		return data, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out after %s", timeout)
	}
}

func (c *cdnTestServer) assert(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	wantStatuses := []int{http.StatusGatewayTimeout, 524, http.StatusTooManyRequests}
	if !sameInts(c.injectedStatuses, wantStatuses) {
		t.Fatalf("transient CDN responses = %v, want %v", c.injectedStatuses, wantStatuses)
	}
	if !containsString(c.seenRequestMethod, http.MethodPost) {
		t.Fatal("CDN did not receive the tunnel upload")
	}
	if len(c.seenRequestHeaders) == 0 {
		t.Fatal("CDN received no tunnel requests")
	}
	if !containsString(c.seenRequestHost, "cdn.example.test") {
		t.Fatalf("CDN did not receive configured public Host; got %v", c.seenRequestHost)
	}

	var sawNoStore, sawPragma, sawIdentity, sawEndToEndAuth bool
	for _, h := range c.seenRequestHeaders {
		cacheControl := h.Get("Cache-Control")
		if strings.Contains(cacheControl, "no-store") && strings.Contains(cacheControl, "no-cache") {
			sawNoStore = true
		}
		if h.Get("Pragma") == "no-cache" {
			sawPragma = true
		}
		if h.Get("Accept-Encoding") == "identity" {
			sawIdentity = true
		}
		// The credential must survive the CDN. Proxy-Authorization is hop-by-hop
		// and gets stripped at the edge, so the signed scheme carries its
		// evidence in two end-to-end headers instead. Both are required: a MAC
		// without a nonce is unverifiable, and a nonce without a MAC is not a
		// credential at all.
		nonce := h.Get(AuthNonceHeader)
		mac := h.Get(AuthMACHeader)
		if validAuthNonce(nonce) && validHex(mac, sha256.Size) {
			sawEndToEndAuth = true
		}
	}
	if !sawNoStore || !sawPragma || !sawIdentity || !sawEndToEndAuth {
		t.Fatalf("client CDN-bypass headers incomplete: no-store=%t pragma=%t identity=%t end-to-end-auth=%t", sawNoStore, sawPragma, sawIdentity, sawEndToEndAuth)
	}

	// The replay is recognised by the position it carries, not by the bytes:
	// it is the same position in the stream, while its pad is a fresh draw
	// and its counters a fresh mask. The wire forms of two requests at the
	// same position share nothing an observer could match on, which is why
	// the fixture needs the key to see the correspondence at all.
	var sawReplayedPOST bool
	for i := c.rejectedPostIndex + 1; i < len(c.seenRequestHeaders); i++ {
		if c.seenRequestMethod[i] == http.MethodPost && c.seenRequestSeq[i] == c.rejectedPostSeq {
			sawReplayedPOST = true
			break
		}
	}
	if c.rejectedPostIndex < 0 || !sawReplayedPOST {
		t.Fatalf("CDN-rejected POST was not replayed from sequence %d", c.rejectedPostSeq)
	}

	if len(c.seenResponseHeader) == 0 {
		t.Fatal("CDN never received an origin response")
	}
	var sawOriginNoStore, sawAccelOff, sawSequenceHeaders bool
	for _, h := range c.seenResponseHeader {
		cacheControl := h.Get("Cache-Control")
		if strings.Contains(cacheControl, "no-store") && strings.Contains(cacheControl, "no-transform") {
			sawOriginNoStore = true
		}
		if h.Get("X-Accel-Buffering") == "no" {
			sawAccelOff = true
		}
		if h.Get("X-Seq") != "" && h.Get("X-Ack") != "" {
			sawSequenceHeaders = true
		}
	}
	if !sawOriginNoStore || !sawAccelOff || !sawSequenceHeaders {
		t.Fatalf("origin CDN response headers incomplete: no-store=%t accel-off=%t seq/ack=%t", sawOriginNoStore, sawAccelOff, sawSequenceHeaders)
	}
}

func sameInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
