package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// streamVerdict snapshots the cached verdict for one endpoint key.
func streamVerdict(key string) (mode string, failures int) {
	streamModeMu.Lock()
	defer streamModeMu.Unlock()
	e := streamModeCache[key]
	return e.mode, e.failures
}

// resetStreamVerdicts clears the package-level negotiation cache. Tests share
// it, and a leftover "poll" verdict would silently change what a later test
// negotiates.
func resetStreamVerdicts() {
	streamModeMu.Lock()
	streamModeCache = map[string]streamModeEntry{}
	streamModeMu.Unlock()
	streamProbeGatesMu.Lock()
	streamProbeGates = map[string]*streamProbeGate{}
	streamProbeGatesMu.Unlock()
}

// TestStreamPollVerdictNeedsTwoConsecutiveFailures pins the downgrade policy: a
// single failed negotiation must not pin the endpoint to polling for the whole
// TTL, because one probe can be tripped by a transient edge state. A successful
// negotiation in between resets the counter.
func TestStreamPollVerdictNeedsTwoConsecutiveFailures(t *testing.T) {
	resetStreamVerdicts()
	defer resetStreamVerdicts()
	lg := zap.NewNop()
	const key = "h1|example:443|sni|fp|tk"

	recordStreamPollVerdict(key, "first", lg)
	if mode, failures := streamVerdict(key); mode != "" || failures != 1 {
		t.Fatalf("after one failure: mode=%q failures=%d, want \"\"/1", mode, failures)
	}
	if _, ttfb := cachedStreamMode(key); ttfb != 0 {
		t.Fatalf("an accumulating verdict must not publish a TTFB baseline, got %v", ttfb)
	}

	// A success in between breaks the streak.
	cacheStreamMode(key, "stream", 12*time.Millisecond)
	recordStreamPollVerdict(key, "after success", lg)
	if mode, failures := streamVerdict(key); mode != "" || failures != 1 {
		t.Fatalf("after success + failure: mode=%q failures=%d, want \"\"/1", mode, failures)
	}

	// Second consecutive failure is what downgrades.
	recordStreamPollVerdict(key, "second", lg)
	if mode, failures := streamVerdict(key); mode != "poll" || failures < 2 {
		t.Fatalf("after two consecutive failures: mode=%q failures=%d, want poll", mode, failures)
	}
	if cfg := (&DialConfig{}); cfg.streamDownlinkEnabled(key) {
		t.Fatal("a poll verdict must disable the stream attempt for the next session")
	}
}

// stalledStreamWriter is an http.ResponseWriter whose second Write blocks, which
// parks a streaming downlink handler while it still owns the dispatch cursor
// (its first Write is the hello frame).
type stalledStreamWriter struct {
	mu      sync.Mutex
	header  http.Header
	body    bytes.Buffer
	writes  int
	helloCh chan struct{}
	block   chan struct{}
}

func newStalledStreamWriter() *stalledStreamWriter {
	return &stalledStreamWriter{
		header:  make(http.Header),
		helloCh: make(chan struct{}),
		block:   make(chan struct{}),
	}
}

func (w *stalledStreamWriter) Header() http.Header { return w.header }

func (w *stalledStreamWriter) WriteHeader(int) {}

func (w *stalledStreamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.body.Write(p)
	w.writes++
	n := w.writes
	w.mu.Unlock()
	if n == 1 {
		close(w.helloCh)
		return len(p), nil
	}
	<-w.block
	return len(p), nil
}

func (w *stalledStreamWriter) Flush() error { return nil }

// ResponseController looks for FlushError before falling back to http.Flusher;
// without it the flush is reported unsupported and the handler gives up before
// the hello frame.
func (w *stalledStreamWriter) FlushError() error { return nil }

func (w *stalledStreamWriter) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.body.Bytes()...)
}

func (w *stalledStreamWriter) writeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

// TestPollGetTakesOverFromStalledStreamWriter proves the mode-downgrade
// takeover: while a streaming handler is stalled mid-write (a buffering
// intermediary looks exactly like this), a poll GET on the same session must
// take the dispatch cursor and serve the buffered downlink bytes instead of
// answering an immediate empty 200 — which would turn the fallback into a
// request storm that never receives data.
func TestPollGetTakesOverFromStalledStreamWriter(t *testing.T) {
	resetStreamVerdicts()
	defer resetStreamVerdicts()

	st := newServerState(8)
	st.customLog = zap.NewNop()
	xl := &XHTTPListener{connCh: make(chan *XHTTPConn, 8), expectedToken: "pw"}
	handler := buildSessionHandler(xl, st, "/stream", "pw", "")

	const sessionID = "stalled-session"
	vConn := newMeekVirtualConn(sessionID, nil, nil, zap.NewNop())
	vConn.writeBuf = newReliableBuffer(defaultWindowBytes)
	defer vConn.Close()
	st.sessionsMu.Lock()
	st.sessions[sessionID] = vConn
	st.sessionsMu.Unlock()

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/stream", nil)
		r.Header.Set("X-Session-ID", sessionID)
		r.Header.Set("X-Target", "127.0.0.1:22")
		r.Header.Set("X-Network", "tcp")
		r.Header.Set("X-Auth-Token", "pw")
		r.Header.Set("X-Seq", "0")
		r.Header.Set("X-Ack", "0")
		return r
	}

	streamReq := newReq()
	streamReq.Header.Set("X-Downstream", "1")
	bw := newStalledStreamWriter()
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		handler.ServeHTTP(bw, streamReq)
	}()
	select {
	case <-bw.helloCh:
	case <-time.After(2 * time.Second):
		t.Fatal("the streaming handler never sent its hello frame")
	}

	payload := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	if _, err := vConn.writeBuf.Write(payload); err != nil {
		t.Fatalf("buffer the target's first bytes: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for bw.writeCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if bw.writeCount() < 2 {
		t.Fatal("the streaming handler never picked up the buffered bytes")
	}
	if !vConn.downWriterActive() {
		t.Fatal("the stalled stream should still own the dispatch cursor")
	}

	rec := httptest.NewRecorder()
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		handler.ServeHTTP(rec, newReq())
	}()
	select {
	case <-pollDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the poll GET neither took over nor answered")
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("poll GET body = %q, want the buffered downlink bytes %q (empty means the stale writer kept the cursor)", got, payload)
	}

	// The takeover evicted the stalled stream, so its response ends on its own.
	close(bw.block)
	select {
	case <-streamDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the evicted streaming handler did not return")
	}
}

// stripDownstreamProxy fronts an origin and drops the X-Downstream capability
// header, which is what a CDN that does not forward unknown headers does. The
// origin then answers the probe as an ordinary long poll.
func stripDownstreamProxy(t *testing.T, origin *url.URL) (*httptest.Server, *int32) {
	t.Helper()
	var probed int32
	rp := httputil.NewSingleHostReverseProxy(origin)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Downstream") == "1" {
			atomic.AddInt32(&probed, 1)
			r.Header.Del("X-Downstream")
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &probed
}

// bannerTarget accepts connections and speaks first, the way an SSH server does.
func bannerTarget(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

// TestStreamFallbackDoesNotLoseFirstDownlinkBytes drives the negotiation against
// an origin the client cannot stream from, where the target speaks before the
// dial returns. The discarded probe response carries those first bytes, and the
// poll fallback must still deliver them — which it does by rewinding the
// dispatch cursor to the peer's acknowledgement when it takes the cursor over.
//
// It also pins the downgrade escalation: one failed negotiation keeps the
// verdict open, the second records poll, and the third dial skips the probe
// entirely.
func TestStreamFallbackDoesNotLoseFirstDownlinkBytes(t *testing.T) {
	resetStreamVerdicts()
	defer resetStreamVerdicts()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	target := bannerTarget(t)
	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pw", "", "", "")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	originURL, _ := url.Parse("http://" + origin.Addr().String())
	front, probed := stripDownstreamProxy(t, originURL)
	serverURL, _ := url.Parse(front.URL + "/stream")

	cfg := &DialConfig{Password: "pw", Path: "/stream", ALPN: "h1"}
	// The client dials the proxy, so the endpoint key carries the proxy's address.
	key := cfg.streamModeKey("http/1.1", serverURL.Host)

	dialAndRead := func(nth int) {
		t.Helper()
		dialCfg := &DialConfig{Password: "pw", Path: "/stream", ALPN: "h1"}
		conn, err := DialXHTTP(ctx, serverURL, dialCfg, target.Addr().String(), "tcp")
		if err != nil {
			t.Fatalf("dial %d: %v", nth, err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 20)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("dial %d: the first downlink bytes were lost by the probe: %v", nth, err)
		}
		if !bytes.HasPrefix(got, []byte("SSH-2.0-")) {
			t.Fatalf("dial %d: first bytes = %q", nth, got)
		}
	}

	dialAndRead(1)
	if mode, failures := streamVerdict(key); mode != "" || failures != 1 {
		t.Fatalf("after the first failed negotiation: mode=%q failures=%d, want \"\"/1 (one sample must not downgrade)", mode, failures)
	}
	if got := atomic.LoadInt32(probed); got != 1 {
		t.Fatalf("probe GETs = %d, want 1", got)
	}

	dialAndRead(2)
	if mode, _ := streamVerdict(key); mode != "poll" {
		t.Fatalf("after the second failed negotiation: mode=%q, want poll", mode)
	}
	if got := atomic.LoadInt32(probed); got != 2 {
		t.Fatalf("probe GETs = %d, want 2", got)
	}

	// The cached verdict now short-circuits the negotiation: no probe at all.
	dialAndRead(3)
	if got := atomic.LoadInt32(probed); got != 2 {
		t.Fatalf("probe GETs = %d after the cached verdict, want 2", got)
	}
}

// TestRefusedTargetIsNotAPathVerdict pins the classification of a session the
// origin ends before the first byte (a refused target, a reaped session). It is
// not a statement about the path, so it must fail the dial with the real reason
// and leave the negotiation cache untouched — otherwise a user whose target is
// down would downgrade a perfectly streamable endpoint for the whole TTL.
func TestRefusedTargetIsNotAPathVerdict(t *testing.T) {
	resetStreamVerdicts()
	defer resetStreamVerdicts()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A port nobody listens on, while the tunnel origin itself is healthy.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pw", "", "", "")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept(ctx)
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				xconn, ok := conn.(*XHTTPConn)
				if !ok {
					return
				}
				target, err := net.Dial("tcp", xconn.TargetAddr())
				if err != nil {
					return // the refusal the test is about
				}
				defer target.Close()
				go func() { _, _ = io.Copy(target, xconn) }()
				_, _ = io.Copy(xconn, target)
			}(conn)
		}
	}()

	serverURL, _ := url.Parse("http://" + origin.Addr().String() + "/stream")
	_, derr := DialXHTTP(ctx, serverURL, &DialConfig{Password: "pw", Path: "/stream", ALPN: "h1"}, deadAddr, "tcp")
	if derr == nil {
		t.Fatal("dialing a refused target must fail, not hand back a dead connection")
	}
	if !strings.Contains(derr.Error(), "closed the session before any data") {
		t.Fatalf("dial error = %v, want the refusal named", derr)
	}
	key := (&DialConfig{Path: "/stream"}).streamModeKey("http/1.1", origin.Addr().String())
	if mode, failures := streamVerdict(key); mode != "" || failures != 0 {
		t.Fatalf("a refused target was recorded as a path verdict: mode=%q failures=%d", mode, failures)
	}
}

// TestStreamProbeInconclusiveDoesNotDowngrade covers the slow-connection case: a
// cold TCP/TLS handshake on a bad link can eat the probe window without saying
// anything about whether the path streams. The session falls back to polling,
// but no verdict is recorded, so the next dial — on the now-warm transport —
// still negotiates streaming.
func TestStreamProbeInconclusiveDoesNotDowngrade(t *testing.T) {
	resetStreamVerdicts()
	defer resetStreamVerdicts()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pw", "", "", "")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	serverURL, _ := url.Parse("http://" + origin.Addr().String() + "/stream")
	key := (&DialConfig{Path: "/stream"}).streamModeKey("http/1.1", origin.Addr().String())

	var dialed int32
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	slowFirstDial := func(c context.Context, network, addr string) (net.Conn, error) {
		if atomic.AddInt32(&dialed, 1) == 1 {
			select {
			case <-time.After(streamProbeMinWindow + 200*time.Millisecond):
			case <-c.Done():
				return nil, c.Err()
			}
		}
		return dialer.DialContext(c, network, addr)
	}

	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password: "pw", Path: "/stream", ALPN: "h1", DialContext: slowFirstDial,
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial with a slow first connection: %v", err)
	}
	defer conn.Close()
	if mode, failures := streamVerdict(key); mode == "poll" || failures != 0 {
		t.Fatalf("a slow connect was recorded as a path verdict: mode=%q failures=%d", mode, failures)
	}

	// The transport is warm now: the next session must negotiate streaming.
	conn2, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password: "pw", Path: "/stream", ALPN: "h1", DialContext: slowFirstDial,
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn2.Close()
	if mode, _ := streamVerdict(key); mode != "stream" {
		t.Fatalf("second dial verdict = %q, want stream (an inconclusive probe must not poison the endpoint)", mode)
	}
}
