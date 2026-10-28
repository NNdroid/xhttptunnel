package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Tunables of the stream-mode downlink. The negotiation, keepalive and
// watchdog intervals must satisfy: keepalive < smallest intermediary idle
// timeout < watchdog.
const (
	// streamProbeMinWindow bounds how long the client waits for the hello
	// frame when deciding whether the path streams, and how long the server
	// waits for the companion POST before concluding the path cannot stream.
	// Both sides share this constant: the client measures from when it sends
	// the GET, the server from when the GET arrives, so a round trip longer
	// than half this window fails the first probe and falls back to polling.
	// Once a prior probe has succeeded the client widens to max(this,
	// 3x the measured TTFB).
	streamProbeMinWindow = 5 * time.Second
	// streamWatchdogTimeout is the no-frame stall threshold for an
	// established stream; the server keepalives every 5s so a healthy path
	// never trips it. 30s = 6× keepalive, leaving headroom for a slow
	// RTT while bounding silent-drop recovery well under the previous 75s.
	streamWatchdogTimeout = 30 * time.Second
	// streamUplinkKeepalive is how often an idle uplink writes an ack-only
	// frame so the server's downlink buffer keeps freeing.
	streamUplinkKeepalive = 25 * time.Second
	// streamModeCacheTTL is how long a negotiated decision stays cached per
	// endpoint before the next session re-probes.
	streamModeCacheTTL = 5 * time.Minute
	// streamCloseGrace bounds how long Close waits for the uplink to ship its
	// close marker before the pump is cancelled outright.
	streamCloseGrace = 2 * time.Second
	// streamRoundTeardown bounds the graceful phase of unwinding one stream
	// round before the downlink body is force-closed.
	streamRoundTeardown = 500 * time.Millisecond
	// ackCoalesceBytes is how much downlink progress accumulates before the
	// downlink reader ships an ack-only frame on the uplink pipe. The server
	// frees its write buffer from these acks — without prompt acks a pure
	// download stalls in 4MB bursts every keepalive tick (~1/10 of the
	// achievable rate).
	ackCoalesceBytes = 32 * 1024
	// reconnectBackoffCap bounds the reconnect backoff between stream rounds.
	reconnectBackoffCap    = 30 * time.Second
	reconnectHealthyWindow = 30 * time.Second
)

// errStreamUnavailable reports that the streaming downlink could not be
// established on this path (old server, buffering proxy, rejected request).
// DialXHTTP falls back to the poll mode when it sees it.
var errStreamUnavailable = errors.New("tunnel: streaming downlink unavailable")

// errAuthRejected reports that the server refused the session's credentials
// (HTTP 401/407). Retrying cannot help, so the tunnel aborts with this.
var errAuthRejected = errors.New("tunnel: authentication rejected by server")

// errTargetDenied reports that the server refused the session's target (HTTP
// 403). attachOrCreateSession runs the allowlist before it registers the
// session, so a poll retry cannot succeed — there is no session to poll and
// the same refusal would come back. The dial aborts rather than degrading into
// a long-poll loop against a 403.
var errTargetDenied = errors.New("tunnel: target refused by server policy")

// errProbeAborted means the local session was closed while the stream
// negotiation was still probing — not a path verdict, so no cache write and
// no failure accounting.
var errProbeAborted = errors.New("tunnel: stream probe aborted by local close")

// errProbeInconclusive means the probe budget expired before the request even
// reached the origin — a cold TCP/TLS handshake on a slow link costs the same
// seconds a buffering path does, and the two are indistinguishable by elapsed
// time alone. It is not a path verdict: the session falls back to polling but
// nothing is cached, so the next dial (on the now-warm pooled transport)
// negotiates again instead of inheriting a five-minute downgrade.
var errProbeInconclusive = errors.New("tunnel: stream probe inconclusive")

// errServerSessionGone means the origin recreated a stream session after the
// application connection had already exchanged data. The old reliable-buffer
// sequence space cannot be rebased without risking duplication or loss, so the
// caller must establish a fresh application connection.
var errServerSessionGone = errors.New("tunnel: server session was recreated")

// errSessionClosedEmpty means the origin accepted the session and ended it
// before a single byte flowed. The usual causes are a target that refused the
// connection or a session the origin rejected after admitting it; either way the
// dial has no usable tunnel to hand back, and polling would meet the same
// refusal.
var errSessionClosedEmpty = errors.New("tunnel: the origin closed the session before any data flowed (target refused, session rejected, or the origin does not stream)")

// errInvalidPeerAck reports that the server's acknowledgement does not match
// the client's write cursor. Unlike transport blips the server is
// persistently out of sync; reconnecting cannot recover, so the pump must
// stop and let the caller observe a fatal closeErr.
var errInvalidPeerAck = errors.New("tunnel: invalid peer acknowledgement")

// streamPollDowngradeAfter is how many consecutive conclusive "this path cannot
// stream" verdicts it takes to downgrade one endpoint to long polling. A single
// sample is not enough: one probe can be tripped by a transient edge state (a
// 429 or 503 from a CDN, an origin restarting mid-probe), and every session
// dialed during the TTL would inherit that verdict. Two consecutive failures
// from two separate sessions is the threshold.
const streamPollDowngradeAfter = 2

type streamModeEntry struct {
	mode     string // "stream", "poll", or "" while failures accumulate
	expiry   time.Time
	ttfbBase time.Duration
	failures int // consecutive conclusive "cannot stream" verdicts
}

var (
	streamModeMu    sync.Mutex
	streamModeCache = map[string]streamModeEntry{}

	// streamProbeGates collapses concurrent negotiations for one endpoint: see
	// dialStreamMode. Keyed like streamModeCache.
	streamProbeGatesMu sync.Mutex
	streamProbeGates   = map[string]*streamProbeGate{}
)

func (c *DialConfig) streamModeKey(protocol, hostPort string) string {
	return protocol + "|" + hostPort + "|" + c.SNI + "|" + c.CertificateFingerprint + "|" + c.TransportKey
}

// pruneStreamModesLocked drops expired entries. The cache lives for the process
// lifetime and is keyed per endpoint, so without a sweep a client that roams
// across many CDN endpoints would keep a key for every one it ever saw.
func pruneStreamModesLocked(now time.Time) {
	for k, e := range streamModeCache {
		if now.After(e.expiry) {
			delete(streamModeCache, k)
		}
	}
}

func cachedStreamMode(key string) (string, time.Duration) {
	streamModeMu.Lock()
	defer streamModeMu.Unlock()
	e, ok := streamModeCache[key]
	if !ok || time.Now().After(e.expiry) {
		return "", 0
	}
	return e.mode, e.ttfbBase
}

// cacheStreamMode records a negotiated verdict. A successful negotiation clears
// any accumulated failures and publishes the measured TTFB, which widens the
// probe window for the next session on a high-RTT path.
func cacheStreamMode(key, mode string, ttfb time.Duration) {
	streamModeMu.Lock()
	defer streamModeMu.Unlock()
	now := time.Now()
	pruneStreamModesLocked(now)
	streamModeCache[key] = streamModeEntry{mode: mode, expiry: now.Add(streamModeCacheTTL), ttfbBase: ttfb}
}

// recordStreamPollVerdict records one conclusive "this path cannot stream"
// verdict and downgrades the endpoint only once the failures are consecutive.
// It is deliberately noisy about the downgrade: without a log line an operator
// can only observe that new sessions stopped streaming for the whole TTL.
func recordStreamPollVerdict(key, reason string, lg *zap.Logger) {
	streamModeMu.Lock()
	now := time.Now()
	pruneStreamModesLocked(now)
	e := streamModeCache[key]
	e.failures++
	downgrade := e.failures >= streamPollDowngradeAfter
	e.mode = ""
	if downgrade {
		e.mode = "poll"
		e.ttfbBase = 0
	}
	e.expiry = now.Add(streamModeCacheTTL)
	streamModeCache[key] = e
	streamModeMu.Unlock()

	if downgrade {
		lg.Warn("⬇️ [Stream] endpoint downgraded to long polling after consecutive failed negotiations",
			zap.String("key", key),
			zap.Int("failures", e.failures),
			zap.String("reason", reason),
			zap.Duration("ttl", streamModeCacheTTL),
		)
		return
	}
	lg.Debug("📉 [Stream] path could not stream once; the next session still probes",
		zap.String("key", key),
		zap.Int("failures", e.failures),
		zap.String("reason", reason),
	)
}

// streamDownlinkEnabled decides whether this session's first attempt uses the
// streaming downlink. Explicit StreamMode wins; "auto" consults the
// per-endpoint negotiation cache.
func (c *DialConfig) streamDownlinkEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(c.StreamMode)) {
	case "stream":
		return true
	case "poll":
		return false
	default:
		mode, _ := cachedStreamMode(key)
		return mode != "poll"
	}
}

// streamProbeGate marks an endpoint whose negotiation is already in flight.
type streamProbeGate struct{ done chan struct{} }

// joinStreamProbe returns the gate for key and whether this caller owns it. The
// owner probes; everyone else waits for its verdict (see dialStreamMode).
func joinStreamProbe(key string) (*streamProbeGate, bool) {
	streamProbeGatesMu.Lock()
	defer streamProbeGatesMu.Unlock()
	if g, ok := streamProbeGates[key]; ok {
		return g, false
	}
	g := &streamProbeGate{done: make(chan struct{})}
	streamProbeGates[key] = g
	return g, true
}

// finishStreamProbe publishes the verdict to the waiting dials and forgets the
// gate. It must run on every path out of the owner's negotiation.
func finishStreamProbe(key string, gate *streamProbeGate) {
	streamProbeGatesMu.Lock()
	if streamProbeGates[key] == gate {
		delete(streamProbeGates, key)
	}
	streamProbeGatesMu.Unlock()
	close(gate.done)
}

// waitStreamProbe parks a joining dial until the owner publishes its verdict,
// the dial is cancelled, or the wait budget elapses. The budget is the minimum
// probe window, not the owner's: waiting longer than that would make a joining
// dial slower than simply probing on its own.
func waitStreamProbe(ctx context.Context, gate *streamProbeGate) {
	t := time.NewTimer(streamProbeMinWindow)
	defer t.Stop()
	select {
	case <-gate.done:
	case <-ctx.Done():
	case <-t.C:
	}
}

// dialStreamMode negotiates the streaming downlink for one session, collapsing
// concurrent negotiations for the same endpoint. Waiting for another dial's
// verdict costs the same wall clock as probing in parallel, but a poll-only path
// then produces one probe instead of one per concurrent session — and that
// request burst is exactly what a CDN rate-limits.
func dialStreamMode(ctx context.Context, key string, a streamDialArgs) (net.Conn, error) {
	gate, owner := joinStreamProbe(key)
	if owner {
		defer finishStreamProbe(key, gate)
		return dialXHTTPStream(a)
	}
	waitStreamProbe(ctx, gate)
	if mode, _ := cachedStreamMode(key); mode == "poll" {
		return nil, fmt.Errorf("%w (a concurrent dial already found the endpoint poll-only)", errStreamUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// No verdict, or a "stream" verdict: a successful negotiation belongs to
	// one session (it owns that GET and its companion POST), so negotiate here
	// too — now with the TTFB baseline the owner just published.
	return dialXHTTPStream(a)
}

type streamDialArgs struct {
	ctx          context.Context
	cfg          *DialConfig
	rt           http.RoundTripper
	ownTransport bool
	client       *http.Client
	reqURL       string
	sessionID    string
	key          string
	targetAddr   string
	network      string
	localAddr    net.Addr
	remoteAddr   net.Addr
	uploadChunk  int
	logger       *zap.Logger
	events       *eventHub
	onReady      func()
}

// dialXHTTPStream runs the stream-mode pump: one persistent GET whose
// response body carries the downlink, plus long POSTs carrying the uplink.
// A break in the stream reconnects with resume semantics; errStreamUnavailable
// signals DialXHTTP to fall back to the poll mode.
func dialXHTTPStream(a streamDialArgs) (net.Conn, error) {
	logger := a.logger
	virtualConn := newMeekVirtualConn(a.sessionID, a.localAddr, a.remoteAddr, logger)
	window, err := windowBytes(a.cfg.WindowSizeMB)
	if err != nil {
		return nil, err
	}
	virtualConn.writeBuf = newReliableBuffer(window)
	pumpCtx, pumpCancel := context.WithCancel(a.ctx)
	pumpDone := make(chan struct{})
	ready := make(chan error, 1)
	var readyOnce sync.Once
	announce := func(err error) { readyOnce.Do(func() { ready <- err }) }
	a.onReady = func() { announce(nil) }

	go func() {
		defer close(pumpDone)
		defer pumpCancel()
		defer announce(errProbeAborted)
		defer virtualConn.Close()

		// atomic.Uint64, never a bare uint64: this pump writes it while
		// streamUplinkWriter reads it concurrently. The wrapper carries the
		// compiler's align64 marker, so it stays 8-byte aligned wherever it lands.
		// A bare uint64 reached through the free atomic functions traps on a 32-bit
		// target (386/arm) the moment its offset is not a multiple of 8.
		var ackedByServer atomic.Uint64
		var lastDown uint64 // highest downSeq delivered to the reassembly buffer
		var established bool
		failures := 0

		for !virtualConn.isClosed() && !virtualConn.closePending() {
			t0 := time.Now()
			var roundReady time.Time
			a.onReady = func() { roundReady = time.Now(); announce(nil) }
			serverClosed, err := a.runStreamRound(pumpCtx, a.client, virtualConn, &ackedByServer, &lastDown, &established, t0)
			if !established {
				// A session that ends before the first byte — whether the round
				// reports a clean close or the downlink simply stopped — has
				// nothing to hand back. Fail the dial with the reason this path
				// can see, and do not count it as a verdict: polling would meet
				// the same refusal.
				if err == nil && serverClosed {
					err = errSessionClosedEmpty
				}
				if errors.Is(err, errSessionClosedEmpty) {
					announce(err)
					a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "peer closed before data", Detail: err.Error()})
					return
				}
			}
			announce(err)
			elapsed := time.Since(t0)

			if virtualConn.isClosed() || virtualConn.closePending() || pumpCtx.Err() != nil {
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "local close"})
				return
			}
			if errors.Is(err, errProbeAborted) {
				// Local close raced the negotiation — the tunnel is going
				// away, so this is neither a path verdict nor a failure.
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "local close"})
				return
			}
			if errors.Is(err, errAuthRejected) {
				virtualConn.setCloseErr(err)
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "auth rejected", Detail: err.Error()})
				return
			}
			if errors.Is(err, errTargetDenied) {
				// A 403 must not reach the reconnect loop below: policy will not
				// change while we sit here, and retrying just hammers the origin
				// (or whatever fronts it) with refusals forever.
				virtualConn.setCloseErr(err)
				logger.Warn("❌ [Stream] target refused by the server, not reconnecting",
					zap.String("session", a.sessionID),
					zap.String("target", a.targetAddr),
				)
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "target denied", Detail: err.Error()})
				return
			}
			if errors.Is(err, errServerSessionGone) {
				virtualConn.setCloseErr(err)
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "server session recreated", Detail: err.Error()})
				return
			}
			if errors.Is(err, errProbeInconclusive) {
				// The budget expired during connection setup, which happens on
				// any cold or high-RTT link. This session polls, but no verdict
				// is recorded: the transport is pooled now, so the next dial
				// negotiates again instead of inheriting a downgrade.
				logger.Warn("⚠️ [Stream] probe inconclusive (the request never reached the origin within the window); this session falls back to long polling, verdict not cached",
					zap.String("session", a.sessionID),
					zap.Error(err),
				)
				return
			}
			if errors.Is(err, errStreamUnavailable) && !established {
				// Path/origin cannot stream: record the verdict and let
				// DialXHTTP fall back to polling. A forced StreamMode="stream"
				// keeps the decision local to this session (no cache write).
				if !strings.EqualFold(strings.TrimSpace(a.cfg.StreamMode), "stream") {
					recordStreamPollVerdict(a.key, err.Error(), logger)
				}
				return
			}
			if errors.Is(err, errInvalidPeerAck) {
				virtualConn.setCloseErr(err)
				if !established && !strings.EqualFold(strings.TrimSpace(a.cfg.StreamMode), "stream") {
					recordStreamPollVerdict(a.key, err.Error(), logger)
				}
				logger.Warn("❌ [Stream] invalid peer ack, not reconnecting",
					zap.String("session", a.sessionID),
					zap.Error(err),
				)
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "invalid peer ack", Detail: err.Error()})
				return
			}
			if err != nil {
				if !roundReady.IsZero() && time.Since(roundReady) >= reconnectHealthyWindow {
					failures = 0
				}
				failures++
				logger.Warn("⚠️ [Stream] downlink stream broke, preparing to reconnect and resume",
					zap.String("session", a.sessionID),
					zap.Int("failures", failures),
					zap.Duration("survived", elapsed),
					zap.Error(err),
				)
				a.events.emit(Reconnecting{SessionID: a.sessionID, Nth: failures, Reason: err.Error()})
				// Retry indefinitely with capped exponential backoff: a network
				// change (Wi-Fi↔cellular, interface flap) must recover on its
				// own, and 2 rapid failures during an outage would otherwise
				// kill a perfectly resumable tunnel.
				if !sleepCtx(pumpCtx, streamReconnectBackoff(failures)) {
					a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "local close"})
					return
				}
				continue
			}
			// Clean end means the server sent the close marker and the tunnel
			// is finished; runStreamRound closes the virtual conn itself.
			if serverClosed {
				virtualConn.setCloseErr(errors.New("peer closed"))
				a.events.emit(TunnelDied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Reason: "peer closed"})
				return
			}
			failures = 0
		}
	}()

	closer := func() error {
		// Ask the uplink to ship whatever is queued plus the close marker.
		// The uplink writer ends its body on closePending (the fix that keeps
		// this fast), the server then closes the session and the downlink
		// reader sees the close marker — pumpDone closes in milliseconds.
		virtualConn.requestClose()
		select {
		case <-pumpDone:
		case <-time.After(streamCloseGrace):
			logger.Debug("⏱️ [Stream] close grace period elapsed, force-cancelling the pump", zap.String("session", a.sessionID))
			pumpCancel()
			virtualConn.Close()
			<-pumpDone
		}
		return virtualConn.Close()
	}
	select {
	case err := <-ready:
		if err == nil {
			return newXHTTPConn(virtualConn, virtualConn, closer, virtualConn.local, virtualConn.remote, virtualConn), nil
		}
		pumpCancel()
		virtualConn.Close()
		<-pumpDone
		return nil, err
	case <-a.ctx.Done():
		pumpCancel()
		virtualConn.Close()
		<-pumpDone
		return nil, a.ctx.Err()
	}
}

// Equal jitter spreads retries over half to all of an exponentially growing
// interval. The total wait, including jitter, never exceeds the cap.
func streamReconnectBackoff(failures int) time.Duration {
	base := 300 * time.Millisecond
	for i := 1; i < failures && base < reconnectBackoffCap; i++ {
		base *= 2
	}
	if base > reconnectBackoffCap {
		base = reconnectBackoffCap
	}
	half := base / 2
	return half + time.Duration(mrand.Int63n(int64(base-half)+1))
}

// roundErrCause returns the error that explains why a round ended, skipping the
// errors that unwinding the round itself produces. `finish` closes the upload
// pipe, and the writer goroutine then fails on that closed pipe — reporting
// "io: read/write on closed pipe" instead of the read EOF that actually ended
// the round hides the real cause (a refused target, a reaped session) from the
// operator.
func roundErrCause(ch chan error) error {
	for {
		select {
		case err := <-ch:
			if err == nil || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, context.Canceled) {
				continue
			}
			return err
		default:
			return nil
		}
	}
}

// runStreamRound establishes one streaming GET and drives it to completion.
// serverClosed reports that the peer ended the session with a close marker.
//
// A reconnect round carries its own throwaway transport: the previous
// round's long POST is still winding down on a pooled connection, and reusing
// that pool for the reconnect GET served the old response's tail bytes — the
// reconnect read ended with an immediate EOF. Fresh sockets for the rare
// reconnect path sidestep the contamination without touching steady-state
// pooling.
func (a streamDialArgs) runStreamRound(pumpCtx context.Context, client *http.Client, virtualConn *meekVirtualConn, ackedByServer *atomic.Uint64, lastDown *uint64, established *bool, roundStart time.Time) (serverClosed bool, err error) {
	roundCtx, cancelRound := context.WithCancel(pumpCtx)
	defer cancelRound()

	if *lastDown > 0 && a.rt != nil {
		// Reconnect: replace the pooled client with an isolated one.
		client = a.isolatedClient()
	}

	// Negotiation probe window: how long we wait for the hello frame before
	// concluding that the path (or the origin) cannot stream.
	probeWindow := streamProbeMinWindow
	if _, base := cachedStreamMode(a.key); base > 0 {
		if w := 3 * base; w > probeWindow {
			probeWindow = w
		}
	}
	if probeWindow > 30*time.Second {
		probeWindow = 30 * time.Second
	}
	deadline := roundStart.Add(probeWindow)
	// probeExpired records that the window itself ended the round, as opposed
	// to our own upload plumbing cancelling it. The two are indistinguishable
	// from roundCtx after the fact, and only the first is a path verdict.
	var probeExpired atomic.Bool
	probeTimer := time.AfterFunc(time.Until(deadline), func() {
		probeExpired.Store(true)
		cancelRound()
	})
	defer probeTimer.Stop()

	req, _ := http.NewRequestWithContext(roundCtx, http.MethodGet, a.reqURL, nil)
	req.Header.Set("X-Downstream", "1")
	req.Header.Set("X-Stream-Probe-Window", strconv.Itoa(int(probeWindow.Seconds())))
	if *lastDown > 0 {
		// Reconnect within the same server session: X-Ack identifies downlink
		// bytes already delivered. Uplink resume is carried by each frame's
		// sequence and acknowledgement metadata.
		req.Header.Set("X-Ack", strconv.FormatUint(*lastDown, 10))
		req.Header.Set("X-Retry", "1")
	}
	if err := applyStreamRequestHeaders(req, a.cfg, a.targetAddr, a.network, a.sessionID); err != nil {
		return false, err
	}
	// WroteRequest separates the two phases that share the probe budget. If the
	// request never left the socket, the budget was spent on connection setup —
	// no verdict. If it did, the origin (or an intermediary) is holding back the
	// response headers, which is exactly the "this path buffers" verdict.
	var wroteRequest atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(roundCtx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) },
	}))

	resp, err := client.Do(req)
	if err != nil {
		if pumpCtx.Err() == nil && roundCtx.Err() != nil {
			if !wroteRequest.Load() {
				return false, fmt.Errorf("%w (connection setup exceeded %v)", errProbeInconclusive, probeWindow)
			}
			return false, fmt.Errorf("%w (no response headers within %v: the path buffers responses)", errStreamUnavailable, probeWindow)
		}
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		// Auth failures will not fix themselves on a reconnect, and a target
		// refusal is worth surfacing as its own event; both skip the generic
		// "unavailable" fallback so the caller sees the real cause.
		if resp.StatusCode == http.StatusProxyAuthRequired || resp.StatusCode == http.StatusUnauthorized {
			return false, errAuthRejected
		}
		if resp.StatusCode == http.StatusForbidden {
			a.events.emit(TargetDenied{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network, Remote: resp.Request.RemoteAddr})
			return false, errTargetDenied
		}
		// 429/503 are transient edge states (rate limit, full origin), not a
		// statement about the path. They still fall back for this session, but
		// the reason travels in the error so an operator can tell them apart
		// from a genuine "cannot stream" verdict in the log.
		return false, fmt.Errorf("%w (origin answered HTTP %d)", errStreamUnavailable, resp.StatusCode)
	}
	if resp.Header.Get("X-Downstream-Accepted") != "1" {
		// Old origin or a proxy that dropped the header: it ran the long-poll
		// branch. Note this response may already carry downlink bytes, which is
		// why the poll fallback relies on AcquireDownWriter rewinding the
		// dispatch cursor to the peer's (zero) acknowledgement.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("%w (the origin did not accept the streaming downlink)", errStreamUnavailable)
	}
	if resp.Header.Get("X-Stream-Uplink-Sync") != "1" {
		// Older origins can send a downlink hello before the companion POST is
		// admitted, making Dial report success for a one-way connection. Fall
		// back (or fail loudly in forced mode) until the origin supports the
		// two-direction readiness handshake.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("%w (the origin predates the two-direction readiness handshake)", errStreamUnavailable)
	}
	// A server announcing a newer protocol generation than this client speaks
	// is fatal, not a fallback: the frame layout may already differ, so
	// polling could corrupt the stream rather than degrade it.
	if err := checkServerProto(resp.Header); err != nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, err
	}

	// Reset the probe timer: the window should cover the hello wait, not the
	// connection setup that has already completed. Without this, a high-RTT
	// handshake consumes most of the window and the hello — which the server
	// sends only after POST admission — arrives after the deadline.
	if roundCtx.Err() == nil {
		probeTimer.Stop()
		deadline = time.Now().Add(probeWindow)
		probeTimer = time.AfterFunc(time.Until(deadline), func() {
			probeExpired.Store(true)
			cancelRound()
		})
	}

	// Start the companion POST before waiting for the hello frame. A current
	// origin emits that frame only after this request has passed auth and the
	// per-session admission limit, so successful negotiation proves that both
	// directions are usable without depending on a CDN forwarding an early
	// response to a still-streaming POST.
	wg := &sync.WaitGroup{}
	roundErr := make(chan error, 2)
	pr, pw := io.Pipe()
	failRound := func(err error) {
		select {
		case roundErr <- err:
		default:
		}
		cancelRound()
		_ = pr.CloseWithError(err)
		_ = pw.CloseWithError(err)
		_ = resp.Body.Close()
	}
	stopPipe := context.AfterFunc(roundCtx, func() { _ = pr.CloseWithError(roundCtx.Err()); _ = pw.CloseWithError(roundCtx.Err()) })
	defer stopPipe()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.streamUplinkWriter(roundCtx, virtualConn, pw, ackedByServer); err != nil {
			failRound(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		upReq, uerr := http.NewRequestWithContext(roundCtx, http.MethodPost, a.reqURL, pr)
		if uerr != nil {
			failRound(uerr)
			return
		}
		if err := applyStreamRequestHeaders(upReq, a.cfg, a.targetAddr, a.network, a.sessionID); err != nil {
			failRound(err)
			return
		}
		upReq.Header.Set("Content-Type", streamContentType)
		upReq.Header.Set("X-Stream-Resume", "1")
		upResp, uerr := client.Do(upReq)
		if uerr != nil {
			failRound(uerr)
			return
		}
		defer upResp.Body.Close()
		if upResp.StatusCode != http.StatusOK {
			if upResp.StatusCode == http.StatusUnauthorized || upResp.StatusCode == http.StatusProxyAuthRequired {
				failRound(errAuthRejected)
			} else {
				failRound(fmt.Errorf("stream upload: HTTP %d", upResp.StatusCode))
			}
			return
		}
		_, uerr = io.Copy(io.Discard, io.LimitReader(upResp.Body, 4096))
		if !virtualConn.closePending() && !virtualConn.isClosed() {
			if uerr == nil {
				uerr = io.ErrUnexpectedEOF
			}
			failRound(uerr)
		}
	}()

	var finishOnce sync.Once
	finish := func() {
		finishOnce.Do(func() {
			cancelRound()
			_ = pw.CloseWithError(io.ErrClosedPipe)
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(streamRoundTeardown):
				resp.Body.Close()
				<-done
			}
		})
	}
	defer finish()

	// First frame inside the probe window proves the path streams.
	type firstResult struct {
		f   streamFrame
		err error
	}
	firstC := make(chan firstResult, 1)
	go func() {
		f, err := readStreamFrame(resp.Body)
		firstC <- firstResult{f: f, err: err}
	}()
	var first streamFrame
	select {
	case res := <-firstC:
		if res.err != nil {
			// Sample the round state BEFORE finish(): it cancels roundCtx, after
			// which every cancellation looks like ours.
			canceledByRound := roundCtx.Err() != nil && pumpCtx.Err() == nil
			finish()
			if uerr := roundErrCause(roundErr); uerr != nil {
				return false, uerr
			}
			if canceledByRound && probeExpired.Load() {
				// Our own probe window ended the read, not the peer: the
				// response headers arrived but the hello did not.
				return false, fmt.Errorf("%w (no frame within %v: the path buffers responses)", errStreamUnavailable, probeWindow)
			}
			if !canceledByRound || errors.Is(res.err, io.EOF) || errors.Is(res.err, io.ErrUnexpectedEOF) {
				// The origin ended the downlink before the first frame, or our
				// upload plumbing died before the window did. Either way this is
				// not a verdict on the path: a refused target, a reaped session.
				return false, fmt.Errorf("%w: %v", errSessionClosedEmpty, res.err)
			}
			return false, res.err
		}
		first = res.f
	case <-virtualConn.closedSignal():
		// Close raced the negotiation: abort the probe immediately so
		// Close() is not held for the probe window. No cache write and no
		// failure count — this is a local close, not a path verdict.
		return false, errProbeAborted
	case <-roundCtx.Done():
		if uerr := roundErrCause(roundErr); uerr != nil {
			return false, uerr
		}
		if pumpCtx.Err() != nil {
			return false, pumpCtx.Err()
		}
		if probeExpired.Load() {
			return false, fmt.Errorf("%w (no frame within %v: the path buffers responses)", errStreamUnavailable, probeWindow)
		}
		return false, errSessionClosedEmpty
	}
	if !probeTimer.Stop() && roundCtx.Err() != nil {
		return false, fmt.Errorf("%w (no frame within %v: the path buffers responses)", errStreamUnavailable, probeWindow)
	}

	logger := a.logger
	if resp.Header.Get("X-Session-Created") == "1" && *established {
		// The server recreated the session (kick, reaper, restart). Already
		// acknowledged uplink bytes have left the reliable buffer, so rebasing
		// the surviving application connection to zero would either stall or
		// silently lose/duplicate data. Fail the old connection explicitly;
		// the application can open a clean tunnel with a new sequence epoch.
		return false, errServerSessionGone
	}
	if !virtualConn.writeBuf.validAck(first.ack) {
		return false, errInvalidPeerAck
	}
	if first.closed {
		// Server closed an empty session immediately: tunnel is over.
		virtualConn.Close()
		return true, nil
	}
	if len(first.data) > 0 {
		*lastDown, err = virtualConn.PutReadDataContext(roundCtx, first.seq, first.data)
		if err != nil {
			return false, err
		}
	}
	if ack := first.ack; ack > ackedByServer.Load() {
		ackedByServer.Store(ack)
		virtualConn.writeBuf.acknowledge(ack)
	}
	// Negotiated. Cache and announce only after the first frame has passed
	// sequence and acknowledgement validation; otherwise a malformed peer can
	// make callers observe a connection that is already doomed.
	cacheStreamMode(a.key, "stream", time.Since(roundStart))
	a.events.emit(TunnelEstablished{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network})
	logger.Debug("📡 [Stream] streaming downlink negotiation succeeded", zap.String("session", a.sessionID), zap.Duration("ttfb", time.Since(roundStart)))
	if a.onReady != nil {
		a.onReady()
	}
	*established = true

	// Watchdog: an established stream must see frames (data or keepalives)
	// regularly; a stall means the path broke silently.
	watchdog := time.AfterFunc(streamWatchdogTimeout, cancelRound)
	defer watchdog.Stop()

	var readScratch []byte
	// Downlink reader (this goroutine): frames into the reassembly buffer.
	for {
		f, rerr := readStreamFrameInto(resp.Body, &readScratch)
		if rerr != nil {
			// Drain the uplink goroutines before reporting.
			finish()
			if uerr := roundErrCause(roundErr); uerr != nil {
				return false, uerr
			}
			return false, rerr
		}
		watchdog.Reset(streamWatchdogTimeout)
		if !virtualConn.writeBuf.validAck(f.ack) {
			finish()
			return false, errInvalidPeerAck
		}
		if ack := f.ack; ack > ackedByServer.Load() {
			ackedByServer.Store(ack)
			virtualConn.writeBuf.acknowledge(ack)
		}
		if f.closed {
			// Server ended the session: tunnel EOF for the local reader.
			virtualConn.Close()
			finish()
			return true, nil
		}
		if len(f.data) > 0 {
			*lastDown, err = virtualConn.PutReadDataContext(roundCtx, f.seq, f.data)
			if err != nil {
				finish()
				return false, err
			}
			// Receive progress wakes the sole uplink writer. The reader never
			// blocks on writing an ACK into a slow upload pipe.
		}
	}
}

// streamUplinkWriter streams reliable-buffer chunks into the POST body pipe,
// keeping the uplink ack (for the server's downlink buffer) flowing even when
// the uplink itself is idle.
func (a streamDialArgs) streamUplinkWriter(ctx context.Context, virtualConn *meekVirtualConn, pw *io.PipeWriter, ackedByServer *atomic.Uint64) error {
	// The dispatch cursor belongs to this HTTP round. On reconnect a fresh
	// writer starts at the cumulative peer ACK and re-sends anything that was
	// handed to the failed round but never acknowledged.
	dispatchSeq := ackedByServer.Load()
	var lastAckSent uint64
	lastSent := time.Now().Add(-streamUplinkKeepalive)
	var sendScratch []byte
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		currentAck := ackedByServer.Load()
		if dispatchSeq < currentAck {
			dispatchSeq = currentAck
		}
		ack := virtualConn.consumedUpSeq()
		frame, currentSeq, err := virtualConn.writeBuf.getStreamFrame(currentAck, dispatchSeq, ack, a.uploadChunk, sendScratch)
		if err != nil {
			return err
		}
		if len(frame) == 0 {
			// Nothing left to ship: end the body so the server's uplink
			// reader sees EOF and tears the session down. This is what keeps
			// Close() fast — idling out the 25s window here would stall every
			// tunnel close by that long.
			if virtualConn.closePending() || virtualConn.isClosed() {
				// End the body so the server sees uplink EOF, tears the
				// session down and ships the close marker — that is what
				// lets pumpDone fire in milliseconds. Leaving the pipe open
				// here made every local Close() burn the full 2s grace.
				frame, err := streamCloseFrameBytes(dispatchSeq, virtualConn.consumedUpSeq())
				if err != nil {
					return err
				}
				if _, err = pw.Write(frame); err != nil {
					return err
				}
				pw.Close()
				return nil
			}
			elapsed := time.Since(lastSent)
			pending := ack - lastAckSent
			if pending < ackCoalesceBytes && elapsed < streamUplinkKeepalive && (pending == 0 || elapsed < streamAckInterval) {
				delay := streamUplinkKeepalive - elapsed
				if pending > 0 {
					delay = streamAckInterval - elapsed
				}
				streamWait(ctx, virtualConn, delay)
				continue
			}
			// Ack-only keepalive: the server frees its downlink buffer from
			// these, so they must flow even with an idle uplink.
			frame, err := streamFrameBytesInto(sendScratch, dispatchSeq, ack, nil)
			if err != nil {
				return err
			}
			if _, err := pw.Write(frame); err != nil {
				return err
			}
			lastAckSent, lastSent = ack, time.Now()
			sendScratch = frame
			continue
		}
		dispatchSeq = currentSeq + uint64(binary.BigEndian.Uint32(frame[16:20]))
		if _, err := pw.Write(frame); err != nil {
			return err
		}
		lastAckSent, lastSent = ack, time.Now()
		sendScratch = frame
	}
}

// isolatedClient returns a client whose transport shares the dial/tls
// parameters but not the connection pool — reconnect rounds never touch the
// pooled sockets the previous round's POST is still draining on.
func (a streamDialArgs) isolatedClient() *http.Client {
	if base, ok := a.rt.(*http.Transport); ok {
		clone := base.Clone()
		clone.DisableKeepAlives = true
		return &http.Client{Transport: clone}
	}
	// h2/h3 transports cannot be cheaply cloned per round; the pool there is
	// per-stream multiplexed, which does not suffer the h1 tail-bytes
	// contamination. Fall back to the shared client.
	return a.client
}

// applyStreamRequestHeaders sets the headers shared by the streaming GET and
// its companion POST (auth, camouflage, routing).
func applyStreamRequestHeaders(req *http.Request, cfg *DialConfig, targetAddr, network, sessionID string) error {
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	if cfg.Host != "" {
		req.Host = cfg.Host
	} else if cfg.SNI != "" {
		req.Host = cfg.SNI
	}
	req.Header.Set("User-Agent", clientUserAgent)
	// Signed credentials: the PSK itself never goes on the wire, so a captured
	// request leaks nothing, and the per-request nonce makes replay a no-op.
	if err := setAuthHeaders(req, cfg.Password, sessionID, network, targetAddr); err != nil {
		return fmt.Errorf("tunnel: could not generate a nonce: %w", err)
	}
	req.Header.Set("X-Target", targetAddr)
	req.Header.Set("X-Network", network)
	req.Header.Set("X-Session-ID", sessionID)
	req.Header.Set(ProtoHeader, strconv.Itoa(offeredProtoVersion))
	return nil
}
