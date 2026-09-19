package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	// frame when deciding whether the path streams. The effective window is
	// max(this, 3x the endpoint's measured TTFB).
	streamProbeMinWindow = 2 * time.Second
	// streamWatchdogTimeout is the no-frame stall threshold for an
	// established stream; the server keepalives every 5s so a healthy path
	// never trips it.
	streamWatchdogTimeout = 75 * time.Second
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
	ackCoalesceBytes = 128 * 1024
	// reconnectBackoffCap bounds the reconnect backoff between stream rounds.
	reconnectBackoffCap = 30 * time.Second
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

// errServerSessionGone means the origin recreated a stream session after the
// application connection had already exchanged data. The old reliable-buffer
// sequence space cannot be rebased without risking duplication or loss, so the
// caller must establish a fresh application connection.
var errServerSessionGone = errors.New("tunnel: server session was recreated")

type streamModeEntry struct {
	mode     string // "stream" or "poll"
	expiry   time.Time
	ttfbBase time.Duration
}

var (
	streamModeMu    sync.Mutex
	streamModeCache = map[string]streamModeEntry{}
)

func (c *DialConfig) streamModeKey(protocol, hostPort string) string {
	return protocol + "|" + hostPort + "|" + c.SNI + "|" + c.CertificateFingerprint + "|" + c.TransportKey
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

func cacheStreamMode(key, mode string, ttfb time.Duration) {
	streamModeMu.Lock()
	defer streamModeMu.Unlock()
	streamModeCache[key] = streamModeEntry{mode: mode, expiry: time.Now().Add(streamModeCacheTTL), ttfbBase: ttfb}
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
			serverClosed, err := a.runStreamRound(pumpCtx, a.client, virtualConn, &ackedByServer, &lastDown, &established, t0)
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
			if errors.Is(err, errStreamUnavailable) {
				// Path/origin cannot stream: remember and let DialXHTTP fall
				// back to polling. A forced StreamMode="stream" keeps the
				// decision local to this session (no cache write happens for
				// it — the caller handles that).
				if !strings.EqualFold(strings.TrimSpace(a.cfg.StreamMode), "stream") {
					cacheStreamMode(a.key, "poll", 0)
				}
				return
			}
			if err != nil {
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
				backoff := time.Duration(failures) * 300 * time.Millisecond
				if backoff > reconnectBackoffCap {
					backoff = reconnectBackoffCap
				}
				select {
				case <-time.After(backoff):
				case <-pumpCtx.Done():
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
	deadline := roundStart.Add(probeWindow)
	probeTimer := time.AfterFunc(time.Until(deadline), cancelRound)
	defer probeTimer.Stop()

	req, _ := http.NewRequestWithContext(roundCtx, http.MethodGet, a.reqURL, nil)
	req.Header.Set("X-Downstream", "1")
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

	resp, err := client.Do(req)
	if err != nil {
		if pumpCtx.Err() == nil && roundCtx.Err() != nil {
			return false, errStreamUnavailable
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
		return false, errStreamUnavailable
	}
	if resp.Header.Get("X-Downstream-Accepted") != "1" {
		// Old origin: it ran the long-poll branch and will answer normally.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, errStreamUnavailable
	}
	if resp.Header.Get("X-Stream-Uplink-Sync") != "1" {
		// Older origins can send a downlink hello before the companion POST is
		// admitted, making Dial report success for a one-way connection. Fall
		// back (or fail loudly in forced mode) until the origin supports the
		// two-direction readiness handshake.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, errStreamUnavailable
	}
	// A server announcing a newer protocol generation than this client speaks
	// is fatal, not a fallback: the frame layout may already differ, so
	// polling could corrupt the stream rather than degrade it.
	if err := checkServerProto(resp.Header); err != nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, err
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
			finish()
			select {
			case uerr := <-roundErr:
				return false, uerr
			default:
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
		select {
		case uerr := <-roundErr:
			return false, uerr
		default:
		}
		if pumpCtx.Err() != nil {
			return false, pumpCtx.Err()
		}
		return false, errStreamUnavailable
	}
	if !probeTimer.Stop() && roundCtx.Err() != nil {
		return false, errStreamUnavailable
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
		return false, fmt.Errorf("tunnel: invalid peer acknowledgement")
	}
	if first.closed || bytes.Equal(first.data, closeMarkerPayload) {
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

	// lastAckSent tracks how much downlink progress has been reported to the
	// server via ack-only frames on the uplink pipe (io.Pipe serialises
	// concurrent writers, so the reader can ack here safely).
	var lastAckSent uint64

	// Downlink reader (this goroutine): frames into the reassembly buffer.
	for {
		f, rerr := readStreamFrame(resp.Body)
		if rerr != nil {
			// Drain the uplink goroutines before reporting.
			finish()
			select {
			case uerr := <-roundErr:
				return false, uerr
			default:
			}
			return false, rerr
		}
		watchdog.Reset(streamWatchdogTimeout)
		if !virtualConn.writeBuf.validAck(f.ack) {
			finish()
			return false, fmt.Errorf("tunnel: invalid peer acknowledgement")
		}
		if ack := f.ack; ack > ackedByServer.Load() {
			ackedByServer.Store(ack)
		}
		if f.closed || bytes.Equal(f.data, closeMarkerPayload) {
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
			// Promptly report downlink progress so the server keeps freeing
			// its write buffer during pure downloads — its ack otherwise
			// rides only the idle uplink keepalive (25s), which throttles a
			// download into 4MB bursts.
			if pending := *lastDown - lastAckSent; pending >= ackCoalesceBytes {
				if frame, err := streamFrameBytes(0, *lastDown, nil); err == nil {
					if _, err := pw.Write(frame); err != nil {
						finish()
						return false, err
					}
					lastAckSent = *lastDown
				}
			}
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
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		currentAck := ackedByServer.Load()
		if dispatchSeq < currentAck {
			dispatchSeq = currentAck
		}
		upData, currentSeq, bufPtr := virtualConn.writeBuf.GetSlice(currentAck, dispatchSeq, a.uploadChunk)
		if len(upData) == 0 {
			safelyPutSendBuf(bufPtr)
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
			// Ack-only keepalive: the server frees its downlink buffer from
			// these, so they must flow even with an idle uplink.
			frame, err := streamFrameBytes(dispatchSeq, virtualConn.consumedUpSeq(), nil)
			if err == nil {
				if _, werr := pw.Write(frame); werr != nil {
					return werr
				}
			}
			virtualConn.writeBuf.waitDispatchable(ctx, streamUplinkKeepalive, dispatchSeq)
			continue
		}
		dispatchSeq = currentSeq + uint64(len(upData))
		frame, err := streamFrameBytes(currentSeq, virtualConn.consumedUpSeq(), upData)
		safelyPutSendBuf(bufPtr)
		if err != nil {
			return err
		}
		if _, err := pw.Write(frame); err != nil {
			return err
		}
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
	if err := setAuthHeaders(req, cfg.Password, sessionID, targetAddr); err != nil {
		return fmt.Errorf("tunnel: could not generate a nonce: %w", err)
	}
	req.Header.Set("X-Target", targetAddr)
	req.Header.Set("X-Network", network)
	req.Header.Set("X-Session-ID", sessionID)
	req.Header.Set(ProtoHeader, strconv.Itoa(offeredProtoVersion))
	return nil
}
