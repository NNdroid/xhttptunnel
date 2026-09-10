package tunnel

import (
	"bytes"
	"context"
	"errors"
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

// errProbeAborted means the local session was closed while the stream
// negotiation was still probing — not a path verdict, so no cache write and
// no failure accounting.
var errProbeAborted = errors.New("tunnel: stream probe aborted by local close")

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

	go func() {
		defer close(pumpDone)
		defer virtualConn.Close()

		var ackedByServer uint64
		var dispatchSeq uint64
		var lastDown uint64 // highest downSeq delivered to the reassembly buffer
		failures := 0

		for !virtualConn.isClosed() && !virtualConn.closePending() {
			t0 := time.Now()
			serverClosed, err := a.runStreamRound(pumpCtx, a.client, virtualConn, &dispatchSeq, &ackedByServer, &lastDown, t0)
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
			if errors.Is(err, errStreamUnavailable) {
				// Path/origin cannot stream: remember and let DialXHTTP fall
				// back to polling. A forced StreamMode="stream" keeps the
				// decision local to this session (no cache write happens for
				// it — the caller handles that).
				cacheStreamMode(a.key, "poll", 0)
				return
			}
			if err != nil {
				failures++
				logger.Warn("⚠️ [Stream] 下行流中断，准备重连续传",
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
			logger.Debug("⏱️ [Stream] 关闭宽限期超时，强制取消数据泵", zap.String("session", a.sessionID))
			pumpCancel()
			<-pumpDone
		}
		return virtualConn.Close()
	}
	return newXHTTPConn(virtualConn, virtualConn, closer, virtualConn.local, virtualConn.remote, virtualConn), nil
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
func (a streamDialArgs) runStreamRound(pumpCtx context.Context, client *http.Client, virtualConn *meekVirtualConn, dispatchSeq, ackedByServer *uint64, lastDown *uint64, roundStart time.Time) (serverClosed bool, err error) {
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

	req, _ := http.NewRequestWithContext(roundCtx, http.MethodGet, a.reqURL, nil)
	req.Header.Set("X-Downstream", "1")
	if *lastDown > 0 {
		// Reconnect: resume both sequence spaces on the server's recreated
		// session — X-Ack = downlink bytes already delivered, X-Up-Resume =
		// the uplink sequence this client will continue transmitting from.
		req.Header.Set("X-Ack", strconv.FormatUint(*lastDown, 10))
		req.Header.Set("X-Retry", "1")
		req.Header.Set("X-Up-Resume", strconv.FormatUint(*dispatchSeq, 10))
	}
	applyStreamRequestHeaders(req, a.cfg, a.targetAddr, a.network, a.sessionID)

	resp, err := client.Do(req)
	if err != nil {
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
		}
		return false, errStreamUnavailable
	}
	if resp.Header.Get("X-Downstream-Accepted") != "1" {
		// Old origin: it ran the long-poll branch and will answer normally.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, errStreamUnavailable
	}

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
			return false, res.err
		}
		first = res.f
	case <-virtualConn.closedSignal():
		// Close raced the negotiation: abort the probe immediately so
		// Close() is not held for the probe window. No cache write and no
		// failure count — this is a local close, not a path verdict.
		return false, errProbeAborted
	case <-time.After(time.Until(deadline)):
		return false, errStreamUnavailable
	}

	// Negotiated. Record the positive decision with the measured TTFB so
	// later sessions reuse the mode (and widen their probe window).
	cacheStreamMode(a.key, "stream", time.Since(roundStart))
	// The tunnel is usable from this moment: emit Established here, not at
	// round end — a healthy stream only ever ends when the tunnel dies, and
	// embedders waiting on this event to start using the conn would wait
	// forever (the Linux CI failure was exactly that).
	a.events.emit(TunnelEstablished{SessionID: a.sessionID, Target: a.targetAddr, Network: a.network})
	logger := a.logger
	logger.Debug("📡 [Stream] 流式下行协商成功", zap.String("session", a.sessionID), zap.Duration("ttfb", time.Since(roundStart)))

	if first.closed {
		// Server closed an empty session immediately: tunnel is over.
		virtualConn.Close()
		return true, nil
	}
	if first.seq == 0 && *lastDown > 0 {
		// The server recreated the session (kick, reaper, restart): its
		// sequence space restarts at zero, so reset BOTH directions — the
		// downlink bookkeeping to accept the new stream, and the uplink
		// dispatch cursor so upload frames renumber from zero (otherwise the
		// server's fresh session parks them in its out-of-order cache waiting
		// for seq 0 forever). Bytes lost with the old session are
		// unrecoverable by design — the tunnelled application's own retry
		// covers that.
		virtualConn.ResetDownCursor(0)
		*lastDown = 0
		*dispatchSeq = 0
		logger.Debug("📡 [Stream] 服务端已重建会话，双向序号重置", zap.String("session", a.sessionID))
	}
	if len(first.data) > 0 {
		virtualConn.PutReadData(first.seq, first.data)
		*lastDown = first.seq + uint64(len(first.data))
	}
	if ack := first.ack; ack > atomic.LoadUint64(ackedByServer) {
		atomic.StoreUint64(ackedByServer, ack)
	}

	// Watchdog: an established stream must see frames (data or keepalives)
	// regularly; a stall means the path broke silently.
	watchdog := time.AfterFunc(streamWatchdogTimeout, cancelRound)
	defer watchdog.Stop()

	wg := &sync.WaitGroup{}
	roundErr := make(chan error, 2)
	// lastAckSent tracks how much downlink progress has been reported to the
	// server via ack-only frames on the uplink pipe (io.Pipe serialises
	// concurrent writers, so the reader can ack here safely).
	var lastAckSent uint64

	// Uplink writer: frames from the reliable buffer into the POST body.
	pr, pw := io.Pipe()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.streamUplinkWriter(roundCtx, virtualConn, pw, dispatchSeq, ackedByServer); err != nil {
			select {
			case roundErr <- err:
			default:
			}
		}
	}()

	// The long POST carries the body; it returns when the uplink ends.
	wg.Add(1)
	go func() {
		defer wg.Done()
		upReq, uerr := http.NewRequestWithContext(roundCtx, http.MethodPost, a.reqURL, pr)
		if uerr != nil {
			select {
			case roundErr <- uerr:
			default:
			}
			return
		}
		applyStreamRequestHeaders(upReq, a.cfg, a.targetAddr, a.network, a.sessionID)
		upReq.Header.Set("Content-Type", streamContentType)
		upResp, uerr := client.Do(upReq)
		if uerr != nil {
			select {
			case roundErr <- uerr:
			default:
			}
			return
		}
		io.Copy(io.Discard, upResp.Body)
		upResp.Body.Close()
	}()

	// finish unwinds the round: stop the uplink, then give the HTTP stack a
	// moment to observe the cancellations before hard-closing the downlink
	// body — an h1 body Read cannot be interrupted by context cancellation
	// alone, and waiting unconditionally here deadlocked Close().
	finish := func() {
		cancelRound()
		_ = pw.CloseWithError(io.ErrClosedPipe)
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(streamRoundTeardown):
			// Hard-stop: closing the response body unblocks the in-flight
			// body Read; the POST goroutine's error path observes it next.
			resp.Body.Close()
			<-done
		}
	}

	// Downlink reader (this goroutine): frames into the reassembly buffer.
	for {
		f, rerr := readStreamFrame(resp.Body)
		if rerr != nil {
			// Drain the uplink goroutines before reporting.
			finish()
			return false, rerr
		}
		watchdog.Reset(streamWatchdogTimeout)
		if ack := f.ack; ack > atomic.LoadUint64(ackedByServer) {
			atomic.StoreUint64(ackedByServer, ack)
		}
		if f.closed || bytes.Equal(f.data, closeMarkerPayload) {
			// Server ended the session: tunnel EOF for the local reader.
			virtualConn.Close()
			finish()
			return true, nil
		}
		if len(f.data) > 0 {
			virtualConn.PutReadData(f.seq, f.data)
			*lastDown = f.seq + uint64(len(f.data))
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
func (a streamDialArgs) streamUplinkWriter(ctx context.Context, virtualConn *meekVirtualConn, pw *io.PipeWriter, dispatchSeq, ackedByServer *uint64) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		currentAck := atomic.LoadUint64(ackedByServer)
		if *dispatchSeq < currentAck {
			*dispatchSeq = currentAck
		}
		upData, currentSeq, bufPtr := virtualConn.writeBuf.GetSlice(currentAck, *dispatchSeq, a.uploadChunk)
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
				pw.Close()
				return nil
			}
			// Ack-only keepalive: the server frees its downlink buffer from
			// these, so they must flow even with an idle uplink.
			frame, err := streamFrameBytes(*dispatchSeq, virtualConn.consumedUpSeq(), nil)
			if err == nil {
				if _, werr := pw.Write(frame); werr != nil {
					return werr
				}
			}
			virtualConn.writeBuf.waitDispatchable(ctx, streamUplinkKeepalive, *dispatchSeq)
			continue
		}
		*dispatchSeq = currentSeq + uint64(len(upData))
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
func applyStreamRequestHeaders(req *http.Request, cfg *DialConfig, targetAddr, network, sessionID string) {
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	if cfg.Host != "" {
		req.Host = cfg.Host
	} else if cfg.SNI != "" {
		req.Host = cfg.SNI
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5410.0 Safari/537.36 Client/"+Version)
	if cfg.Password != "" {
		req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Password)
		// Proxy-Authorization is hop-by-hop and is commonly stripped by CDNs;
		// the end-to-end header keeps authentication working behind them.
		req.Header.Set("X-Auth-Token", cfg.Password)
	}
	req.Header.Set("X-Target", targetAddr)
	req.Header.Set("X-Network", network)
	req.Header.Set("X-Session-ID", sessionID)
}
