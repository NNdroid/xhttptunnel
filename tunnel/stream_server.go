package tunnel

import (
	"errors"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// streamContentType marks a long POST whose body is a continuous frame
// stream (stream-mode uplink). It is distinct from the poll mode's
// application/octet-stream so the handler can route it before reading a
// bounded body.
const streamContentType = "application/xhttp-stream"

// streamKeepaliveInterval is how often an idle streaming downlink writes a
// zero-payload keepalive frame. It refreshes the session's idle stamp (so the
// reaper does not evict live-but-quiet tunnels) and resets intermediaries'
// proxy_read_timeout counters. The tick is also the bound on how long the
// downlink handler can miss a wakeup for kicked/closed sessions — kept short
// so a lost cond broadcast costs a few seconds, never a full CDN idle window.
const streamKeepaliveInterval = 5 * time.Second

// attachOrCreateSession is the single critical section shared by the poll and
// stream paths: atomic lookup, allowlist enforcement, capacity check and
// registration, plus the connCh push that hands a brand-new session to the
// accept loop. It returns the (possibly pre-existing) session, whether it was
// created by this call, and an HTTP status when the request must be rejected
// (0 = proceed). A created session always starts both sequence spaces at
// zero — reconnecting clients detect this via the hello frame's sequence and
// reset their own bookkeeping.
func (st *serverState) attachOrCreateSession(xl *XHTTPListener, sessionID, target, network, host, remoteAddr string, lg *zap.Logger) (*meekVirtualConn, bool, int) {
	st.sessionsMu.Lock()
	vConn, exists := st.sessions[sessionID]
	if exists {
		vConn.updateActive()
		st.sessionsMu.Unlock()
		return vConn, false, 0
	}

	// Policy check happens before a session is registered, otherwise a
	// rejected target would still leave a phantom session behind. The protocol
	// goes along so a "tcp://host:port" entry can be honoured.
	if !st.targetAllowed(target, network) {
		st.sessionsMu.Unlock()
		lg.Warn("❌ [Server] refused connection: target not in allow list", zap.String("target", target), zap.String("remote", remoteAddr))
		st.events.emit(TargetDenied{Target: target, Network: network, Remote: remoteAddr})
		return nil, false, http.StatusForbidden
	}
	if len(st.sessions) >= st.maxSessions {
		st.sessionsMu.Unlock()
		lg.Warn("❌ [Server] refused connection: reached max concurrent sessions", zap.Int("limit", st.maxSessions), zap.String("remote", remoteAddr))
		st.stats.sessionsReject.Add(1)
		st.events.emit(SessionLimitRejected{SessionID: sessionID, Remote: remoteAddr})
		return nil, false, http.StatusServiceUnavailable
	}
	// Per-IP cap: a single PSK holder (or one compromised host) behind an
	// otherwise-healthy client must not be able to occupy the whole registry
	// and starve the rest. 0 disables. perIP is kept in sync with the registry
	// (incremented on create, decremented by removeSessionLocked on every
	// removal path: session close, kick, reaper, connCh-full rejection).
	if st.maxPerIP > 0 {
		if ip := ipOnly(remoteAddr); ip != "" && st.perIP[ip] >= st.maxPerIP {
			st.sessionsMu.Unlock()
			lg.Warn("❌ [Server] refused connection: reached per-IP session limit", zap.String("ip", ip), zap.Int("limit", st.maxPerIP))
			st.stats.sessionsReject.Add(1)
			st.events.emit(SessionLimitRejected{SessionID: sessionID, Remote: remoteAddr})
			return nil, false, http.StatusServiceUnavailable
		}
	}
	vConn = newMeekVirtualConn(sessionID, stringAddr(host), stringAddr(remoteAddr), st.lg())
	st.sessions[sessionID] = vConn
	if st.perIP != nil {
		if ip := ipOnly(remoteAddr); ip != "" {
			st.perIP[ip]++
		}
	}
	st.stats.sessionsTotal.Add(1)
	st.sessionsMu.Unlock()

	xConn := newXHTTPConn(vConn, vConn, func() error {
		// Give an in-flight poll a moment to pick up the queued close frame
		// before the session vanishes from the registry; otherwise the client
		// keeps re-creating the session and the target connection lingers
		// until the idle cleaner fires.
		vConn.waitDrained(serverDrainTimeout)
		st.removeSession(sessionID)
		reason := "client"
		if vConn.kicked.Load() {
			reason = "kicked"
		}
		st.events.emit(SessionClosed{SessionID: sessionID, Reason: reason})
		lg.Debug("💀 [Server] session fully removed and destroyed", zap.String("session", sessionID))
		return vConn.Close()
	}, vConn.local, vConn.remote, vConn)
	xConn.targetAddr = target
	xConn.network = network

	// Never block the HTTP handler on the accept backlog: a stalled accept
	// loop would strand handlers and freeze every session.
	select {
	case xl.connCh <- xConn:
	default:
		st.removeSession(sessionID)
		vConn.Close()
		lg.Warn("❌ [Server] session queue full, refusing new session", zap.String("session", sessionID), zap.String("remote", remoteAddr))
		return nil, false, http.StatusServiceUnavailable
	}
	lg.Debug("🆕 [Server] received and created a new tunnel session", zap.String("session", sessionID), zap.String("target", target))
	st.events.emit(SessionEstablished{SessionID: sessionID, Target: target, Network: network, Remote: remoteAddr})
	return vConn, true, 0
}

// serveStreamDownlink implements the stream-mode downlink: a persistent GET
// whose response body is a continuous frame stream. SSE-style response
// streaming is the one "almost duplex" shape legacy proxies tolerate, so the
// deployment requirements are identical to the long-poll mode's
// (X-Accel-Buffering: no + response streaming enabled).
func serveStreamDownlink(w http.ResponseWriter, r *http.Request, st *serverState, vConn *meekVirtualConn, sessionID string, created bool) {
	if r.Context().Err() != nil {
		return
	}
	logger := st.lg()
	if created {
		logger.Debug("📡 [Stream] new session established streaming downlink", zap.String("session", sessionID))
	} else {
		logger.Debug("📡 [Stream] client resumed the existing session's streaming downlink (resume)", zap.String("session", sessionID))
	}

	// A reconnecting GET carries X-Ack = the downlink bytes the client
	// already has. Record it before taking ownership so the acquire-time
	// cursor rewind resumes exactly there — but ONLY for an attached
	// session. A freshly created session starts its write buffer at zero,
	// where a stale X-Ack (referring to the old session) would discard the
	// first bytes and misalign the frame stream; the client detects the
	// recreated session via hello.seq == 0 and resets its own bookkeeping.
	if ack, err := strconvParseUint(r.Header.Get("X-Ack")); err == nil && ack > 0 && !created {
		vConn.noteDownPeerAck(ack)
	}

	// Exclusive ownership of the downlink cursor. Acquiring evicts a previous
	// writer (mode downgrade, stale reconnect) and rewinds the cursor to the
	// peer's acknowledged byte, so nothing the old writer had in flight is
	// lost — the peer dedups re-sent bytes by sequence number.
	ticket := &downWriterTicket{}
	vConn.AcquireDownWriter(ticket)
	defer vConn.ReleaseDownWriter(ticket)

	// CDN / reverse-proxy traversal headers, same set as the poll path, plus
	// the capability announcement the client's negotiation state machine
	// looks for. No Content-Length: the body length is unbounded.
	h := w.Header()
	h.Set("Cache-Control", "no-cache, no-store, no-transform, must-revalidate, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "X-Seq, X-Ack, X-Session-ID, X-Downstream-Accepted")
	h.Set("X-Downstream-Accepted", "1")
	h.Set("X-Stream-Uplink-Sync", "1")
	if created {
		h.Set("X-Session-Created", "1")
	}
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		// A path that cannot flush cannot stream; the client will not see the
		// hello bytes inside its probe window and falls back to polling.
		logger.Warn("⚠️ [Stream] response does not support Flush, streaming downlink unavailable", zap.String("session", sessionID), zap.Error(err))
		return
	}

	// Hello frame: zero payload, carries the current dispatch cursor so the
	// client learns immediately where the stream resumes. This is also what
	// the client's TTFB probe observes.
	vConn.downWindowMu.Lock()
	helloSeq := vConn.downDispatchSeq
	vConn.downWindowMu.Unlock()
	hello, err := streamFrameBytes(helloSeq, vConn.consumedUpSeq(), nil)
	if err != nil {
		return
	}
	if _, err = w.Write(hello); err != nil {
		return
	}
	if err = rc.Flush(); err != nil {
		return
	}

	// The client starts its companion POST only after seeing the flushed GET
	// headers. Do not send the hello frame until that POST has passed auth and
	// per-session admission; this makes Dial success mean both directions are
	// actually usable, without requiring full-duplex responses on the POST
	// (which many CDNs buffer until its request body ends).
	if created {
		select {
		case <-vConn.streamReady:
		case <-r.Context().Done():
			return
		case <-time.After(streamProbeMinWindow):
			return
		}
	}
	if vConn.isClosed() {
		if !vConn.kicked.Load() {
			vConn.downWindowMu.Lock()
			byeSeq := vConn.downDispatchSeq
			vConn.downWindowMu.Unlock()
			if bye, err := streamCloseFrameBytes(byeSeq, vConn.consumedUpSeq()); err == nil {
				_, _ = w.Write(bye)
				_ = rc.Flush()
			}
		}
		return
	}

	for {
		if r.Context().Err() != nil {
			return
		}
		if vConn.isClosed() {
			if vConn.kicked.Load() {
				// Admin kick: end the response without the close marker so
				// the client transparently re-establishes (poll parity).
				return
			}
			// Session over (client closed uplink, or the target ended it):
			// ship the poll-compatible close marker so the client's tunnel
			// conn sees EOF, then end the response.
			vConn.downWindowMu.Lock()
			byeSeq := vConn.downDispatchSeq
			vConn.downWindowMu.Unlock()
			if bye, err := streamCloseFrameBytes(byeSeq, vConn.consumedUpSeq()); err == nil {
				_, _ = w.Write(bye)
				_ = rc.Flush()
			}
			return
		}
		if !vConn.holdsDownWriter(ticket) {
			// A newer stream evicted us (reconnect takeover). End quietly —
			// the takeover rewound the cursor, so nothing is lost.
			return
		}

		vConn.downWindowMu.Lock()
		if !vConn.holdsDownWriter(ticket) {
			vConn.downWindowMu.Unlock()
			return
		}
		downData, myDownSeq, downBufPtr := vConn.writeBuf.GetSlice(vConn.downPeerAck.Load(), vConn.downDispatchSeq, currentMaxSendBufSize())
		if len(downData) > 0 {
			vConn.downDispatchSeq = myDownSeq + uint64(len(downData))
		} else {
			vConn.downDispatchSeq = myDownSeq
		}
		vConn.downWindowMu.Unlock()

		if len(downData) == 0 {
			// Idle: keepalive frame resets intermediary read timeouts and the
			// session's idle stamp, then park until data, client departure,
			// or the next keepalive tick.
			ka, err := streamFrameBytes(myDownSeq, vConn.consumedUpSeq(), nil)
			if err != nil {
				return
			}
			if _, err = w.Write(ka); err != nil {
				return
			}
			if err = rc.Flush(); err != nil {
				return
			}
			if r.Context().Err() != nil {
				return
			}
			vConn.updateActive()
			vConn.writeBuf.waitDispatchable(r.Context(), streamKeepaliveInterval, myDownSeq)
			continue
		}

		frame, err := streamFrameBytes(myDownSeq, vConn.consumedUpSeq(), downData)
		// streamFrameBytes copies the payload out, so the pooled buffer can
		// go back right away — this also satisfies HTTP/3's write-slice
		// retention without the special-case copy the poll path needs.
		safelyPutSendBuf(downBufPtr)
		if err != nil {
			return
		}
		if _, err := w.Write(frame); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		vConn.updateActive()
	}
}

// serveStreamUplink implements the stream-mode uplink: one long POST whose
// body is a continuous frame stream. It returns when the client ends the
// tunnel, so it must run before the bounded-body poll path.
func serveStreamUplink(w http.ResponseWriter, r *http.Request, st *serverState, vConn *meekVirtualConn, sessionID string) {
	logger := st.lg()
	defer r.Body.Close()

	for {
		f, err := readStreamFrame(r.Body)
		if err != nil {
			if r.Context().Err() != nil || (r.Header.Get("X-Stream-Resume") == "1" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))) {
				// A transport round ended, not the application session. Preserve
				// acknowledged bytes for the replacement POST; explicit markers
				// below still close normally. Legacy clients retain EOF semantics.
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// Client ended the uplink: normal tunnel close or connection
				// loss. Either way the session cannot make progress — closing
				// (not just requestClose) makes the downlink loop ship its
				// close marker so the client's reader finishes promptly.
				logger.Debug("📡 [Stream] uplink stream ended", zap.String("session", sessionID))
				vConn.Close()
				return
			}
			logger.Warn("⚠️ [Stream] failed to parse uplink frame", zap.String("session", sessionID), zap.Error(err))
			vConn.Close()
			return
		}
		vConn.updateActive()
		// The metadata ack records the client's downlink progress; the
		// downlink writer's GetSlice frees acknowledged bytes based on it.
		vConn.noteDownPeerAck(f.ack)
		if f.closed {
			logger.Debug("📡 [Stream] uplink stream carried a close marker", zap.String("session", sessionID))
			vConn.Close()
			return
		}
		if len(f.data) > 0 {
			// A frame whose sequence is entirely below the read cursor is a
			// duplicate retransmission: normal transport behaviour, but worth
			// surfacing at a high rate (possible replay probing).
			consumed := vConn.consumedUpSeq()
			if f.seq <= consumed && uint64(len(f.data)) <= consumed-f.seq {
				st.events.emit(ReplayDropped{SessionID: sessionID, Seq: f.seq})
			}
			// The client dedups by sequence; PutReadData may block here to
			// apply backpressure when the target drains slowly — that is the
			// transport's flow control working as designed.
			if _, err := vConn.PutReadDataContext(r.Context(), f.seq, f.data); err != nil {
				return
			}
		}
	}
}

// closeMarkerPayload is the payload that, when it flows through a session
// into the peer's frame parser, signals tunnel EOF (same wire marker the poll
// mode's WriteCloseFrame produces).
var closeMarkerPayload = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
