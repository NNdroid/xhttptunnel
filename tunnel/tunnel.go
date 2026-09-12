// Package tunnel exposes the xhttptunnel Split-HTTP/meek transport as an
// embeddable Go library.
//
// The client side is a net.Dialer-style primitive: [Client.DialContext] opens
// a tunnelled stream to a remote service through a xhttptunnel server, so it
// plugs directly into http.Transport, gRPC, database drivers and anything
// else that accepts a dial function. [Client.ListenAndServe] additionally
// provides the same local TCP/UDP forwarder the xhttptunnel CLI runs.
//
// The server side terminates the Split-HTTP protocol and bridges sessions to
// local services. [Server] wraps the low-level [ListenXHTTP] listener with
// the accept/target-bridge loop the CLI runs; passing a non-nil
// [ServerConfig.Handler] replaces that bridge with custom logic.
//
// Low-level building blocks ([DialXHTTP], [ListenXHTTP], [XHTTPConn]) remain
// exported for custom wiring on top of the protocol.
//
// # Logging
//
// The package logs through a single package-level logger that defaults to a
// no-op logger — a library must not write to stderr uninvited. Call
// [SetLogger] (or set Logger on ClientConfig/ServerConfig) to receive the
// debug/audit trail the CLI prints.
package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Version is stamped into the client User-Agent string. The CLI sets it from
// its linker-injected version; library builds default to "dev". Like
// SetLogger, it is an unsynchronized package global: set it during process
// startup, before any Client or Server is constructed.
var Version = "dev"

// clientUserAgent is the User-Agent every client request (poll, stream GET
// and stream POST) presents. It must stay consistent with the TLS
// fingerprint the dialer advertises (utls.HelloChrome_Auto): the current
// value identifies an Android WebView (Chrome 151), matching the mobile
// camouflage this deployment targets.
const clientUserAgent = "Mozilla/5.0 (Linux; Android 15; SM-A057G Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7922.202 Mobile Safari/537.36 w2n/Android"

// Sentinel errors the library returns for programmatically actionable
// conditions. Check with errors.Is; the concrete error may carry more detail.
var (
	// ErrSessionLimit is returned by Client dials (and surfaces as a closed
	// local connection in ListenAndServe) when ClientConfig.MaxConns sessions
	// are already open.
	ErrSessionLimit = errors.New("tunnel session limit reached")
)

// logger is the package-wide sink for all internal logging. It starts as a
// no-op so embedding processes are silent until they opt in via SetLogger.
var logger = zap.NewNop()

// loggerPkg returns the current package-wide logger. Internal helper for
// nil-logger fallbacks in low-level construction paths.
func loggerPkg() *zap.Logger { return logger }

// noteDownPeerAck records the peer's acknowledgement of our downlink stream.
// Used by AcquireDownWriter to rewind the cursor on writer takeover.
func (c *meekVirtualConn) noteDownPeerAck(ack uint64) {
	for {
		old := c.downPeerAck.Load()
		if ack <= old || c.downPeerAck.CompareAndSwap(old, ack) {
			return
		}
	}
}

// consumedUpSeq reports how many uplink bytes the session has fully consumed
// (the next expected uplink sequence). Stream-mode responses echo it in the
// metadata ack so the client's write buffer can release acknowledged bytes.
func (c *meekVirtualConn) consumedUpSeq() uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	return c.nextReadSeq
}

// ResetDownCursor rewinds the client-side downlink bookkeeping to seq so a
// recreated session's frames (which restart at zero) are accepted instead of
// being deduplicated away as stale retransmissions.
func (c *meekVirtualConn) ResetDownCursor(seq uint64) {
	c.readCond.L.Lock()
	c.nextReadSeq = seq
	c.oooBuf = make(map[uint64][]byte)
	c.oooBytes = 0
	c.readCond.Broadcast()
	c.readCond.L.Unlock()
}

// sessionEventHub delivers typed session events on a dedicated goroutine,
// never on the HTTP handler path. Emissions are non-blocking (dropped when
// the buffer is full); a panicking handler is contained by recover.
type sessionEventHub struct {
	mu      sync.Mutex
	ch      chan SessionEvent
	handler SessionEventHandler
	closed  bool
	wg      sync.WaitGroup
}

func newSessionEventHub(handler SessionEventHandler) *sessionEventHub {
	if handler == nil {
		return nil
	}
	h := &sessionEventHub{ch: make(chan SessionEvent, 64), handler: handler}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for ev := range h.ch {
			func() {
				defer func() { _ = recover() }()
				h.handler(ev)
			}()
		}
	}()
	return h
}

// emit queues ev for delivery; never blocks the HTTP handler path. A nil hub
// (no handler configured) makes this a no-op. The mutex pairs with close():
// without it a send racing the channel close would panic.
func (h *sessionEventHub) emit(ev SessionEvent) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	select {
	case h.ch <- ev:
	default:
	}
}

// close stops delivery and lets the dispatcher drain whatever is buffered
// before exiting. Safe to call on a nil hub and repeatedly.
func (h *sessionEventHub) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	close(h.ch)
}

// strconvParseUint is a small wrapper keeping strconv out of stream_server's
// hot imports while preserving parse-failure-as-zero semantics.
func strconvParseUint(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// SetLogger installs the package-wide logger used by every tunnel component.
// Passing nil restores the no-op default. The logger is process-wide: a
// ClientConfig/ServerConfig Logger field routes through this as well, so the
// last configuration wins. Call it during startup, before any Client or
// Server is constructed — concurrent SetLogger/reads are not synchronized.
func SetLogger(l *zap.Logger) {
	if l == nil {
		logger = zap.NewNop()
		return
	}
	logger = l
}

// stringAddr is a net.Addr backed by a plain string. It labels the virtual
// endpoints reported by tunnelled connections, which own no real socket.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SetChunkSizeKB caps the upstream payload carried by one poll request, in
// kilobytes. Values are clamped to [16, 900]: 16KB is the smallest useful
// block and 900KB keeps a frame safely under the 1MB body limit that nginx
// and many CDN/WAF tiers enforce. 0 restores the 256KB default.
// ClientConfig.ChunkSizeKB overrides this default for one client.
func SetChunkSizeKB(kb int) {
	maxsendBufSize.Store(int64(chunkSizeBytes(kb)))
}

func chunkSizeBytes(kb int) int {
	if kb <= 0 {
		kb = defaultChunkSize / 1000
	}
	if kb < 16 {
		kb = 16
	}
	if kb > 900 {
		kb = 900
	}
	return kb * 1000
}

const defaultMaxSessions = 2000

// ProtoHeader advertises the wire-protocol generation a request speaks and is
// echoed by the server in every response. Bumping tunnelProtoVersion is the
// single place to change when a frame-format revision lands; clients refuse
// servers that report a newer generation rather than corrupting silently.
const (
	ProtoHeader        = "X-XHTTP-Proto"
	tunnelProtoVersion = 1
)

// errProtoTooNew reports a server speaking a protocol generation this client
// predates. Distinct from the "unavailable → fall back" signal because a
// newer wire format must not be polled by an older client.
var errProtoTooNew = errors.New("tunnel: server reports a newer protocol version than this client supports")

// checkServerProto rejects responses that advertise a protocol generation
// newer than tunnelProtoVersion. An absent header is treated as the oldest
// generation (legacy server), so it is always acceptable.
func checkServerProto(h http.Header) error {
	v := h.Get(ProtoHeader)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= tunnelProtoVersion {
		return nil
	}
	return fmt.Errorf("%w (server %d, client %d)", errProtoTooNew, n, tunnelProtoVersion)
}

// TunnelStats is the monotonic snapshot reported by Server.Stats and the
// optional health endpoint. Counters never reset; ActiveSessions is the live
// registry size.
type TunnelStats struct {
	ActiveSessions   int    `json:"active_sessions"`
	SessionsTotal    uint64 `json:"sessions_total"`
	SessionsRejected uint64 `json:"sessions_rejected"`
	SessionsKicked   uint64 `json:"sessions_kicked"`
	SessionsReaped   uint64 `json:"sessions_reaped"`
	RequestsTotal    uint64 `json:"requests_total"`
	ProtoVersion     int    `json:"proto_version"`
}

func (st *serverState) snapshot() TunnelStats {
	st.sessionsMu.RLock()
	active := len(st.sessions)
	st.sessionsMu.RUnlock()
	return TunnelStats{
		ActiveSessions:   active,
		SessionsTotal:    st.stats.sessionsTotal.Load(),
		SessionsRejected: st.stats.sessionsReject.Load(),
		SessionsKicked:   st.stats.sessionsKicked.Load(),
		SessionsReaped:   st.stats.sessionsReaped.Load(),
		RequestsTotal:    st.stats.requests.Load(),
		ProtoVersion:     tunnelProtoVersion,
	}
}

// serverState holds the mutable policy and the session registry of one
// server. It exists so several servers can run side by side in one process:
// the low-level ListenXHTTP keeps using defaultServerState (its historical
// process-global behaviour), while Server gives every instance its own state.
type serverState struct {
	sessionsMu  sync.RWMutex
	sessions    map[string]*meekVirtualConn
	maxSessions int
	// maxPerIP bounds sessions from one client address (0 = unlimited). The
	// global cap alone lets a single PSK holder — or one compromised machine —
	// starve everyone else out of the registry.
	maxPerIP int
	// perIP counts live sessions by client IP (host part of remoteAddr).
	perIP map[string]int
	// minProto rejects requests whose advertised X-XHTTP-Proto is below this
	// (0 = accept everything, including legacy clients that send no header).
	minProto int
	// stats are monotonic counters surfaced by Server.Stats and the optional
	// health endpoint. Atomic so the read side never takes sessionsMu.
	stats struct {
		sessionsTotal  atomic.Uint64
		sessionsReject atomic.Uint64
		sessionsKicked atomic.Uint64
		sessionsReaped atomic.Uint64
		requests       atomic.Uint64
	}
	// healthPath ("" = disabled) serves a JSON snapshot of stats on GET,
	// outside the tunnel path and without authentication — intended for
	// localhost/operator use.
	healthPath string
	// events delivers typed session events to the embedder's handler. Nil
	// until Server.SetEventHandler (or a configured EventHandler) starts it.
	events *sessionEventHub
	// customLog is the per-server logger from ServerConfig.Logger; nil means
	// "inherit the package logger" (which SetLogger may still replace).
	customLog *zap.Logger

	// allowedTargets restricts which forwarding targets a client may request.
	// An entry matches when it equals the target exactly, ends with ":port"
	// (any host on that port), or starts with "host:" (any port on that host).
	// An empty list means every target is allowed. Atomic publication keeps
	// active request handlers safe if an embedding process reloads config.
	allowed atomic.Pointer[[]string]

	// trustProxyHeaders controls whether client-supplied proxy headers
	// (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are honoured when logging
	// the client address. They are trivially spoofable, so this is OFF by
	// default: RemoteAddr is used instead. Turn it on ONLY when the server is
	// reachable exclusively through a trusted reverse proxy / CDN that strips
	// these headers on ingress. Never enable it for direct public exposure.
	trustProxy atomic.Bool

	cleanerOnce sync.Once
	stopOnce    sync.Once
	// stopCleaner terminates the session reaper when closed. The package
	// default state never has it closed: its reaper runs for the lifetime of
	// the process, preserving the historical semantics for ListenXHTTP users.
	stopCleaner chan struct{}
}

// lg returns the instance logger, falling back to the package logger when
// no per-instance one was configured.
func (st *serverState) lg() *zap.Logger {
	if st.customLog != nil {
		return st.customLog
	}
	return logger
}

func newServerState(maxSessions int) *serverState {
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	return &serverState{
		sessions:    make(map[string]*meekVirtualConn),
		perIP:       make(map[string]int),
		maxSessions: maxSessions,
		stopCleaner: make(chan struct{}),
	}
}

// defaultServerState backs the legacy low-level API (ListenXHTTP plus the
// package-level Set* functions below). Its reaper is never stopped — the
// historical process-global behaviour — and nothing in the package calls
// stop() on it.
var defaultServerState = newServerState(0)

// SetAllowedTargets installs the target allowlist used by servers created via
// the low-level ListenXHTTP entry point. Server instances carry their own
// allowlist through ServerConfig.AllowedTargets. An empty list allows all.
// Deprecated: configures the shared low-level ListenXHTTP state; use
// ServerConfig.AllowedTargets / ServerConfig.TrustProxyHeaders instead.
func SetAllowedTargets(targets []string) { defaultServerState.setAllowedTargets(targets) }

// AllowedTargets returns the allowlist installed with SetAllowedTargets.
// Deprecated: configures the shared low-level ListenXHTTP state; use
// ServerConfig.AllowedTargets / ServerConfig.TrustProxyHeaders instead.
func AllowedTargets() []string { return defaultServerState.currentAllowedTargets() }

// SetTrustProxyHeaders toggles proxy-header trust for servers created via the
// low-level ListenXHTTP entry point. Server instances configure this through
// ServerConfig.TrustProxyHeaders.
// Deprecated: configures the shared low-level ListenXHTTP state; use
// ServerConfig.AllowedTargets / ServerConfig.TrustProxyHeaders instead.
func SetTrustProxyHeaders(trust bool) { defaultServerState.trustProxy.Store(trust) }

// TrustProxyHeaders reports the proxy-header trust flag of the default state.
// Deprecated: configures the shared low-level ListenXHTTP state; use
// ServerConfig.AllowedTargets / ServerConfig.TrustProxyHeaders instead.
func TrustProxyHeaders() bool { return defaultServerState.trustProxy.Load() }

// TargetAllowed reports whether a client-requested forwarding target may be
// dialed under the default state's allowlist.
// Deprecated: configures the shared low-level ListenXHTTP state; use
// ServerConfig.AllowedTargets / ServerConfig.TrustProxyHeaders instead.
func TargetAllowed(target string) bool { return defaultServerState.targetAllowed(target) }

func (st *serverState) setAllowedTargets(targets []string) {
	if len(targets) == 0 {
		st.allowed.Store(nil)
		return
	}
	cloned := append([]string(nil), targets...)
	st.allowed.Store(&cloned)
}

func (st *serverState) currentAllowedTargets() []string {
	targets := st.allowed.Load()
	if targets == nil {
		return nil
	}
	return *targets
}

// targetAllowed reports whether a client-requested forwarding target may be
// dialed. Allowlist entries support three forms: "host:port" (exact),
// ":port" (any host on that port) and "host:" (any port on that host).
func (st *serverState) targetAllowed(target string) bool {
	targets := st.currentAllowedTargets()
	if len(targets) == 0 {
		return true
	}
	for _, entry := range targets {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.HasSuffix(entry, ":") && strings.HasPrefix(target, entry) {
			return true
		}
		if strings.HasPrefix(entry, ":") && strings.HasSuffix(target, entry) {
			return true
		}
		if target == entry {
			return true
		}
	}
	return false
}

func (st *serverState) getClientIP(r *http.Request) string {
	// Proxy headers are client-controlled and therefore untrusted. Only read
	// them when the operator has explicitly opted in via trust_proxy_headers
	// (meaning a trusted CDN/proxy is known to strip them on ingress).
	if st.trustProxy.Load() {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	return r.RemoteAddr
}

func (st *serverState) getSession(id string) (*meekVirtualConn, bool) {
	st.sessionsMu.RLock()
	defer st.sessionsMu.RUnlock()
	v, ok := st.sessions[id]
	return v, ok
}

// addSession registers a new session unless the registry is full.
func (st *serverState) addSession(id string, v *meekVirtualConn) bool {
	st.sessionsMu.Lock()
	defer st.sessionsMu.Unlock()
	if len(st.sessions) >= st.maxSessions {
		return false
	}
	st.sessions[id] = v
	return true
}

// ipOnly strips the port from a client address ("1.2.3.4:5678" → "1.2.3.4",
// "[::1]:443" → "::1"); a bare IP passes through. Unparseable values become
// "" so they collapse into one shared bucket rather than fragmenting the
// per-IP accounting.
func ipOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	if addr != "" && !strings.Contains(addr, ":") {
		return addr
	}
	return ""
}

// removeSessionLocked unregisters a session and decrements its per-IP tally.
// Callers must hold sessionsMu and must have looked the session up first.
func (st *serverState) removeSessionLocked(id string) {
	v := st.sessions[id]
	delete(st.sessions, id)
	if v != nil && v.remote != nil && st.perIP != nil {
		if ip := ipOnly(v.remote.String()); ip != "" {
			if st.perIP[ip] <= 1 {
				delete(st.perIP, ip)
			} else {
				st.perIP[ip]--
			}
		}
	}
}

func (st *serverState) removeSession(id string) {
	st.sessionsMu.Lock()
	st.removeSessionLocked(id)
	st.sessionsMu.Unlock()
}

// SessionIDs lists the session IDs currently registered.
func (st *serverState) SessionIDs() []string {
	st.sessionsMu.RLock()
	defer st.sessionsMu.RUnlock()
	ids := make([]string, 0, len(st.sessions))
	for id := range st.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Kick closes the named session and removes it from the registry. It reports
// whether the session existed. In-flight polls for the session fail on their
// next round; the client re-establishes if it is still alive.
func (st *serverState) Kick(id string) bool {
	st.sessionsMu.Lock()
	v, ok := st.sessions[id]
	if ok {
		st.removeSessionLocked(id)
	}
	st.sessionsMu.Unlock()
	if ok {
		st.stats.sessionsKicked.Add(1)
		// Mark the kick so a streaming downlink ends its response WITHOUT the
		// close marker: marker means "session over, stop reconnecting", while
		// a kicked client must transparently re-establish (poll parity).
		v.kicked.Store(true)
		st.lg().Debug("👢 [Server] 会话被管理员踢除", zap.String("session", id))
		v.Close()
	}
	return ok
}

// KickAll closes and removes every registered session. Returns the number of
// sessions kicked.
func (st *serverState) KickAll() int {
	st.sessionsMu.Lock()
	victims := make([]*meekVirtualConn, 0, len(st.sessions))
	for id, v := range st.sessions {
		victims = append(victims, v)
		st.removeSessionLocked(id)
	}
	st.sessionsMu.Unlock()
	for _, v := range victims {
		v.kicked.Store(true)
		v.Close()
	}
	if len(victims) > 0 {
		st.stats.sessionsKicked.Add(uint64(len(victims)))
		st.lg().Debug("👢 [Server] 全部会话被管理员踢除", zap.Int("count", len(victims)))
	}
	return len(victims)
}

// startSessionCleaner launches the idle-session reaper for this state. The
// reaper is idempotent per state and runs detached from any listener
// context: binding it to one meant that the first server to shut down (a
// test, a graceful restart) killed the only reaper for the lifetime of the
// process, after which stale sessions accumulated forever.
func (st *serverState) startSessionCleaner() {
	st.cleanerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(cleanerInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					st.sweepIdleSessions()
				case <-st.stopCleaner:
					return
				}
			}
		}()
	})
}

func (st *serverState) sweepIdleSessions() {
	now := time.Now().Unix()
	st.sessionsMu.Lock()
	defer st.sessionsMu.Unlock()
	for id, v := range st.sessions {
		if now-atomic.LoadInt64(&v.lastActive) > int64(sessionIdleTimeout.Seconds()) {
			logger.Debug("🧹 [Cleaner] 发现过期会话，清理释放资源", zap.String("session", id))
			st.events.emit(SessionClosed{SessionID: id, Reason: "reaped"})
			st.stats.sessionsReaped.Add(1)
			v.Close()
			st.removeSessionLocked(id)
		}
	}
}

// stop halts the reaper and force-closes every session still registered. It
// is safe to call concurrently and repeatedly. The package default state
// never has stop() called on it, preserving the historical immortal-reaper
// behaviour for ListenXHTTP users.
func (st *serverState) stop() {
	st.stopOnce.Do(func() {
		close(st.stopCleaner)
		// Stop the session-event dispatcher: without this a server that
		// registered a handler leaks its goroutine (blocked on range h.ch)
		// for the rest of the process lifetime.
		st.events.close()
		st.sweepAllSessions()
	})
}

func (st *serverState) sweepAllSessions() {
	st.sessionsMu.Lock()
	defer st.sessionsMu.Unlock()
	for id, v := range st.sessions {
		v.Close()
		st.removeSessionLocked(id)
	}
}
