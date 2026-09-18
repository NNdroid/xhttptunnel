package tunnel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	// longPollTimeout is how long a poll request parks on the server waiting
	// for downlink data. It has to stay well below CDN/nginx idle timeouts
	// (Cloudflare 524 fires at 100s, nginx proxy_read_timeout defaults to 60s)
	// while being long enough to amortise request overhead. The client's
	// close-flush grace is derived from this value.
	longPollTimeout = 5 * time.Second
	// serverDrainTimeout bounds how long a closing session waits for an
	// in-flight poll to pick up its final bytes (the close frame) before it is
	// removed from the registry and freed.
	serverDrainTimeout = 2 * time.Second
	// cleanerInterval is how often the session reaper sweeps the registry.
	cleanerInterval = 1 * time.Minute
	// sessionIdleTimeout is how long a session may go without a single poll
	// before the reaper drops it. It has to exceed the client's poll cadence
	// by a wide margin so a merely quiet tunnel is never mistaken for a dead
	// one.
	sessionIdleTimeout = 120 * time.Second
)

type XHTTPListener struct {
	// RequestCount MUST stay the first field. On 32-bit targets (386/arm) a
	// plain uint64 accessed with atomic.AddUint64 traps with "unaligned 64-bit
	// atomic operation" unless it sits on an 8-byte boundary. The Go memory
	// model guarantees the first word of an allocated struct is 8-byte aligned,
	// so keeping it first makes the atomic op safe without changing the public
	// uint64 type. Do not reorder fields above it.
	RequestCount uint64

	connCh        chan *XHTTPConn
	ln            net.Listener
	uln           net.PacketConn
	srvTCP        bool
	srvUDP        bool
	expectedToken string
	// chOnly marks a listener that exists only for its session channel (the
	// mounted Server.Handler mode). Closing it closes the channel so an
	// external drain loop can exit; there are no sockets to release.
	chOnly bool
}

func (l *XHTTPListener) Accept(ctx context.Context) (net.Conn, error) {
	select {
	case conn, ok := <-l.connCh:
		if !ok {
			return nil, fmt.Errorf("closed")
		}
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (l *XHTTPListener) Close() error {
	// A udp://-only listener never touches l.ln; guard both handles so
	// shutdown does not panic and always tears down what is open. A chOnly
	// listener closes its session channel to release the drain loop.
	var err error
	if l.chOnly {
		select {
		case <-l.connCh:
		default:
			close(l.connCh)
		}
		return nil
	}
	if l.ln != nil {
		err = l.ln.Close()
	}
	if l.uln != nil {
		if e := l.uln.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (l *XHTTPListener) Addr() net.Addr {
	if l.ln != nil {
		return l.ln.Addr()
	}
	if l.uln != nil {
		return l.uln.LocalAddr()
	}
	return nil
}

type ActiveTracker struct {
	wg sync.WaitGroup
	// n must be atomic.Int64, not int64: on 32-bit targets a plain int64
	// reached via atomic.AddInt64/LoadInt64 traps with "unaligned 64-bit
	// atomic operation". atomic.Int64 is always 8-byte aligned.
	n     atomic.Int64
	quiet chan struct{}
}

func NewActiveTracker() *ActiveTracker {
	return &ActiveTracker{quiet: make(chan struct{})}
}

func (t *ActiveTracker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.n.Add(1)
		t.wg.Add(1)
		defer func() {
			t.wg.Done()
			if t.n.Add(-1) == 0 {
				select {
				case <-t.quiet:
				default:
					close(t.quiet)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (t *ActiveTracker) Wait(ctx context.Context) error {
	if t.n.Load() == 0 {
		return nil
	}
	select {
	case <-t.quiet:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *ActiveTracker) Active() int64 { return t.n.Load() }

func nginxError(w http.ResponseWriter, code int) {
	statusText := http.StatusText(code)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<html>\n<head><title>%d %s</title></head>\n", code, statusText)
	fmt.Fprintln(w, "<body>")
	fmt.Fprintf(w, "<center><h1>%d %s</h1></center>\n", code, statusText)
	fmt.Fprintln(w, "<hr><center>nginx</center>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
}

func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("💀 [HTTP] Handler recovered from panic", zap.Any("panic", err), zap.Stack("stack"))
				nginxError(w, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

const (
	NetTCP  = "tcp"
	NetUDP  = "udp"
	NetBoth = "tcp+udp"
)

func ParseListenAddr(listenAddr string) (string, string) {
	schemes := map[string]string{
		"tcp://":     NetTCP,
		"udp://":     NetUDP,
		"tcp+udp://": NetBoth,
	}

	for scheme, netType := range schemes {
		if strings.HasPrefix(listenAddr, scheme) {
			return strings.TrimPrefix(listenAddr, scheme), netType
		}
	}

	return listenAddr, NetBoth
}

// constTimeEqual compares two strings without leaking where they first differ.
func constTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// redactAuth renders a credential header safe for logging as "<scheme> <n bytes>".
// The header carries the shared PSK in cleartext ("Bearer <token>"), and debug
// logs routinely end up in bug reports and log collectors, so it must never be
// written out verbatim — the length is all a human ever needs to tell whether
// a client sent credentials at all.
func redactAuth(header string) string {
	if header == "" {
		return "-"
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found {
		return fmt.Sprintf("<%d bytes>", len(header))
	}
	return fmt.Sprintf("%s <%d bytes>", scheme, len(token))
}

// describeAuth renders the credential a request presented, redacted. A v2
// client sends no key at all, so Proxy-Authorization alone is "-": this
// distinguishes a signed request from an unsigned one, which is what an
// operator needs to see when debugging why a client was refused. The nonce is
// logged verbatim because it is public by design — it is the value the replay
// window is keyed on — while the digest is reduced to its byte length.
func describeAuth(r *http.Request) string {
	if mac := r.Header.Get(AuthMACHeader); mac != "" {
		return fmt.Sprintf("signed nonce=%s mac=%d bytes", r.Header.Get(AuthNonceHeader), len(mac))
	}
	return redactAuth(r.Header.Get("Proxy-Authorization"))
}

// tunnelRequestHeaders is every header this protocol uses to carry session or
// policy state. The fallback proxy forwards camouflage traffic to an external
// site, so none of them may leave the origin. X-Auth-Token matters most: it
// carries the bare pre-shared key (Proxy-Authorization is hop-by-hop and Go's
// ReverseProxy already strips it, which is exactly why this duplicate exists),
// and X-Target names the internal address clients are dialing through.
var tunnelRequestHeaders = []string{
	"X-Auth-Token",
	AuthNonceHeader,
	AuthMACHeader,
	"X-Target",
	"X-Network",
	"X-Session-ID",
	ProtoHeader,
	"X-Seq",
	"X-Ack",
	"X-Retry",
	"X-Downstream",
	"X-Stream-Resume",
}

// scrubTunnelRequest strips protocol state before a request leaves the origin
// through the fallback proxy. The body is emptied as well: it carries raw
// tunnel frames, which a disguise site has no business parsing. The method is
// kept so the forwarded request still looks like an ordinary web request.
func scrubTunnelRequest(req *http.Request) {
	for _, h := range tunnelRequestHeaders {
		req.Header.Del(h)
	}
	if req.Body != nil && req.Body != http.NoBody {
		_ = req.Body.Close()
	}
	req.Body = http.NoBody
	req.ContentLength = 0
	req.GetBody = nil
}

// authorize decides whether one request may use this tunnel. Two credential
// shapes are accepted:
//
//   - v2, the signed path: X-HTTP-Tunnel-Nonce plus X-HTTP-Tunnel-MAC. The
//     PSK never crosses the wire, and the nonce stops the request from being
//     replayed. This is the only path a current client uses.
//   - legacy, the bare path: the PSK itself in Proxy-Authorization or
//     X-Auth-Token. Kept only so a fleet can be upgraded in place — servers
//     first, clients after — instead of having to restart every client at once.
//
// Either credential is sufficient, so an in-flight session is not cut when its
// endpoint is upgraded. To retire the legacy path set min_proto_version to 2:
// a v2 client that does not sign is refused below rather than downgraded, so
// that setting genuinely closes the bare-token hole.
func (st *serverState) authorize(r *http.Request, expected string) bool {
	if requiresMAC(r) {
		// This client announced the signed generation, so it commits to it: the
		// bare-token path is closed to it. Without this rule min_proto_version
		// would be a gate with a hole — a v2 client could keep replayable
		// credentials and still satisfy the minimum, so rotating the PSK would
		// read as a success.
		return st.authorizeByMAC(r, expected, r.Header.Get(AuthMACHeader))
	}
	if mac := r.Header.Get(AuthMACHeader); mac != "" {
		// A legacy-generation client that still signs is a migration hybrid.
		// Take the signature; if it is wrong, fall through to the bare token
		// rather than treating it as a protocol error.
		if st.authorizeByMAC(r, expected, mac) {
			return true
		}
	}
	return st.authorizeByToken(r, expected)
}

// requiresMAC reports whether a request announced the signed protocol
// generation. A request that sends no X-XHTTP-Proto at all is a pre-v2 client
// and is not held to it, which is what keeps the dual-mode window open.
func requiresMAC(r *http.Request) bool {
	v, err := strconv.Atoi(r.Header.Get(ProtoHeader))
	return err == nil && v >= offeredProtoVersion
}

func (st *serverState) authorizeByMAC(r *http.Request, expected, mac string) bool {
	nonce := r.Header.Get(AuthNonceHeader)
	if !validAuthNonce(nonce) {
		return false
	}
	// The session id and target are bound into the signature so a valid
	// request cannot be replayed against a different session or aimed at a
	// different address. They are read from the headers, not from local state,
	// so the value verified here is exactly the value the dispatcher uses.
	msg := authMessage(nonce, r.Header.Get("X-Session-ID"), r.Header.Get("X-Target"))
	for _, tok := range splitTokens(expected) {
		if tok == "" {
			continue
		}
		if authMACMatches(tok, msg, mac) {
			// Consume the nonce only after the signature checks out: a caller
			// who cannot sign must not be able to fill the window and evict
			// legitimate requests by flooding it.
			return st.nonces.mark(nonce)
		}
	}
	return false
}

func (st *serverState) authorizeByToken(r *http.Request, expected string) bool {
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("Authorization")
	}
	customTokenHeader := r.Header.Get("X-Auth-Token")
	for _, tok := range splitTokens(expected) {
		if tok == "" {
			continue
		}
		// Compared in constant time: a plain == short-circuits on the first
		// differing byte, which hands an attacker a byte-at-a-time oracle on
		// the shared secret.
		if constTimeEqual(authHeader, "Bearer "+tok) ||
			constTimeEqual(authHeader, tok) ||
			constTimeEqual(customTokenHeader, tok) {
			return true
		}
	}
	return false
}

// splitTokens splits a configured PSK list on commas and trims each element.
// Empty elements are left in place so callers can skip them explicitly.
func splitTokens(expected string) []string {
	parts := strings.Split(expected, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// buildSessionHandler assembles the Split-HTTP session handler: the mux that
// authenticates polls, feeds the session registry and bridges long polls, plus
// the fallback camouflage and panic/active middleware. It is shared by
// listenXHTTP (self-hosted mode) and Server.Handler (mount-your-own mode), so
// both paths exercise identical session semantics.
func buildSessionHandler(xl *XHTTPListener, st *serverState, path, token, fallbackURL string) http.Handler {
	logger := st.lg()
	var fallbackProxy *httputil.ReverseProxy
	if fallbackURL != "" {
		if u, err := url.Parse(fallbackURL); err == nil {
			fallbackProxy = httputil.NewSingleHostReverseProxy(u)
			originalDirector := fallbackProxy.Director
			fallbackProxy.Director = func(req *http.Request) {
				originalDirector(req)
				req.Host = u.Host
				scrubTunnelRequest(req)
			}
			logger.Info("🛡️ fallback camouflage site enabled", zap.String("target", fallbackURL))
		} else {
			logger.Warn("❌ failed to parse fallback URL", zap.Error(err))
		}
	}

	mux := http.NewServeMux()
	if healthPath := st.healthPath; healthPath != "" {
		mux.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				nginxError(w, http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st.snapshot())
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := st.getClientIP(r)
		// Per-request hot path: level-check first so the Field slice and the
		// redaction are skipped when debug logging is off.
		if ce := logger.Check(zap.DebugLevel, "👀 [HTTP] received raw HTTP request"); ce != nil {
			ce.Write(
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote", clientIP),
				zap.String("session", r.Header.Get("X-Session-ID")),
				zap.String("auth", describeAuth(r)),
			)
		}
		if r.URL.Path != path {
			// This branch is silent by default, so a client configured with the
			// wrong path leaves no trace at all: the disguise site's status code
			// (often 403) comes back and the client reports it as a target
			// refusal. Debug level, because scanners hit non-tunnel paths
			// constantly.
			if ce := logger.Check(zap.DebugLevel, "🛡️ [HTTP] path mismatch, serving fallback camouflage"); ce != nil {
				ce.Write(
					zap.String("path", r.URL.Path),
					zap.String("want", path),
					zap.String("remote", clientIP),
				)
			}
			if fallbackProxy != nil {
				fallbackProxy.ServeHTTP(w, r)
				return
			}
			nginxError(w, http.StatusNotFound)
			return
		}
		atomic.AddUint64(&xl.RequestCount, 1)
		st.stats.requests.Add(1)
		// Advertise this server's protocol generation and, when configured,
		// refuse clients that announced an older one than the operator allows.
		w.Header().Set(ProtoHeader, strconv.Itoa(tunnelProtoVersion))
		if st.minProto > 0 {
			if v, err := strconv.Atoi(r.Header.Get(ProtoHeader)); err != nil || v < st.minProto {
				logger.Warn("❌ [HTTP] rejected request: protocol version too old",
					zap.String("remote", clientIP),
					zap.String("client_proto", r.Header.Get(ProtoHeader)))
				http.Error(w, "upgrade required", http.StatusUpgradeRequired)
				return
			}
		}

		target := r.Header.Get("X-Target")
		// A "tcp://" prefix is resolved away before both the allowlist check
		// and the dial. Left in place the dialer would receive
		// "tcp://host:port" and fail with "too many colons". The strip also
		// means the prefix is dropped silently rather than honoured: the
		// client's protocol comes from X-Network, never from the target's
		// scheme, so gen-config refuses the prefix as decoration.
		_, authority := splitTargetScheme(target)
		target = authority
		network := r.Header.Get("X-Network")
		sessionID := r.Header.Get("X-Session-ID")

		if sessionID == "" {
			logger.Warn("❌ [HTTP] rejected request: missing Session ID", zap.String("remote", clientIP))
			nginxError(w, http.StatusBadRequest)
			return
		}
		if xl.expectedToken != "" && !st.authorize(r, xl.expectedToken) {
			logger.Warn("❌ [HTTP] rejected request: bad password or unauthorized",
				zap.String("remote", r.RemoteAddr),
				zap.Bool("signed", r.Header.Get(AuthMACHeader) != ""),
			)
			st.events.emit(AuthRejected{Remote: r.RemoteAddr, Path: r.URL.Path})
			nginxError(w, http.StatusProxyAuthRequired)
			return
		}

		if target == TargetBwExchange {
			if !st.brutalCfg.BWExchange {
				// The server does not participate in the exchange. Answer like
				// any unparseable target: the client probes once, sees a
				// non-200 and disables itself instead of retrying forever.
				nginxError(w, http.StatusNotFound)
				return
			}
			// The exchange carries no tunnel data and dials no address, so it
			// sits after authentication — the signed nonce binds this target
			// like any other — and before attachOrCreateSession, whose
			// allowlist is a policy for addresses, not protocol requests. It
			// registers no session, so it does not consume MaxSessions or the
			// per-IP budget.
			st.handleBwExchange(w, r, clientIP)
			return
		}

		// Lookup, policy check and registration must be atomic: the pump's
		// workers fire their first polls concurrently, and without one
		// critical section two of them could both miss the lookup and both
		// register, pushing two bridges for a single session. The stream
		// branch shares the same helper. A created session starts both
		// sequence spaces at zero; reconnecting clients detect that via the
		// hello frame and reset their own bookkeeping.
		vConn, created, status := st.attachOrCreateSession(xl, sessionID, target, network, r.Host, r.RemoteAddr, logger)
		if status != 0 {
			nginxError(w, status)
			return
		}

		// Stream-mode downlink: one persistent GET whose response body is a
		// continuous frame stream (SSE-style — the one full-duplex-ish shape
		// old proxies tolerate). Must run before the poll path below.
		if r.Method == http.MethodGet && r.Header.Get("X-Downstream") == "1" {
			serveStreamDownlink(w, r, st, vConn, sessionID, created)
			return
		}
		// Stream-mode uplink: one long POST whose body is a continuous frame
		// stream fed into the session. It returns only when the client ends
		// the tunnel, so it must run before the bounded-body poll path.
		if r.Header.Get("Content-Type") == streamContentType {
			// A stream frame can retain the full 4 MiB receive window while
			// blocked. Admit only one such producer per session so authenticated
			// request fan-out cannot multiply that retained heap by 16.
			if !vConn.streamUp.CompareAndSwap(0, 1) {
				nginxError(w, http.StatusTooManyRequests)
				return
			}
			defer vConn.streamUp.Store(0)
			vConn.signalStreamReady()
			serveStreamUplink(w, r, st, vConn, sessionID)
			return
		}

		// Bound poll request payloads/goroutines as well as the shared receive
		// window. The client uses at most eight concurrent poll workers.
		if vConn.uploads.Add(1) > 8 {
			vConn.uploads.Add(-1)
			nginxError(w, http.StatusTooManyRequests)
			return
		}
		defer vConn.uploads.Add(-1)

		cSeq, _ := strconv.ParseUint(r.Header.Get("X-Seq"), 10, 64)
		cAck, _ := strconv.ParseUint(r.Header.Get("X-Ack"), 10, 64)
		if !vConn.writeBuf.validAck(cAck) {
			nginxError(w, http.StatusBadRequest)
			return
		}
		vConn.noteDownPeerAck(cAck)

		bufPtr := sendBuf.Get().(*[]byte)
		readChunk := *bufPtr
		var totalUpBytes int
		var errBody error
		currentSeq := cSeq
		var myUpAck uint64

		for {
			n, err := r.Body.Read(readChunk)
			if n > 0 {
				myUpAck, errBody = vConn.PutReadDataContext(r.Context(), currentSeq, readChunk[:n])
				if errBody != nil {
					break
				}
				currentSeq += uint64(n)
				totalUpBytes += n
			}
			if err != nil {
				if err != io.EOF {
					errBody = err
				}
				break
			}
		}
		r.Body.Close()
		safelyPutSendBuf(bufPtr)

		if errBody != nil {
			logger.Warn("⚠️ [HTTP] failed to read uplink body or it ended unexpectedly", zap.Error(errBody))
			nginxError(w, http.StatusBadRequest)
			return
		}

		if totalUpBytes == 0 {
			myUpAck = vConn.PutReadData(cSeq, nil)
		}

		if ce := logger.Check(zap.DebugLevel, "📥 [HTTP] parsing uplink request"); ce != nil {
			ce.Write(
				zap.String("session", sessionID),
				zap.Uint64("Client_Seq", cSeq),
				zap.Uint64("Client_Ack", cAck),
				zap.Int("Up_Bytes", totalUpBytes),
				zap.Uint64("Server_Expect_Ack", myUpAck),
			)
		}

		var downData []byte
		var myDownSeq uint64
		var downBufPtr *[]byte

		fetchDownData := func() bool {
			vConn.downWindowMu.Lock()
			defer vConn.downWindowMu.Unlock()

			if vConn.downDispatchSeq < cAck || r.Header.Get("X-Retry") == "1" {
				vConn.downDispatchSeq = cAck
			}

			downData, myDownSeq, downBufPtr = vConn.writeBuf.GetSlice(cAck, vConn.downDispatchSeq, currentMaxSendBufSize())

			if len(downData) > 0 {
				vConn.downDispatchSeq = myDownSeq + uint64(len(downData))
				return true
			}

			vConn.downDispatchSeq = myDownSeq
			return false
		}

		// A streaming downlink response owns the dispatch cursor while it
		// lives; poll responses must not piggyback downlink alongside it or
		// the two writers would split the stream.
		if vConn.downWriterActive() {
			logger.Debug("📡 [HTTP] streaming downlink owns the session; this response will not piggyback downlink data", zap.String("session", sessionID))
		} else {
			if r.Method == http.MethodGet {
				// A poll GET briefly owns the cursor and evicts a streaming
				// writer if one is still attached (mode downgrade).
				ticket := &downWriterTicket{}
				vConn.AcquireDownWriter(ticket)
				defer vConn.ReleaseDownWriter(ticket)
			}
			if totalUpBytes > 0 {
				fetchDownData()
			} else {
				if !fetchDownData() && !vConn.isClosed() {
					vConn.writeBuf.waitLongPoll(r.Context(), longPollTimeout)
					fetchDownData()
				}
			}
		}

		// HTTP/3 cannot write straight out of the pooled buffer. quic-go's
		// send stream holds on to the slice given to ResponseWriter.Write
		// until it has been packetised, which happens after this handler
		// returns — so recycling it here would hand the buffer to another
		// session while QUIC is still reading from it. Give QUIC a private
		// copy and put the pooled one back immediately.
		// HTTP/1.1 (copies into the bufio writer) and HTTP/2 (writeDataFrom-
		// Handler blocks until the frame is on the wire) are both safe.
		if r.ProtoMajor == 3 && len(downData) > 0 {
			owned := make([]byte, len(downData))
			copy(owned, downData)
			safelyPutSendBuf(downBufPtr)
			downData, downBufPtr = owned, nil
		}

		if ce := logger.Check(zap.DebugLevel, "📤 [HTTP] preparing downlink response"); ce != nil {
			ce.Write(
				zap.String("session", sessionID),
				zap.Uint64("Server_Seq", myDownSeq),
				zap.Uint64("Server_Ack", myUpAck),
				zap.Int("Down_Bytes", len(downData)),
			)
		}

		// Key CDN / reverse-proxy traversal headers: disable CDN edge caching and intermediate buffering
		w.Header().Set("Cache-Control", "no-cache, no-store, no-transform, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "X-Seq, X-Ack, X-Session-ID, Content-Length")

		w.Header().Set("X-Ack", strconv.FormatUint(myUpAck, 10))
		w.Header().Set("X-Seq", strconv.FormatUint(myDownSeq, 10))
		w.Header().Set("Content-Length", strconv.Itoa(len(downData)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		if len(downData) > 0 {
			w.Write(downData)
		}

		safelyPutSendBuf(downBufPtr)
	})

	tracker := NewActiveTracker()
	return panicRecoveryMiddleware(tracker.Middleware(mux))
}

// handleBwExchange serves the bandwidth exchange. The caller reports how fast
// it can ingest, and this server applies that as its own send rate for the
// caller's connection group; the response carries this server's advertised
// ingest capacity in the same sense. Both sides converge on the slower link.
//
// The request registers no session: it opens no bridge and costs far less
// than a poll, so it does not draw on the session budget. It is still
// authenticated, and on the client side it is bounded by bw_interval, so the
// exchange cannot be used to probe the server at high rate.
func (st *serverState) handleBwExchange(w http.ResponseWriter, r *http.Request, clientIP string) {
	logger := st.lg()
	cfg := st.brutalCfg
	groupID := cfg.GroupID
	if cfg.GroupFromRemote {
		groupID = groupIDFromRemote(r.RemoteAddr)
	}
	if raw := r.Header.Get(BwHeader); raw != "" {
		v, ok := parseBwValue(raw)
		if ok {
			// The configured rate stays a ceiling, so a client can only lower
			// this server's send rate for its own group, never raise it — which
			// also bounds a hostile advertisement.
			st.setGroupRate(groupID, mergeBrutalRate(cfg.Rate, v))
		} else {
			// Invalid or out of range. Keep the rate that is in force: applying
			// zero would stall every connection in the group.
			logger.Warn("⚠️ [BW] ignoring an invalid bandwidth advertisement",
				zap.String("remote", clientIP), zap.String("value", raw))
		}
	}
	if ce := logger.Check(zap.DebugLevel, "📶 [BW] served a bandwidth exchange"); ce != nil {
		ce.Write(
			zap.String("remote", clientIP),
			zap.String("advertised", r.Header.Get(BwHeader)),
			zap.Uint64("group_id", groupID),
			zap.Uint64("rate", st.groupRate(groupID, cfg.Rate)),
		)
	}
	w.Header().Set(CapsHeader, CapBrutalBw)
	if cfg.BWAdvertise > 0 {
		w.Header().Set(BwHeader, strconv.FormatUint(cfg.BWAdvertise, 10))
	}
	// One tiny request per bw_interval; there is no reason to keep the socket
	// warm for it.
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
}

// ListenXHTTP starts the low-level Split-HTTP server listener. It keeps the
// historical process-global session registry and policy state; embedding
// processes that want instance isolation should use [Server] instead. The
// returned listener must be driven by an accept loop (see [Server]) that
// bridges accepted XHTTPConn sessions to their targets.
func ListenXHTTP(ctx context.Context, listenAddr, path, token, certFile, keyFile, fallbackURL string) (*XHTTPListener, error) {
	return listenXHTTP(ctx, listenAddr, path, token, certFile, keyFile, fallbackURL, defaultServerState)
}

func listenXHTTP(ctx context.Context, listenAddr, path, token, certFile, keyFile, fallbackURL string, st *serverState) (*XHTTPListener, error) {
	logger := st.lg()
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("TLS requires both cert and key files")
	}
	tlsEnabled := certFile != ""

	xl := &XHTTPListener{connCh: make(chan *XHTTPConn, 256), expectedToken: token}
	rListenAddr, rNetwork := ParseListenAddr(listenAddr)
	// HTTP/3 always uses QUIC over TLS. A cleartext origin behind a
	// TLS-terminating CDN must only bind TCP; keeping a UDP socket open there
	// wastes a port and falsely suggests that H3 is available.
	if !tlsEnabled {
		if rNetwork == NetUDP {
			return nil, fmt.Errorf("udp listener requires TLS because HTTP/3 requires TLS")
		}
		rNetwork = NetTCP
	}

	if rNetwork == NetTCP || rNetwork == NetBoth {
		ln, err := net.Listen("tcp", rListenAddr)
		if err != nil {
			return nil, err
		}
		// Wrapping the listener covers every TCP path that shares xl.ln —
		// ServeTLS and the h2c Serve both accept from it — and it happens
		// before the TLS handshake begins. Wrapping xl.uln would be wrong:
		// brutal caps TCP sockets, not the QUIC path.
		if apply := st.newBrutalServerApplier(); apply != nil {
			ln = newBrutalListener(ln, apply)
		}
		xl.ln = ln
		xl.srvTCP = true
	}
	if rNetwork == NetUDP || rNetwork == NetBoth {
		udpListenAddr := rListenAddr
		// Independent TCP and UDP :0 binds choose unrelated ports. H3 has to
		// use the same externally advertised port as HTTPS.
		if xl.ln != nil {
			udpListenAddr = xl.ln.Addr().String()
		}
		ln, err := net.ListenPacket("udp", udpListenAddr)
		if err != nil {
			if xl.ln != nil {
				_ = xl.ln.Close()
			}
			return nil, err
		}
		xl.uln = ln
		xl.srvUDP = true
	}

	// The session registry lives in the state; the reaper itself is started
	// at the end of this function, once every setup step that can fail has
	// succeeded, so a failed Listen call never leaks a reaper goroutine.

	handler := buildSessionHandler(xl, st, path, token, fallbackURL)

	server := &http.Server{
		IdleTimeout:       1 * time.Hour,
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout covers reading the request body, which is bounded by the
		// chunk size; WriteTimeout must comfortably exceed the long poll below
		// so parked requests are not cut off mid-flight.
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	var (
		connsMu sync.Mutex
		conns   = make(map[net.Conn]struct{})
	)
	server.ConnState = func(c net.Conn, state http.ConnState) {
		connsMu.Lock()
		defer connsMu.Unlock()
		switch state {
		case http.StateNew:
			conns[c] = struct{}{}
		case http.StateClosed, http.StateHijacked:
			delete(conns, c)
		}
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		logger.Info("🛑 shutdown signal received, gracefully closing HTTP server...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("⚠️ graceful shutdown timed out or errored, force-closing remaining TCP connections...", zap.Error(err))
			connsMu.Lock()
			for c := range conns {
				c.Close()
			}
			connsMu.Unlock()
		} else {
			logger.Info("✅ HTTP server exited gracefully")
		}
	}()

	if tlsEnabled {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			xl.Close()
			return nil, fmt.Errorf("load TLS certificate %s: %w", certFile, err)
		}

		var tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		server.TLSConfig = tlsConfig
		var h3Server *http3.Server
		if xl.srvUDP {
			h3Server = &http3.Server{
				Addr:      xl.uln.LocalAddr().String(),
				Handler:   handler,
				TLSConfig: tlsConfig.Clone(),
			}
		}

		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A tcp:// TLS listener intentionally opts out of H3. Do not emit
			// Alt-Svc unless we really own a QUIC socket.
			if h3Server != nil {
				_ = h3Server.SetQUICHeaders(w.Header())
			}
			handler.ServeHTTP(w, r)
		})

		if xl.srvTCP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.Info("🔐 [Server] starting TCP(TLS) HTTP server", zap.String("addr", listenAddr))
				// Own error variable: the HTTP/3 goroutine below runs
				// concurrently and a shared one would be a data race.
				if err := server.ServeTLS(xl.ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					logger.Warn("⚠️ TLS server exited", zap.Error(err))
				}
			}()
		}

		if h3Server != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.Info("🔐 [Server] attempting to start HTTP/3 (QUIC) server", zap.String("addr", listenAddr))
				if err := h3Server.Serve(xl.uln); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					logger.Warn("⚠️ HTTP/3 server exited", zap.Error(err))
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				<-ctx.Done()
				h3Server.Close()
			}()
		}

	} else {
		server.Handler = h2c.NewHandler(handler, &http2.Server{IdleTimeout: 1 * time.Hour})

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("🚀 [Server] Starting cleartext HTTP (h2c) server", zap.String("addr", listenAddr))
			if err := server.Serve(xl.ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
				logger.Warn("⚠️ H2C server exited", zap.Error(err))
			}
		}()
	}

	// Every setup step that can fail has succeeded; start the idle-session
	// reaper now so a failed Listen call never leaks its goroutine. The
	// reaper is idempotent per state: repeated ListenXHTTP calls (tests,
	// restarts) never start a second reaper for the same registry.
	st.startSessionCleaner()

	return xl, nil
}

// ServerConfig configures a [Server]. The zero value is not directly useful:
// Listen defaults to ":8443" only through the CLI; embedders should set at
// least Listen and a PSK (an empty PSK runs the server in unauthenticated
// open mode — never expose that publicly).
type ServerConfig struct {
	// Listen is the bind address with an optional scheme prefix: "tcp://:8443",
	// "udp://:8443" or "tcp+udp://:8443" (default when no scheme is given).
	// A udp:// socket serves HTTP/3 and therefore requires TLS (see CertFile).
	Listen string
	// Path is the Split-HTTP endpoint path requests must hit.
	Path string
	// PSK is the pre-shared key. A current client never sends it: it sends a
	// fresh nonce plus its HMAC over the nonce, session id and target. A
	// legacy client presents the key itself as "Proxy-Authorization: Bearer
	// <token>" or "X-Auth-Token"; that path is still accepted so a fleet can
	// be upgraded in place (servers first, clients after), and it is closed to
	// any client that advertises protocol version 2. Comma-separated values
	// accept multiple keys. Empty disables authentication.
	PSK string
	// CertFile/KeyFile enable TLS when both are set. Leave both empty for a
	// cleartext origin (typically behind a TLS-terminating CDN).
	CertFile string
	KeyFile  string
	// SelfSign generates a fresh self-signed certificate at startup instead
	// of loading CertFile/KeyFile. Handy for quick deployments and tests;
	// the certificate changes on every start, so clients must not pin its
	// fingerprint across restarts.
	SelfSign   bool
	SelfSignCN string
	// Fallback redirects any request that misses Path to this URL, camou-
	// flaging the endpoint as an ordinary website. Empty returns an nginx-
	// style 404 instead.
	Fallback string
	// DefaultTarget is where sessions are bridged when the client does not
	// request a specific target, in "tcp://host:port" form. Only used when
	// Handler is nil.
	DefaultTarget string
	// AllowedTargets restricts which targets clients may request. Each entry
	// may carry a "tcp://" or "udp://" prefix and one of three address forms:
	// "host:port" (exact), ":port" (any host on that port) or "host:" (any
	// port on that host); "*" means any. A scheme restricts the protocol the
	// client asked for, so "tcp://192.168.1.10:" admits only TCP; an entry
	// without a scheme admits either protocol. Empty allows everything.
	// Enforcement happens when a session is created, so it applies to custom
	// Handlers too — the built-in bridge and a Handler both only ever see
	// allowlisted targets.
	AllowedTargets []string
	// TrustProxyHeaders makes client-address logging honour
	// CF-Connecting-IP / X-Forwarded-For / X-Real-IP. Those headers are
	// spoofable: enable only behind a trusted proxy that strips them.
	TrustProxyHeaders bool
	// MaxSessions caps concurrent tunnel sessions. 0 selects the default
	// (2000).
	MaxSessions int
	// MaxSessionsPerIP caps concurrent sessions from a single client address,
	// bounding one PSK holder's blast radius against the shared registry. 0
	// (default) disables the per-IP limit; the global MaxSessions still applies.
	// Behind an untrusted front (no TrustProxyHeaders) this keys off the TCP
	// peer address; enable TrustProxyHeaders only behind a CDN that strips the
	// forwarding headers, or the limit is trivially bypassed by spoofing them.
	MaxSessionsPerIP int
	// MinProtoVersion rejects requests advertising an X-XHTTP-Proto below this
	// value with HTTP 426, letting an operator force a fleet off an old wire
	// generation. 0 (default) accepts every client, including legacy ones that
	// send no header.
	MinProtoVersion int
	// HealthPath, when non-empty (e.g. "/healthz"), serves an unauthenticated
	// JSON TunnelStats snapshot on GET at that path, independent of the tunnel
	// path. Intended for localhost or an operator-only listener.
	HealthPath string
	// Dump hex-dumps tunnelled traffic to stdout (debugging only).
	Dump bool
	// Brutal configures TCP Brutal on this server's accepted TCP connections.
	// Invalid combinations are rejected by NewServer. The HTTP/3 socket is
	// never affected: brutal caps TCP sockets, and QUIC is UDP.
	//
	// A static GroupID on a server would pool every client into one aggregate
	// ceiling, which is a global rate cap rather than a per-client one; set
	// GroupFromRemote instead to derive a group from the peer's address.
	Brutal BrutalConfig
	// Logger is the per-instance logger: every log line this server emits goes
	// here, independently of other servers in the process. Nil inherits the
	// package logger (see SetLogger). This no longer swaps the global logger.
	Logger *zap.Logger
	// EventHandler receives typed session events (SessionEstablished,
	// AuthRejected, TargetDenied, SessionLimitRejected, SessionClosed).
	// Handlers run on a dedicated goroutine with panic recovery and best-
	// effort delivery; they must not gate the tunnel's data path. Can also be
	// installed later via Server.SetEventHandler.
	EventHandler SessionEventHandler
	// Handler replaces the built-in target bridge: every accepted session is
	// passed to it on its own goroutine and the handler owns the connection,
	// including closing it. conn.TargetAddr()/conn.Network() report what the
	// client asked for. The AllowedTargets policy is enforced before the
	// handler sees a session. When Handler is nil, sessions are bridged to
	// the requested target (or DefaultTarget).
	Handler func(conn *XHTTPConn)
}

// Server is an embeddable xhttptunnel server: it terminates the Split-HTTP
// protocol and bridges accepted sessions to local services (or hands them to
// a custom Handler). Construct one with [NewServer] and run it with
// [Server.ListenAndServe].
type Server struct {
	cfg    ServerConfig
	state  *serverState
	defURL *url.URL

	// xl is published by ListenAndServe and read by Close/Addr, which may
	// run concurrently with it (the intended "serve in a goroutine, close
	// from main" pattern), so it is accessed atomically.
	xl atomic.Pointer[XHTTPListener]

	// certDir is the temp directory backing a SelfSign certificate, if any.
	// Removed on Close so repeated NewServer/Close cycles do not litter the
	// filesystem.
	certDir string
	// bridges counts in-flight session bridges (built-in or custom handlers).
	// Shutdown waits on it to let sessions drain before force-closing.
	bridges sync.WaitGroup
	// mountOnce guards the one-time setup of mounted mode (Server.Handler):
	// the session reaper and the channel-only listener's drain loop.
	mountOnce sync.Once
	stopOnce  sync.Once
}

// NewServer validates cfg and prepares the server. It does not bind any
// socket; call [Server.ListenAndServe] to start serving. Self-signed
// certificate generation (ServerConfig.SelfSign) happens here.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Path == "" {
		cfg.Path = "/stream"
	}
	if err := cfg.Brutal.Validate("server"); err != nil {
		return nil, err
	}

	certFile, keyFile := cfg.CertFile, cfg.KeyFile
	var certDir string
	if cfg.SelfSign {
		dir, err := os.MkdirTemp("", "xhttptunnel-cert-")
		if err != nil {
			return nil, fmt.Errorf("create temp dir for self-signed certificate: %w", err)
		}
		certDir = dir
		certFile = filepath.Join(dir, "cert.pem")
		keyFile = filepath.Join(dir, "key.pem")
		cn := cfg.SelfSignCN
		if cn == "" {
			cn = "www.bing.com"
		}
		if err := GenerateSelfSignedCert(certFile, keyFile, cn); err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("generate self-signed certificate: %w", err)
		}
	}

	state := newServerState(cfg.MaxSessions)
	state.customLog = cfg.Logger
	state.events = newSessionEventHub(cfg.EventHandler)
	state.setAllowedTargets(cfg.AllowedTargets)
	state.trustProxy.Store(cfg.TrustProxyHeaders)
	state.maxPerIP = cfg.MaxSessionsPerIP
	state.minProto = cfg.MinProtoVersion
	state.healthPath = cfg.HealthPath
	state.brutalCfg = cfg.Brutal
	if cfg.Brutal.Enabled {
		state.brutalWarns = newWarnGate()
		if !brutalAvailable() {
			// brutal's syscalls are Linux-only, so on any other platform the
			// listener is never even wrapped. Say so once rather than per
			// accepted connection.
			state.lg().Warn("⚠️ [TCP] TCP Brutal is configured but it is only available on Linux; the server runs without it")
		}
		if cfg.Brutal.GroupID != 0 && !cfg.Brutal.GroupFromRemote && cfg.Brutal.BWExchange {
			// A static group pools every client into one aggregate ceiling, so
			// one client's exchange updates the whole pool. Per-client
			// isolation needs group_from_remote.
			state.lg().Warn("⚠️ [TCP] a static brutal.group_id pools every client into one rate ceiling; the bandwidth exchange will update all of them. Use group_from_remote for per-client isolation")
		}
	}

	s := &Server{cfg: cfg, state: state, certDir: certDir}
	if cfg.DefaultTarget != "" {
		defURL, err := url.Parse(cfg.DefaultTarget)
		if err != nil {
			s.cleanupCertDir()
			return nil, fmt.Errorf("parse default target %q: %w", cfg.DefaultTarget, err)
		}
		s.defURL = defURL
	}
	// Keep the resolved cert paths for ListenAndServe (self-sign case).
	s.cfg.CertFile, s.cfg.KeyFile = certFile, keyFile
	return s, nil
}

// ListenAndServe binds the configured listener and serves until ctx is
// cancelled or the listener fails irrecoverably. Cancelling ctx stops the
// HTTP server and the accept loop; in-flight session bridges then drain on
// their own (idle sessions are reaped within ~2 minutes). Call [Server.Close]
// instead to force-close every session immediately.
func (s *Server) ListenAndServe(ctx context.Context) error {
	logger := s.state.lg()
	xl, err := listenXHTTP(ctx, s.cfg.Listen, s.cfg.Path, s.cfg.PSK, s.cfg.CertFile, s.cfg.KeyFile, s.cfg.Fallback, s.state)
	if err != nil {
		return err
	}
	s.xl.Store(xl)
	logger.Info("🚀 Server started successfully", zap.String("listen", s.cfg.Listen))
	go func() {
		<-ctx.Done()
		logger.Info("🛑 Shutdown signal received, closing listener...")
		xl.Close()
	}()

	for {
		conn, err := xl.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				logger.Info("✅ Server stopped cleanly")
				return nil
			}

			// Accept only ever fails when the context is done — the connCh is
			// never closed — so retrying would spin the CPU logging at full
			// speed. Treat it as terminal.
			logger.Error("❌ Accept connection failed, stopping accept loop", zap.Error(err))
			return err
		}
		xc, ok := conn.(*XHTTPConn)
		if !ok {
			// The accept loop must never panic: today Accept only produces
			// *XHTTPConn, but a future transport type must fail loud
			// and skip, not crash the whole server.
			logger.Error("❌ Accepted unexpected connection type, skipping", zap.String("type", fmt.Sprintf("%T", conn)))
			continue
		}
		logger.Debug("📥 [Accept] Accepted underlying virtual connection",
			zap.String("client_addr", xc.RemoteAddr().String()),
			zap.String("local_addr", xc.LocalAddr().String()),
			zap.String("req_target", xc.TargetAddr()),
			zap.String("req_network", xc.Network()),
		)

		if s.cfg.Handler != nil {
			// The custom handler owns the session, including closing it.
			s.bridges.Add(1)
			go func() {
				defer s.bridges.Done()
				s.cfg.Handler(xc)
			}()
			continue
		}
		s.bridges.Add(1)
		go func() {
			defer s.bridges.Done()
			s.bridge(xc)
		}()
	}
}

// Close shuts the server down: the listener, the session reaper and every
// session still registered are torn down, and a SelfSign temp directory is
// removed. Safe to call more than once.
func (s *Server) Close() error {
	var err error
	s.stopOnce.Do(func() {
		if xl := s.xl.Load(); xl != nil {
			err = xl.Close()
		}
		s.state.stop()
		s.cleanupCertDir()
	})
	return err
}

// Shutdown stops the listener (new polls are rejected) and waits for
// in-flight session bridges to finish, up to ctx's deadline. On deadline
// expiry the remaining sessions are force-closed like Close, and ctx.Err()
// is returned.
func (s *Server) Shutdown(ctx context.Context) error {
	if xl := s.xl.Load(); xl != nil {
		_ = xl.Close()
	}
	done := make(chan struct{})
	go func() {
		s.bridges.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.Close()
		return nil
	case <-ctx.Done():
		s.Close()
		return ctx.Err()
	}
}

func (s *Server) cleanupCertDir() {
	if s.certDir != "" {
		_ = os.RemoveAll(s.certDir)
		s.certDir = ""
	}
}

// Addr reports the bound listener address, or nil before ListenAndServe.
func (s *Server) Addr() net.Addr {
	if xl := s.xl.Load(); xl != nil {
		return xl.Addr()
	}
	return nil
}

// Stats returns a monotonic snapshot of the server's activity: live session
// count, cumulative creates/rejects/kicks/reaps and request total. Safe to
// call concurrently; it takes only a read lock for the gauge.
func (s *Server) Stats() TunnelStats { return s.state.snapshot() }

// ActiveSessions reports the number of tunnel sessions currently registered
// on this server (created, not yet closed). Useful for health endpoints and
// capacity dashboards.
func (s *Server) ActiveSessions() int {
	s.state.sessionsMu.RLock()
	defer s.state.sessionsMu.RUnlock()
	return len(s.state.sessions)
}

// SetEventHandler installs (or replaces) the typed session event handler.
// Handlers run on a dedicated goroutine with panic recovery; delivery is
// best-effort. Call before ListenAndServe/Handler() to catch the first
// SessionEstablished. Replacing a handler closes the previous hub — each hub
// owns one dispatcher goroutine, and dropping the reference without closing
// it would strand that goroutine on its channel forever.
func (s *Server) SetEventHandler(h SessionEventHandler) {
	s.state.events.close()
	s.state.events = newSessionEventHub(h)
}

// SessionIDs lists the IDs of the sessions currently registered on this
// server.
func (s *Server) SessionIDs() []string { return s.state.SessionIDs() }

// Kick closes the named session and removes it from the registry, reporting
// whether it existed. In-flight polls for that session fail on their next
// round and the client re-establishes if still alive.
func (s *Server) Kick(id string) bool { return s.state.Kick(id) }

// KickAll closes and removes every session on this server, returning how many
// were kicked.
func (s *Server) KickAll() int { return s.state.KickAll() }

// Handler returns an http.Handler implementing the Split-HTTP endpoint so the
// tunnel can be mounted inside an existing HTTP server instead of occupying
// its own port. Sessions are created against this server's config (PSK,
// AllowedTargets, MaxSessions) and dispatched through ServerConfig.Handler or
// the built-in bridge exactly like the self-hosted mode.
//
// Mount it at cfg.Path on your own mux/router. TLS, HTTP/2 and HTTP/3 then
// come from the hosting server; Host-mode routing (CDN in front) keeps working
// as long as the path and Host reach your application unchanged. When using
// this mode, leave ListenAndServe uncalled — the two own the same server
// state. Close still tears the state down.
func (s *Server) Handler() http.Handler {
	s.mountOnce.Do(func() {
		s.state.startSessionCleaner()
		xl := &XHTTPListener{connCh: make(chan *XHTTPConn, 256), expectedToken: s.cfg.PSK, chOnly: true}
		s.xl.Store(xl)
		// Mirror the accept loop of ListenAndServe without owning a socket:
		// pump accepted sessions into the configured handler or the built-in
		// bridge. Exits when Close closes the channel-only listener.
		logger := s.state.lg()
		go func() {
			for {
				conn, err := xl.Accept(context.Background())
				if err != nil {
					return
				}
				xc, ok := conn.(*XHTTPConn)
				if !ok {
					logger.Error("❌ Accepted unexpected connection type, skipping", zap.String("type", fmt.Sprintf("%T", conn)))
					continue
				}
				if s.cfg.Handler != nil {
					s.bridges.Add(1)
					go func() {
						defer s.bridges.Done()
						s.cfg.Handler(xc)
					}()
					continue
				}
				s.bridges.Add(1)
				go func() {
					defer s.bridges.Done()
					s.bridge(xc)
				}()
			}
		}()
	})
	return buildSessionHandler(s.xl.Load(), s.state, s.cfg.Path, s.cfg.PSK, s.cfg.Fallback)
}

// bridge connects one accepted session to its target service. It is the
// built-in Handler: the client's X-Target/X-Network headers (or
// DefaultTarget) decide where to dial.
func (s *Server) bridge(xc *XHTTPConn) {
	logger := s.state.lg()
	defer xc.Close()

	connID := generateRandomHex(4)
	logger.Debug("🔌 New client request received", zap.String("id", connID), zap.String("remote", xc.RemoteAddr().String()))

	target, network := xc.TargetAddr(), xc.Network()
	if target == "" && s.defURL != nil {
		target = s.defURL.Host
	}
	if network == "" && s.defURL != nil {
		network = s.defURL.Scheme
	}

	logger.Debug("🎯 Target routing resolved", zap.String("id", connID), zap.String("network", network), zap.String("target", target))

	if network == "tcp" {
		logger.Debug("⏳ Dialing target TCP service...", zap.String("id", connID), zap.String("target", target))
		rc, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			logger.Error("❌ Failed to connect to target TCP service", zap.String("id", connID), zap.String("target", target), zap.Error(err))
			xc.WriteCloseFrame()
			return
		}
		// Enable TCP keepalive on the target connection so a half-open
		// peer (crashed box, severed cable, NAT table entry dropped)
		// is noticed in seconds instead of lingering until the idle
		// cleaner sweeps it. Keepalive probes ride in-band and cost
		// nothing until the peer is actually dead.
		if tcpConn, ok := rc.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
		var closeOnce sync.Once
		closeTarget := func() {
			closeOnce.Do(func() {
				_ = rc.Close()
			})
		}
		defer closeTarget()

		logger.Debug("✅ Target TCP service connected successfully", zap.String("id", connID), zap.String("target", target))

		var targetConn net.Conn = rc
		if s.cfg.Dump {
			targetConn = &DumpConn{Conn: rc, Prefix: "Server Target - " + connID}
		}

		go func() {
			defer closeTarget()
			n, err := io.Copy(targetConn, xc)
			if err != nil && err != io.EOF {
				logger.Debug("⚠️ TCP uplink (Client->Target) ended with error", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
			} else {
				logger.Debug("🛑 TCP uplink (Client->Target) finished normally", zap.String("id", connID), zap.Int64("bytes", n))
			}

			if c, ok := targetConn.(interface{ CloseWrite() error }); ok {
				c.CloseWrite()
			} else {
				targetConn.Close()
			}
		}()

		n, err := io.Copy(xc, targetConn)
		if err != nil && err != io.EOF {
			logger.Debug("⚠️ TCP downlink (Target->Client) ended with error", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
		} else {
			logger.Debug("🛑 TCP downlink (Target->Client) finished normally", zap.String("id", connID), zap.Int64("bytes", n))
		}
		xc.WriteCloseFrame()
		logger.Debug("💀 TCP session cleaned up", zap.String("id", connID))

	} else if network == "udp" {
		logger.Debug("⏳ Dialing target UDP service...", zap.String("id", connID), zap.String("target", target))
		rc, err := net.DialTimeout("udp", target, 5*time.Second)
		if err != nil {
			logger.Error("❌ Failed to connect to target UDP service", zap.String("id", connID), zap.String("target", target), zap.Error(err))
			// Mirror the TCP branch: without a close frame the client
			// keeps polling a session whose target never existed.
			xc.WriteCloseFrame()
			return
		}
		var closeOnce sync.Once
		closeTarget := func() {
			closeOnce.Do(func() {
				_ = rc.Close()
			})
		}
		defer closeTarget()

		if s.cfg.Dump {
			rc = &DumpConn{
				Conn:   rc,
				Prefix: "Server Target[UDP] - " + connID,
			}
		}
		logger.Debug("✅ Target UDP service connected successfully", zap.String("id", connID), zap.String("target", target))

		go func() {
			defer closeTarget() // When the uplink exits, close rc immediately to interrupt the downlink goroutine that may be blocked on rc.Read
			uBuf := make([]byte, maxUDPFrameSize)
			for {
				n, err := ReadUDPFrameInto(xc, uBuf)
				if err != nil {
					if err != io.EOF {
						logger.Debug("⚠️ UDP uplink read frame failed", zap.String("id", connID), zap.Error(err))
					} else {
						logger.Debug("🛑 UDP uplink read frame finished (EOF)", zap.String("id", connID))
					}
					return
				}
				rc.Write(uBuf[:n])
			}
		}()

		dBuf := make([]byte, maxUDPFrameSize)
		for {
			_ = rc.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := rc.Read(dBuf)
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					logger.Debug("🛑 UDP downlink finished (connection closed)", zap.String("id", connID))
				} else {
					logger.Debug("⚠️ UDP downlink read target failed", zap.String("id", connID), zap.Error(err))
				}
				return
			}
			if errW := WriteUDPFrame(xc, dBuf[:n]); errW != nil {
				return
			}
		}
	} else {
		logger.Warn("⚠️ Unknown network type", zap.String("id", connID), zap.String("network", network))
	}
}
