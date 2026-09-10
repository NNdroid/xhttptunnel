package tunnel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
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
	connCh        chan *XHTTPConn
	ln            net.Listener
	uln           net.PacketConn
	srvTCP        bool
	srvUDP        bool
	expectedToken string
	// chOnly marks a listener that exists only for its session channel (the
	// mounted Server.Handler mode). Closing it closes the channel so an
	// external drain loop can exit; there are no sockets to release.
	chOnly       bool
	RequestCount uint64
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
	wg    sync.WaitGroup
	n     int64
	quiet chan struct{}
}

func NewActiveTracker() *ActiveTracker {
	return &ActiveTracker{quiet: make(chan struct{})}
}

func (t *ActiveTracker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&t.n, 1)
		t.wg.Add(1)
		defer func() {
			t.wg.Done()
			if atomic.AddInt64(&t.n, -1) == 0 {
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
	if atomic.LoadInt64(&t.n) == 0 {
		return nil
	}
	select {
	case <-t.quiet:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *ActiveTracker) Active() int64 { return atomic.LoadInt64(&t.n) }

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
			}
			logger.Info("🛡️ 伪装站点 (Fallback) 已启用", zap.String("target", fallbackURL))
		} else {
			logger.Warn("❌ 伪装站点 URL 解析失败", zap.Error(err))
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := st.getClientIP(r)
		logger.Debug("👀 [HTTP] 收到原始 HTTP 请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote", clientIP),
			zap.String("session", r.Header.Get("X-Session-ID")),
			zap.String("auth", redactAuth(r.Header.Get("Proxy-Authorization"))),
		)
		if r.URL.Path != path {
			if fallbackProxy != nil {
				fallbackProxy.ServeHTTP(w, r)
				return
			}
			nginxError(w, http.StatusNotFound)
			return
		}
		atomic.AddUint64(&xl.RequestCount, 1)

		target := r.Header.Get("X-Target")
		network := r.Header.Get("X-Network")
		sessionID := r.Header.Get("X-Session-ID")

		if sessionID == "" {
			logger.Warn("❌ [HTTP] 拒绝请求: 缺少 Session ID", zap.String("remote", clientIP))
			nginxError(w, http.StatusBadRequest)
			return
		}
		if xl.expectedToken != "" {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader == "" {
				authHeader = r.Header.Get("Authorization")
			}
			customTokenHeader := r.Header.Get("X-Auth-Token")
			tokens := strings.Split(xl.expectedToken, ",")
			authed := false
			for _, tok := range tokens {
				cleanTok := strings.TrimSpace(tok)
				if cleanTok == "" {
					continue
				}
				// Compared in constant time: a plain == short-circuits on the
				// first differing byte, which hands an attacker a byte-at-a-
				// time oracle on the shared secret.
				if constTimeEqual(authHeader, "Bearer "+cleanTok) ||
					constTimeEqual(authHeader, cleanTok) ||
					constTimeEqual(customTokenHeader, cleanTok) {
					authed = true
					break
				}
			}
			if !authed {
				logger.Warn("❌ [HTTP] 拒绝请求: 密码错误或未授权",
					zap.String("remote", r.RemoteAddr),
				)
				st.events.emit(AuthRejected{Remote: r.RemoteAddr, Path: r.URL.Path})
				nginxError(w, http.StatusProxyAuthRequired)
				return
			}
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
			serveStreamUplink(w, r, st, vConn, sessionID)
			return
		}

		cSeq, _ := strconv.ParseUint(r.Header.Get("X-Seq"), 10, 64)
		cAck, _ := strconv.ParseUint(r.Header.Get("X-Ack"), 10, 64)
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
				myUpAck = vConn.PutReadData(currentSeq, readChunk[:n])
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
			logger.Warn("⚠️ [HTTP] 读取上行 Body 失败或异常中断", zap.Error(errBody))
			nginxError(w, http.StatusBadRequest)
			return
		}

		if totalUpBytes == 0 {
			myUpAck = vConn.PutReadData(cSeq, nil)
		}

		logger.Debug("📥 [HTTP] 解析上行请求",
			zap.String("session", sessionID),
			zap.Uint64("Client_Seq", cSeq),
			zap.Uint64("Client_Ack", cAck),
			zap.Int("Up_Bytes", totalUpBytes),
			zap.Uint64("Server_Expect_Ack", myUpAck),
		)

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
			logger.Debug("📡 [HTTP] 流式下行接管，本响应不捎带下行", zap.String("session", sessionID))
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

		logger.Debug("📤 [HTTP] 准备发送下行响应",
			zap.String("session", sessionID),
			zap.Uint64("Server_Seq", myDownSeq),
			zap.Uint64("Server_Ack", myUpAck),
			zap.Int("Down_Bytes", len(downData)),
		)

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
		logger.Info("🛑 收到退出信号，正在优雅关闭 HTTP 服务器...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("⚠️ 优雅关闭超时或出错，强制关闭残留的 TCP 连接...", zap.Error(err))
			connsMu.Lock()
			for c := range conns {
				c.Close()
			}
			connsMu.Unlock()
		} else {
			logger.Info("✅ HTTP 服务器已优雅退出")
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
				logger.Info("🔐 [Server] 启动 TCP(TLS) HTTP 服务器", zap.String("addr", listenAddr))
				// Own error variable: the HTTP/3 goroutine below runs
				// concurrently and a shared one would be a data race.
				if err := server.ServeTLS(xl.ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					logger.Warn("TLS 退出", zap.Error(err))
				}
			}()
		}

		if h3Server != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.Info("🔐 [Server] 尝试启动 HTTP/3 (QUIC) 服务器", zap.String("addr", listenAddr))
				if err := h3Server.Serve(xl.uln); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					logger.Warn("HTTP/3 退出", zap.Error(err))
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
				logger.Warn("H2C 退出", zap.Error(err))
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
	// PSK is the pre-shared token. Clients present it as
	// "Proxy-Authorization: Bearer <token>" or "X-Auth-Token". Comma-separated
	// values accept multiple tokens. Empty disables authentication.
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
	// AllowedTargets restricts which targets clients may request. Entries may
	// be "host:port", ":port" (any host on that port) or "host:" (any port on
	// that host). Empty allows everything. Enforcement happens when a session
	// is created, so it applies to custom Handlers too — the built-in bridge
	// and a Handler both only ever see allowlisted targets.
	AllowedTargets []string
	// TrustProxyHeaders makes client-address logging honour
	// CF-Connecting-IP / X-Forwarded-For / X-Real-IP. Those headers are
	// spoofable: enable only behind a trusted proxy that strips them.
	TrustProxyHeaders bool
	// MaxSessions caps concurrent tunnel sessions. 0 selects the default
	// (2000).
	MaxSessions int
	// Dump hex-dumps tunnelled traffic to stdout (debugging only).
	Dump bool
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
					logger.Debug("🛑 UDP downlink finished (连接已关闭)", zap.String("id", connID))
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
