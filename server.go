package main

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

var (
	meekSessions      = make(map[string]*meekVirtualConn)
	meekMutex         sync.RWMutex
	cleanerOnce       sync.Once
	maxGlobalSessions = 2000

	// allowedTargets restricts which forwarding targets a client may request.
	// An entry matches when it equals the target exactly, ends with ":port"
	// (any host on that port), or starts with "host:" (any port on that host).
	// An empty list means every target is allowed. Written once at startup.
	allowedTargets []string

	// trustProxyHeaders controls whether client-supplied proxy headers
	// (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are honoured when logging
	// the client address. They are trivially spoofable, so this is OFF by
	// default: RemoteAddr is used instead. Turn it on ONLY when the server is
	// reachable exclusively through a trusted reverse proxy / CDN that strips
	// these headers on ingress. Never enable it for direct public exposure.
	trustProxyHeaders bool
)

type XHTTPListener struct {
	connCh        chan *xhttpFramedConn
	ln            net.Listener
	uln           net.PacketConn
	srvTCP        bool
	srvUDP        bool
	expectedToken string
	RequestCount  uint64
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
	// shutdown does not panic and always tears down what is open.
	var err error
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

// targetAllowed reports whether a client-requested forwarding target may be
// dialed. Allowlist entries support three forms: "host:port" (exact),
// ":port" (any host on that port) and "host:" (any port on that host).
func targetAllowed(target string) bool {
	if len(allowedTargets) == 0 {
		return true
	}
	for _, entry := range allowedTargets {
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

func getClientIP(r *http.Request) string {
	// Proxy headers are client-controlled and therefore untrusted. Only read
	// them when the operator has explicitly opted in via trust_proxy_headers
	// (meaning a trusted CDN/proxy is known to strip them on ingress).
	if trustProxyHeaders {
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

func ListenXHTTP(ctx context.Context, listenAddr, path, token, certFile, keyFile, fallbackURL string) (*XHTTPListener, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("TLS requires both cert and key files")
	}
	tlsEnabled := certFile != ""

	xl := &XHTTPListener{connCh: make(chan *xhttpFramedConn, 256), expectedToken: token}
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

	// The session registry is process-global, so the reaper deliberately runs
	// detached from any listener context: binding it to one meant that the
	// first server to shut down (a test, a graceful restart) killed the only
	// reaper for the lifetime of the process, after which stale sessions
	// accumulated forever.
	cleanerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(cleanerInterval)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now().Unix()
				meekMutex.Lock()
				for id, v := range meekSessions {
					if now-atomic.LoadInt64(&v.lastActive) > int64(sessionIdleTimeout.Seconds()) {
						logger.Debug("🧹 [Cleaner] 发现过期会话，清理释放资源", zap.String("session", id))
						v.Close()
						delete(meekSessions, id)
					}
				}
				meekMutex.Unlock()
			}
		}()
	})

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
		clientIP := getClientIP(r)
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
				nginxError(w, http.StatusProxyAuthRequired)
				return
			}
		}

		meekMutex.Lock()
		vConn, exists := meekSessions[sessionID]
		if !exists {
			// Policy check happens before a session is registered, otherwise
			// a rejected target would still leave a phantom session behind.
			if !targetAllowed(target) {
				meekMutex.Unlock()
				logger.Warn("❌ [Server] 拒绝连接: 目标不在允许列表", zap.String("target", target), zap.String("remote", r.RemoteAddr))
				nginxError(w, http.StatusForbidden)
				return
			}
			if len(meekSessions) >= maxGlobalSessions {
				meekMutex.Unlock()
				logger.Warn("❌ [Server] 拒绝连接: 达到最大并发会话数限制", zap.Int("limit", maxGlobalSessions), zap.String("remote", r.RemoteAddr))
				nginxError(w, http.StatusServiceUnavailable)
				return
			}
			vConn = newMeekVirtualConn(sessionID, stringAddr(r.Host), stringAddr(r.RemoteAddr))
			meekSessions[sessionID] = vConn
			meekMutex.Unlock()

			xConn := newXhttpFramedConn(vConn, vConn, func() error {
				// Give an in-flight poll a moment to pick up the queued
				// close frame before the session vanishes from the registry;
				// otherwise the client keeps re-creating the session and the
				// target connection lingers until the idle cleaner fires.
				vConn.waitDrained(serverDrainTimeout)
				meekMutex.Lock()
				delete(meekSessions, sessionID)
				meekMutex.Unlock()
				logger.Debug("💀 [Server] 会话彻底注销销毁", zap.String("session", sessionID))
				return vConn.Close()
			}, vConn.local, vConn.remote)
			xConn.targetAddr = target
			xConn.network = network

			// Never block the HTTP handler on the accept backlog: a stalled
			// accept loop would strand handlers and freeze every session.
			select {
			case xl.connCh <- xConn:
			default:
				meekMutex.Lock()
				delete(meekSessions, sessionID)
				meekMutex.Unlock()
				vConn.Close()
				logger.Warn("❌ [Server] 会话队列已满，拒绝新会话", zap.String("session", sessionID), zap.String("remote", r.RemoteAddr))
				nginxError(w, http.StatusServiceUnavailable)
				return
			}
			logger.Debug("🆕 [Server] 收到并创建全新隧道会话", zap.String("session", sessionID), zap.String("target", target))
		} else {
			vConn.updateActive()
			meekMutex.Unlock()
		}

		cSeq, _ := strconv.ParseUint(r.Header.Get("X-Seq"), 10, 64)
		cAck, _ := strconv.ParseUint(r.Header.Get("X-Ack"), 10, 64)

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

			downData, myDownSeq, downBufPtr = vConn.writeBuf.GetSlice(cAck, vConn.downDispatchSeq, maxsendBufSize)

			if len(downData) > 0 {
				vConn.downDispatchSeq = myDownSeq + uint64(len(downData))
				return true
			}

			vConn.downDispatchSeq = myDownSeq
			return false
		}

		if totalUpBytes > 0 {
			fetchDownData()
		} else {
			if !fetchDownData() && !vConn.isClosed() {
				vConn.writeBuf.waitLongPoll(r.Context(), longPollTimeout)
				fetchDownData()
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
	handler := panicRecoveryMiddleware(tracker.Middleware(mux))

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
			logger.Fatal("❌ 加载 TLS 证书失败", zap.Error(err), zap.String("cert", certFile))
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

	return xl, nil
}

func runServer(ctx context.Context, listenAddr, path, defaultTargetStr, psk, certFile, keyFile string, dump bool, fallback string) {
	defURL, err := url.Parse(defaultTargetStr)
	if err != nil {
		logger.Fatal("解析失败", zap.Error(err))
	}
	logger.Debug("🔧 默认路由配置", zap.String("host", defURL.Host), zap.String("scheme", defURL.Scheme))

	// Keep the optional tcp://, udp:// or tcp+udp:// prefix intact. Stripping
	// it here made every configured listener look like the default tcp+udp
	// mode, so explicit protocol selection was silently ignored.
	host := listenAddr
	xl, err := ListenXHTTP(ctx, listenAddr, path, psk, certFile, keyFile, fallback)
	if err != nil {
		logger.Fatal("Server listen failed", zap.Error(err))
	}
	logger.Info("🚀 Server started successfully", zap.String("listen", host))
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
				return
			}

			// Accept only ever fails when the context is done — the connCh is
			// never closed — so retrying would spin the CPU logging at full
			// speed. Treat it as terminal.
			logger.Error("❌ Accept connection failed, stopping accept loop", zap.Error(err))
			return
		}
		xc, ok := conn.(*xhttpFramedConn)
		if !ok {
			// The accept loop must never panic: today Accept only produces
			// *xhttpFramedConn, but a future transport type must fail loud
			// and skip, not crash the whole server.
			logger.Error("❌ Accepted unexpected connection type, skipping", zap.String("type", fmt.Sprintf("%T", conn)))
			continue
		}
		logger.Debug("📥 [Accept] Accepted underlying virtual connection",
			zap.String("client_addr", xc.RemoteAddr().String()),
			zap.String("local_addr", xc.LocalAddr().String()),
			zap.String("req_target", xc.targetAddr),
			zap.String("req_network", xc.network),
		)

		go func(xc *xhttpFramedConn) {
			defer xc.Close()

			connID := generateRandomHex(4)
			logger.Debug("🔌 New client request received", zap.String("id", connID), zap.String("remote", xc.RemoteAddr().String()))

			target, network := xc.targetAddr, xc.network
			if target == "" {
				target = defURL.Host
			}
			if network == "" {
				network = defURL.Scheme
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
				if dump {
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

				if dump {
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
						n, err := readUDPFrameInto(xc, uBuf)
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
					if errW := writeUDPFrame(xc, dBuf[:n]); errW != nil {
						return
					}
				}
			} else {
				logger.Warn("⚠️ Unknown network type", zap.String("id", connID), zap.String("network", network))
			}
		}(xc)
	}
}
