package main

import (
	"context"
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

var (
	meekSessions      = make(map[string]*meekVirtualConn)
	meekMutex         sync.RWMutex
	cleanerOnce       sync.Once
	maxGlobalSessions = 2000
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
func (l *XHTTPListener) Close() error   { return l.ln.Close() }
func (l *XHTTPListener) Addr() net.Addr { return l.ln.Addr() }

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

func ListenXHTTP(ctx context.Context, listenAddr, path, token, certFile, keyFile, fallbackURL string) (*XHTTPListener, error) {
	xl := &XHTTPListener{connCh: make(chan *xhttpFramedConn, 256), expectedToken: token}
	rListenAddr, rNetwork := ParseListenAddr(listenAddr)
	if rNetwork == NetTCP || rNetwork == NetBoth {
		ln, err := net.Listen("tcp", rListenAddr)
		if err != nil {
			return nil, err
		}
		xl.ln = ln
		xl.srvTCP = true
	}
	if rNetwork == NetUDP || rNetwork == NetBoth {
		ln, err := net.ListenPacket("udp", rListenAddr)
		if err != nil {
			return nil, err
		}
		xl.uln = ln
		xl.srvUDP = true
	}

	cleanerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now().Unix()
					meekMutex.Lock()
					for id, v := range meekSessions {
						if now-atomic.LoadInt64(&v.lastActive) > 120 {
							logger.Debug("🧹 [Cleaner] 发现过期会话，清理释放资源", zap.String("session", id))
							v.Close()
							delete(meekSessions, id)
						}
					}
					meekMutex.Unlock()
				}
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
		logger.Debug("👀 [HTTP] 收到原始 HTTP 请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote", r.RemoteAddr),
			zap.String("session", r.Header.Get("X-Session-ID")),
			zap.String("auth", r.Header.Get("Proxy-Authorization")),
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
			logger.Warn("❌ [HTTP] 拒绝请求: 缺少 Session ID", zap.String("remote", r.RemoteAddr))
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
				if cleanTok != "" && (authHeader == "Bearer "+cleanTok || authHeader == cleanTok || customTokenHeader == cleanTok) {
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
				meekMutex.Lock()
				delete(meekSessions, sessionID)
				meekMutex.Unlock()
				logger.Debug("💀 [Server] 会话彻底注销销毁", zap.String("session", sessionID))
				return vConn.Close()
			}, vConn.local, vConn.remote)
			xConn.targetAddr = target
			xConn.network = network

			xl.connCh <- xConn
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
			if !fetchDownData() && !vConn.closed {
				vConn.writeBuf.mu.Lock()
				if vConn.writeBuf.count == 0 {
					stopCtx := context.AfterFunc(r.Context(), func() {
						vConn.writeBuf.cond.Broadcast()
					})
					timer := time.AfterFunc(15*time.Second, func() {
						vConn.writeBuf.cond.Broadcast()
					})

					vConn.writeBuf.cond.Wait()

					timer.Stop()
					stopCtx()
				}
				vConn.writeBuf.mu.Unlock()

				fetchDownData()
			}
		}

		logger.Debug("📤 [HTTP] 准备发送下行响应",
			zap.String("session", sessionID),
			zap.Uint64("Server_Seq", myDownSeq),
			zap.Uint64("Server_Ack", myUpAck),
			zap.Int("Down_Bytes", len(downData)),
		)

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

	var err error
	if certFile != "" && keyFile != "" {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Fatal("❌ 加载 TLS 证书失败", zap.Error(err), zap.String("cert", certFile))
		}

		var tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		server.TLSConfig = tlsConfig
		h3Server := &http3.Server{
			Addr:      listenAddr,
			Handler:   handler,
			TLSConfig: tlsConfig,
		}

		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = h3Server.SetQUICHeaders(w.Header())
			handler.ServeHTTP(w, r)
		})

		if xl.srvTCP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.Info("🔐 [Server] 启动 TCP(TLS) HTTP 服务器", zap.String("addr", listenAddr))
				if err = server.ServeTLS(xl.ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					logger.Warn("TLS 退出", zap.Error(err))
				}
			}()
		}

		if xl.srvUDP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.Info("🔐 [Server] 尝试启动 HTTP/3 (QUIC) 服务器", zap.String("addr", listenAddr))
				if err = h3Server.Serve(xl.uln); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
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
			if err = server.Serve(xl.ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
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

	var host string
	if strings.Contains(listenAddr, "://") {
		u, _ := url.Parse(listenAddr)
		host = u.Host
	} else {
		host = listenAddr
	}

	xl, err := ListenXHTTP(ctx, host, path, psk, certFile, keyFile, fallback)
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

			logger.Error("❌ Accept connection failed", zap.Error(err))
			continue
		}
		if xc, ok := conn.(*xhttpFramedConn); ok {
			logger.Debug("📥 [Accept] Accepted underlying virtual connection",
				zap.String("client_addr", xc.RemoteAddr().String()),
				zap.String("local_addr", xc.LocalAddr().String()),
				zap.String("req_target", xc.targetAddr),
				zap.String("req_network", xc.network),
			)
		}

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
					defer closeTarget() // 上行退出时，立刻关闭 rc，打断可能阻塞在 rc.Read 上的下行协程
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
		}(conn.(*xhttpFramedConn))
	}
}
