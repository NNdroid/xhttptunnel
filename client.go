package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

const (
	// clientRequestTimeout bounds a single poll request, including reading its
	// response body.
	clientRequestTimeout = 90 * time.Second
	// protoCacheTTL keeps a negotiated protocol per endpoint. Without it every
	// tunnel connection pays for its own QUIC probe plus TLS handshake.
	protoCacheTTL = 5 * time.Minute
	// h3ProbeTimeout bounds the QUIC handshake probe.
	h3ProbeTimeout = 1800 * time.Millisecond
	// closeFlushTimeout is how long Close() lets the pump ship a queued close
	// frame before tearing the session down. It has to exceed the server's
	// long-poll timeout so a worker parked in a poll still gets to deliver it.
	closeFlushTimeout = longPollTimeout + time.Second
	// dialTimeout bounds establishing the underlying TCP connection.
	dialTimeout = 10 * time.Second
	// sharedMaxIdleConns caps idle keep-alive sockets for one shared transport.
	sharedMaxIdleConns = 512

	// minPumpWorkers is the number of polling workers every session keeps
	// alive. One of them holds the long poll that carries downlink traffic;
	// the other parks on the write buffer so uplink data is sent the instant
	// it arrives instead of waiting for that long poll to come back. Only the
	// long poll costs a request against the CDN.
	minPumpWorkers = 2
	// maxPumpWorkers caps concurrent polls for one busy session.
	maxPumpWorkers = 8
)

var (
	maxClientSessions = 2000

	// clientIdleTimeout is how long a local TCP connection may stay silent
	// before it is dropped. Refreshed on every successful read; configurable
	// via the idle_timeout config field.
	clientIdleTimeout = 15 * time.Minute

	// transportCache holds one HTTP/1.1 or h2 transport per endpoint. Sessions
	// share it so they reuse a single connection pool instead of each holding
	// up to workerCount sockets, which is what exhausted file descriptors and
	// hammered CDNs with connection churn.
	transportMu    sync.Mutex
	transportCache = map[string]http.RoundTripper{}

	// protoCache memoises the protocol negotiated for an endpoint.
	protoMu    sync.Mutex
	protoCache = map[string]protoEntry{}
)

type protoEntry struct {
	protocol string
	expiry   time.Time
}

// pooledBody hands a send-buffer back to the pool exactly once, when the
// transport is finished with it.
//
// Recycling right after RoundTrip returns is unsafe. net/http documents that a
// RoundTripper "must always close the body, including on errors, but depending
// on the implementation may do so in a separate goroutine even after RoundTrip
// returns" — and both h2 and h3 take that option (h3 writes the request body
// from its own goroutine). A buffer recycled early can be claimed and rewritten
// by another worker while it is still being streamed, which silently corrupts
// the upload and leaks one session's bytes into another.
type pooledBody struct {
	*bytes.Reader
	buf  *[]byte
	once sync.Once
}

func newPooledBody(p []byte, buf *[]byte) *pooledBody {
	return &pooledBody{Reader: bytes.NewReader(p), buf: buf}
}

func (b *pooledBody) Close() error {
	b.once.Do(func() { safelyPutSendBuf(b.buf) })
	return nil
}

func buildNextProtos(alpn string) []string {
	alpn = strings.ToLower(strings.TrimSpace(alpn))
	switch alpn {
	case "h1", "http/1.1":
		return []string{"http/1.1"}
	case "h2":
		return []string{"h2", "http/1.1"}
	case "h3":
		return []string{"h3", "h2", "http/1.1"}
	default: // auto
		return []string{"h3", "h2", "http/1.1"}
	}
}

func probeHTTP3(ctx context.Context, hostPort, sni string, timeout time.Duration, fingerprint string) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify:    true,
		ServerName:            sni,
		NextProtos:            []string{"h3"},
		VerifyPeerCertificate: verifyFingerprint(fingerprint),
	}

	qconf := &quic.Config{}

	logger.Debug("🔎 probeHTTP3 开始 QUIC 握手探测", zap.String("hostport", hostPort), zap.String("sni", sni), zap.Duration("timeout", timeout))

	type result struct {
		sess *quic.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		sess, err := quic.DialAddr(cctx, hostPort, tlsConf, qconf)
		if cctx.Err() != nil && sess != nil {
			_ = sess.CloseWithError(0, "probe timeout")
			return
		}
		ch <- result{sess: sess, err: err}
	}()

	select {
	case <-cctx.Done():
		logger.Debug("🔎 probeHTTP3 超时/取消", zap.String("hostport", hostPort), zap.Error(cctx.Err()))
		return false, cctx.Err()
	case res := <-ch:
		if res.err != nil {
			logger.Debug("🔎 probeHTTP3 握手失败", zap.String("hostport", hostPort), zap.Error(res.err))
			return false, res.err
		}
		if cerr := res.sess.CloseWithError(0, "probe done"); cerr != nil {
			logger.Debug("🔎 probeHTTP3: CloseWithError 返回", zap.Error(cerr))
		}
		logger.Debug("🔎 probeHTTP3 握手成功，发现 QUIC/HTTP3 支持", zap.String("hostport", hostPort))
		return true, nil
	}
}

// detectProtocol resolves which HTTP version a tunnel should speak. The result
// is cached per endpoint: working it out costs a QUIC handshake plus a TCP/TLS
// handshake, and paying that on every single tunnel connection is what made
// short-lived connections crawl behind a CDN.
func detectProtocol(ctx context.Context, cfg *Config, nextProtos []string, isTLS bool, hostPort string) (string, error) {
	if !isTLS {
		if slices.Contains(nextProtos, "h2") {
			return "h2", nil
		}
		return "http/1.1", nil
	}

	key := strings.Join(nextProtos, ",") + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint
	now := time.Now()

	protoMu.Lock()
	if e, ok := protoCache[key]; ok && now.Before(e.expiry) {
		protoMu.Unlock()
		logger.Debug("[Sniffer] ♻️ 复用缓存的协议探测结果", zap.String("hostport", hostPort), zap.String("protocol", e.protocol))
		return e.protocol, nil
	}
	protoMu.Unlock()

	protocol, err := sniffProtocol(ctx, cfg, nextProtos, hostPort)
	if err != nil {
		return "", err
	}

	protoMu.Lock()
	protoCache[key] = protoEntry{protocol: protocol, expiry: now.Add(protoCacheTTL)}
	protoMu.Unlock()
	return protocol, nil
}

// sniffProtocol performs the one-off QUIC probe and TLS handshake used to pick
// a protocol. The probe socket is closed afterwards: the shared pool dials its
// own connections, and dedicating one socket per session is exactly the fan-out
// this design has to avoid.
func sniffProtocol(ctx context.Context, cfg *Config, nextProtos []string, hostPort string) (string, error) {
	alpnPref := strings.ToLower(strings.TrimSpace(cfg.ALPN))
	if alpnPref == "h3" || alpnPref == "auto" {
		logger.Debug("尝试使用 QUIC/HTTP3 探测", zap.String("hostport", hostPort), zap.String("sni", cfg.SNI))
		ok, perr := probeHTTP3(ctx, hostPort, cfg.SNI, h3ProbeTimeout, cfg.CertificateFingerprint)
		if ok && perr == nil {
			logger.Debug("QUIC/HTTP3 探测成功，使用 HTTP/3", zap.String("host", hostPort))
			return "h3", nil
		}
		logger.Debug("QUIC/HTTP3 探测失败，回落至 TCP/TLS 探测", zap.String("host", hostPort), zap.Error(perr))
	}

	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos, VerifyPeerCertificate: verifyFingerprint(cfg.CertificateFingerprint)}
	tlsConn := utls.UClient(conn, utlsConfig, utls.HelloChrome_Auto)
	if err := tlsConn.BuildHandshakeState(); err != nil {
		return "", fmt.Errorf("utls build handshake state failed: %w", err)
	}
	for _, ext := range tlsConn.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = nextProtos
			break
		}
	}
	if err := tlsConn.Handshake(); err != nil {
		return "", err
	}

	protocol := tlsConn.ConnectionState().NegotiatedProtocol
	if protocol == "" {
		if slices.Contains(nextProtos, "h2") {
			protocol = "h2"
		} else {
			protocol = "http/1.1"
		}
	}
	logger.Debug("[Sniffer] ✅ TLS 探测完成", zap.String("ALPN", protocol), zap.String("SNI", cfg.SNI))
	return protocol, nil
}

// dialParams carries everything needed to open a connection to one endpoint.
// Sessions sharing a transport share these parameters, which is what makes
// their pooled connections interchangeable.
type dialParams struct {
	hostPort    string
	sni         string
	fingerprint string
	nextProtos  []string
	isTLS       bool
}

func (p *dialParams) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", p.hostPort)
	if err != nil {
		logger.Error("❌ [Dialer] 建立底层连接失败", zap.Error(err))
		return nil, err
	}
	if !p.isTLS {
		return c, nil
	}

	utlsConfig := &utls.Config{ServerName: p.sni, InsecureSkipVerify: true, NextProtos: p.nextProtos, VerifyPeerCertificate: verifyFingerprint(p.fingerprint)}
	tlsC := utls.UClient(c, utlsConfig, utls.HelloChrome_Auto)
	if err := tlsC.BuildHandshakeState(); err != nil {
		c.Close()
		return nil, fmt.Errorf("utls build handshake state failed: %w", err)
	}
	for _, ext := range tlsC.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = p.nextProtos
			break
		}
	}
	if err := tlsC.Handshake(); err != nil {
		logger.Error("❌ [Dialer] TLS 握手失败", zap.Error(err))
		c.Close()
		return nil, err
	}
	return tlsC, nil
}

// selectTransport returns the RoundTripper for a session.
//
// Every transport is shared per endpoint. In particular, a shared HTTP/3
// transport multiplexes all sessions over a warm QUIC connection; creating a
// new transport per local connection wastes a UDP socket and a full QUIC/TLS
// handshake on every dial.
func selectTransport(protocol string, cfg *Config, nextProtos []string, isTLS bool, hostPort string) (http.RoundTripper, bool) {
	if protocol == "h3" {
		key := protocol + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint + "|" + strings.Join(nextProtos, ",")
		transportMu.Lock()
		defer transportMu.Unlock()
		if rt, ok := transportCache[key]; ok {
			return rt, false
		}
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/3 (QUIC) 作为传输")
		rt := &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    true,
				ServerName:            cfg.SNI,
				NextProtos:            []string{"h3"},
				VerifyPeerCertificate: verifyFingerprint(cfg.CertificateFingerprint),
			},
			QUICConfig: &quic.Config{
				KeepAlivePeriod: 90 * time.Second,
			},
		}
		transportCache[key] = rt
		return rt, false
	}

	key := protocol + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint + "|" + strings.Join(nextProtos, ",")

	transportMu.Lock()
	defer transportMu.Unlock()
	if rt, ok := transportCache[key]; ok {
		logger.Debug("♻️ [Dialer] 复用共享 Transport", zap.String("protocol", protocol), zap.String("hostport", hostPort))
		return rt, false
	}

	p := &dialParams{hostPort: hostPort, sni: cfg.SNI, fingerprint: cfg.CertificateFingerprint, nextProtos: nextProtos, isTLS: isTLS}

	var rt http.RoundTripper
	if protocol == "h2" {
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/2 作为传输")
		rt = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return p.dial(ctx, network, addr)
			},
		}
	} else {
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/1.1 作为传输")
		t1 := &http.Transport{
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        sharedMaxIdleConns,
			MaxIdleConnsPerHost: sharedMaxIdleConns,
			DisableKeepAlives:   false,
			IdleConnTimeout:     90 * time.Second,
		}
		t1.DialTLSContext = p.dial
		t1.DialContext = p.dial
		rt = t1
	}
	transportCache[key] = rt
	return rt, false
}

func DialXHTTP(ctx context.Context, serverURL *url.URL, cfg *Config, targetAddr, network string) (net.Conn, error) {
	isTLS := serverURL.Scheme == "https"
	basePort := serverURL.Port()
	if basePort == "" {
		if isTLS {
			basePort = "443"
		} else {
			basePort = "80"
		}
	}
	// Deliberately NOT writing cfg.Path here. cfg is shared by every session
	// spawned from this listener, so mutating it from concurrent dials is a
	// data race — and pointless, since runClient already seeds Path from the
	// server URL. reqURL below reads cfg.Path, which is that same value.
	nextProtos := buildNextProtos(cfg.ALPN)
	hostPort := net.JoinHostPort(serverURL.Hostname(), basePort)

	protocol, err := detectProtocol(ctx, cfg, nextProtos, isTLS, hostPort)
	if err != nil {
		return nil, err
	}

	// The connection pool is shared, so a session no longer owns one specific
	// socket and there is no meaningful per-session local address to report.
	localAddr := stringAddr("tunnel-local")
	remoteAddr := stringAddr(hostPort)

	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	reqURL := fmt.Sprintf("%s://%s%s", scheme, hostPort, cfg.Path)
	sessionID := generateRandomHex(16)

	rt, ownTransport := selectTransport(protocol, cfg, nextProtos, isTLS, hostPort)

	client := &http.Client{Transport: rt, Timeout: clientRequestTimeout}
	virtualConn := newMeekVirtualConn(sessionID, localAddr, remoteAddr)

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	pumpDone := make(chan struct{})
	logger.Debug("🚀 启动客户端 HTTP 数据泵", zap.String("session", sessionID), zap.String("target", targetAddr), zap.String("transport", fmt.Sprintf("%T", rt)))

	go func() {
		defer close(pumpDone)
		defer virtualConn.Close()
		defer logger.Debug("💀 客户端 HTTP 数据泵已停止", zap.String("session", sessionID))

		var ackedByServer uint64
		var dispatchSeq uint64
		var windowMu sync.Mutex
		var triggerRetry int32
		var emptyPollers int32

		restartCount := 0

		for !virtualConn.isClosed() && !virtualConn.closePending() {
			if restartCount > 0 {
				if restartCount > 6 {
					logger.Error("❌ [Pump] 数据泵重启次数达到上限 (超过 90 秒)，放弃恢复，关闭隧道", zap.String("session", sessionID))
					break
				}

				backoff := time.Duration(1<<restartCount) * time.Second
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
				logger.Warn("⚠️ [Pump] 发生严重网络错误，数据泵已退出，准备指数退避后自动重启",
					zap.String("session", sessionID),
					zap.Int("restarts", restartCount),
					zap.Duration("backoff", backoff),
				)
				select {
				case <-time.After(backoff):
				case <-pumpCtx.Done():
				}
			}
			if virtualConn.isClosed() || virtualConn.closePending() || pumpCtx.Err() != nil {
				break
			}

			var consecutiveErrors int32
			var wg sync.WaitGroup

			// active is the live worker count, nextWorkerID the id handed to
			// the next one. spawn() is only ever called from inside a worker,
			// so the WaitGroup counter is never zero while it runs and the
			// Add/Wait race the docs warn about cannot happen.
			var active int32
			var nextWorkerID int32
			var spawn func()

			// scaleUp keeps enough senders in flight to drain the backlog
			// without pinning idle long polls against the CDN. It runs at the
			// top of every iteration so a burst that lands while the only
			// awake worker is parked in a long poll still gets senders within
			// one loop, instead of up to longPollTimeout later.
			var scaleUp func()

			worker := func(id int) {
				defer wg.Done()
				defer atomic.AddInt32(&active, -1)
				for !virtualConn.isClosed() {
					scaleUp()
					windowMu.Lock()
					currentAck := atomic.LoadUint64(&ackedByServer)
					if dispatchSeq < currentAck {
						dispatchSeq = currentAck
					}
					upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(currentAck, dispatchSeq, maxsendBufSize)
					if len(upData) == 0 {
						// Shutting down and nothing left to hand over:
						// leave instead of parking on a long poll.
						if virtualConn.closePending() {
							windowMu.Unlock()
							break
						}
						// Extra workers exist only to drain a backlog.
						// Once it is gone they retire; the permanent ones
						// stay to keep the tunnel alive.
						if id >= minPumpWorkers {
							windowMu.Unlock()
							return
						}
						if atomic.LoadInt32(&emptyPollers) >= 1 {
							windowMu.Unlock()
							virtualConn.writeBuf.wait()
							continue
						}
						atomic.AddInt32(&emptyPollers, 1)
						dispatchSeq = currentSeq
					} else {
						dispatchSeq = currentSeq + uint64(len(upData))
					}
					windowMu.Unlock()

					var method string
					var bodyReader io.Reader
					if len(upData) > 0 {
						method = http.MethodPost
						// The transport owns upData until it closes the
						// body — see pooledBody. Never recycle it by hand.
						bodyReader = newPooledBody(upData, upBufPtr)
					} else {
						method = http.MethodGet
						bodyReader = http.NoBody
					}

					req, _ := http.NewRequestWithContext(pumpCtx, method, reqURL, bodyReader)

					if len(upData) > 0 {
						req.ContentLength = int64(len(upData))
					} else {
						q := req.URL.Query()
						q.Set("t", strconv.FormatInt(time.Now().UnixNano(), 36))
						req.URL.RawQuery = q.Encode()
					}

					req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					req.Header.Set("Pragma", "no-cache")
					req.Header.Set("Accept", "*/*")
					req.Header.Set("Accept-Encoding", "identity")
					req.Header.Set("Connection", "keep-alive")
					if cfg.Host != "" {
						req.Host = cfg.Host
					} else if cfg.SNI != "" {
						req.Host = cfg.SNI
					}
					req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5410.0 Safari/537.36 Client/"+versionString())
					if cfg.Password != "" {
						req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Password)
						// Proxy-Authorization is hop-by-hop and is commonly stripped
						// by CDNs and reverse proxies. The server also accepts this
						// end-to-end header, keeping authenticated tunnels working
						// behind standards-compliant intermediaries.
						req.Header.Set("X-Auth-Token", cfg.Password)
					}
					req.Header.Set("X-Target", targetAddr)
					req.Header.Set("X-Network", network)
					req.Header.Set("X-Session-ID", sessionID)

					virtualConn.readCond.L.Lock()
					myAck := virtualConn.nextReadSeq
					virtualConn.readCond.L.Unlock()

					req.Header.Set("X-Seq", strconv.FormatUint(currentSeq, 10))
					req.Header.Set("X-Ack", strconv.FormatUint(myAck, 10))
					if len(upData) > 0 {
						req.Header.Set("Content-Type", "application/octet-stream")
					}
					if atomic.CompareAndSwapInt32(&triggerRetry, 1, 0) {
						req.Header.Set("X-Retry", "1")
					}

					logger.Debug("📤 [Pump] 发起 HTTP 轮询请求",
						zap.String("session", sessionID),
						zap.Uint64("Client_Seq", currentSeq),
						zap.Uint64("Client_Ack", myAck),
						zap.Int("Up_Bytes", len(upData)),
						zap.Int("worker", id),
					)

					resp, err := client.Do(req)

					if len(upData) == 0 {
						atomic.AddInt32(&emptyPollers, -1)
						// Must take the lock: a bare cond.Broadcast() can be
						// missed by a waiter sitting between its predicate
						// check and Wait(), which strands it until the next
						// write or the long poll returns.
						virtualConn.writeBuf.broadcast()
					}

					if err != nil {
						if pumpCtx.Err() != nil {
							logger.Debug("🛑 [Pump] 收到 Context 取消信號，Worker 退出", zap.Int("worker", id))
							break
						}
						logger.Debug("⚠️ [Pump] HTTP 轮询失败，准备重试", zap.String("session", sessionID), zap.Error(err))
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)
						if atomic.AddInt32(&consecutiveErrors, 1) > 20 {
							logger.Warn("❌ [Pump] 连续错误过多，Worker 退出准备触发数据泵重启", zap.Int("worker", id))
							break
						}
						time.Sleep(300 * time.Millisecond)
						continue
					}
					atomic.StoreInt32(&consecutiveErrors, 0)

					var sAck uint64
					if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" {
						sAck, _ = strconv.ParseUint(sAckStr, 10, 64)
						for {
							old := atomic.LoadUint64(&ackedByServer)
							if sAck <= old || atomic.CompareAndSwapUint64(&ackedByServer, old, sAck) {
								break
							}
						}
					}

					if resp.StatusCode != http.StatusOK {
						downBuf := bytesBufPool.Get().(*bytes.Buffer)
						downBuf.Reset()
						downBuf.ReadFrom(resp.Body)
						bodyErr := downBuf.Bytes()
						resp.Body.Close()

						// An edge-generated response carries no trustworthy X-Ack.
						// Rewind to the last acknowledgement before retrying, otherwise
						// a rejected POST has already advanced dispatchSeq and its
						// upload bytes are silently skipped forever. Replaying from the
						// peer's ACK is safe: the server drops duplicate sequence data.
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)

						// 504 (Gateway Timeout) / 524 (Cloudflare Timeout) are normal
						// long-poll timeouts — go straight to the next poll round.
						if resp.StatusCode == http.StatusGatewayTimeout || resp.StatusCode == 524 {
							logger.Debug("⏱️ [Pump] CDN/网关轮询超时，立即发起下一轮轮询",
								zap.String("session", sessionID),
								zap.Int("status", resp.StatusCode),
							)
							bytesBufPool.Put(downBuf)
							continue
						}

						// 429 Too Many Requests: hit a CDN/WAF rate limit, back off briefly.
						if resp.StatusCode == http.StatusTooManyRequests {
							logger.Warn("⚠️ [Pump] 触发 CDN/WAF 频控限制 (429 Too Many Requests)，正在退避等待...",
								zap.String("session", sessionID),
							)
							bytesBufPool.Put(downBuf)
							time.Sleep(1 * time.Second)
							continue
						}

						logger.Error("❌ [Pump] 收到异常 HTTP 状态码",
							zap.String("session", sessionID),
							zap.Int("status", resp.StatusCode),
							zap.String("error_body", string(bodyErr)),
						)

						bytesBufPool.Put(downBuf)
						time.Sleep(1 * time.Second)
						continue
					}

					sSeqStr := resp.Header.Get("X-Seq")
					sSeq, _ := strconv.ParseUint(sSeqStr, 10, 64)

					bufPtr := sendBuf.Get().(*[]byte)
					readChunk := *bufPtr
					var totalDownBytes int
					var errBody error
					downSeq := sSeq

					for {
						n, err := resp.Body.Read(readChunk)
						if n > 0 {
							virtualConn.PutReadData(downSeq, readChunk[:n])
							downSeq += uint64(n)
							totalDownBytes += n
						}
						if err != nil {
							if err != io.EOF {
								errBody = err
							}
							break
						}
					}
					resp.Body.Close()
					safelyPutSendBuf(bufPtr)

					if errBody != nil {
						logger.Warn("⚠️ [Pump] 读取下行 Body 失败或异常中断，触发安全重传", zap.Error(errBody))

						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)
						time.Sleep(300 * time.Millisecond)
						continue
					}

					logger.Debug("📥 [Pump] 收到 HTTP 轮询响应",
						zap.String("session", sessionID),
						zap.Uint64("Server_Seq", sSeq),
						zap.Uint64("Server_Ack", sAck),
						zap.Int("Down_Bytes", totalDownBytes),
					)

					if totalDownBytes == 0 && sSeqStr != "" {
						virtualConn.PutReadData(sSeq, nil)
					}

					// Graceful shutdown: once everything buffered has been
					// handed to the peer there is nothing left for this
					// worker to do, so stop instead of opening a new poll.
					if virtualConn.closePending() {
						windowMu.Lock()
						pending := virtualConn.writeBuf.undispatched(dispatchSeq)
						windowMu.Unlock()
						if pending == 0 {
							break
						}
					}

					if len(upData) == 0 && totalDownBytes == 0 && virtualConn.writeBuf.Len() == 0 {
						time.Sleep(100 * time.Millisecond)
					}
				}
			}

			spawn = func() {
				id := int(atomic.AddInt32(&nextWorkerID, 1)) - 1
				atomic.AddInt32(&active, 1)
				wg.Add(1)
				go worker(id)
			}

			scaleUp = func() {
				windowMu.Lock()
				pending := virtualConn.writeBuf.undispatched(dispatchSeq)
				windowMu.Unlock()

				want := int32(minPumpWorkers)
				if pending > defaultChunkSize {
					want += int32(pending / defaultChunkSize)
				}
				if want > maxPumpWorkers {
					want = maxPumpWorkers
				}
				for atomic.LoadInt32(&active) < want &&
					!virtualConn.isClosed() && !virtualConn.closePending() {
					spawn()
				}
			}

			// Start the permanent workers; scaleUp adds elastic ones as
			// soon as there is a backlog worth parallelising.
			for i := 0; i < minPumpWorkers; i++ {
				spawn()
			}

			wg.Wait()
			restartCount++
		}

		// All current transports are shared. Keep the ownership guard so a
		// future per-session transport can still clean itself up without ever
		// closing a pooled HTTP/1.1, H2, or H3 connection.
		if ownTransport {
			if rt3, ok := rt.(*http3.Transport); ok {
				logger.Debug("🧹 [Dialer] 关闭 HTTP/3 Transport", zap.String("session", sessionID))
				rt3.Close()
			}
		}
	}()

	closer := func() error {
		// Ask the pump to ship whatever is still queued — most importantly the
		// EOF/close frame — instead of tearing the session down immediately and
		// silently discarding it. The server would otherwise hold the target
		// connection open until the idle cleaner noticed, 120s later.
		virtualConn.requestClose()

		if virtualConn.writeBuf.Len() == 0 {
			pumpCancel()
		} else {
			select {
			case <-pumpDone:
			case <-time.After(closeFlushTimeout):
				logger.Debug("⏱️ [Pump] 关闭帧 flush 超时，强制取消数据泵", zap.String("session", sessionID))
				pumpCancel()
			}
		}
		return virtualConn.Close()
	}

	return newXhttpFramedConn(virtualConn, virtualConn, closer, virtualConn.local, virtualConn.remote), nil
}

// idleRefresher keeps the local socket's idle deadline alive while data flows
// out to the client.
//
// The deadline exists to reap connections that have gone quiet in BOTH
// directions, but it was only ever extended by the read loop. During a long
// download the local client sends nothing, so the read loop sits blocked while
// the deadline runs down and kills a perfectly healthy tunnel the moment it
// expires. Wrapping the downlink writer extends it on real traffic instead.
// A connection silent in both directions still times out — the reap is intact.
type idleRefresher struct {
	net.Conn
	idle time.Duration
}

func (c *idleRefresher) Write(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

func runClient(ctx context.Context, listenStr, serverURLStr, forwardTarget, psk, customSNI, customHost, alpn string, dump bool, fingerprint string) {
	if !strings.Contains(listenStr, "://") {
		listenStr = "tcp://" + listenStr
	}
	u, err := url.Parse(listenStr)
	if err != nil {
		logger.Fatal("解析失败", zap.Error(err))
	}

	serverURL, err := url.Parse(serverURLStr)
	if err != nil {
		logger.Fatal("解析失败", zap.Error(err))
	}

	sni := serverURL.Hostname()
	if customSNI != "" {
		sni = customSNI
	}
	host := serverURL.Host
	if customHost != "" {
		host = customHost
	}

	cfg := &Config{Password: psk, Path: serverURL.Path, SNI: sni, Host: host, ALPN: alpn, CertificateFingerprint: fingerprint}
	logger.Debug("🔧 客户端配置初始化", zap.String("SNI", cfg.SNI), zap.String("Host", cfg.Host), zap.String("Target", forwardTarget), zap.String("ALPN", cfg.ALPN), zap.String("CertificateFingerprint", fingerprint))

	// The TLS dials below set InsecureSkipVerify and only install
	// verifyFingerprint, which is a no-op when no fingerprint is configured.
	// That combination means the server certificate is accepted sight unseen,
	// so an on-path attacker can terminate the tunnel. Say so loudly rather
	// than letting the operator assume the padlock is real.
	if serverURL.Scheme == "https" && fingerprint == "" {
		logger.Warn("⚠️ 未配置证书指纹 (fingerprint)：TLS 证书将不被校验，存在中间人风险。建议设置 fingerprint 做证书锁定。")
	}

	if u.Scheme == "tcp" {
		ln, err := net.Listen("tcp", u.Host)
		if err != nil {
			logger.Fatal("TCP监听失败", zap.Error(err))
		}
		logger.Info("🚀 Client 启动成功", zap.String("addr", u.Host), zap.String("ALPN", alpn))
		go func() {
			<-ctx.Done()
			logger.Info("🛑 收到退出信号，正在关闭客户端 TCP 监听...")
			ln.Close()
		}()

		var activeTCPConns int32

		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("❌ Accept 接收本地连接失败", zap.Error(err))
				continue
			}

			if atomic.LoadInt32(&activeTCPConns) >= int32(maxClientSessions) {
				logger.Warn("❌ [TCP] 拒绝本地连接: 达到最大并发连接数限制", zap.Int("limit", maxClientSessions), zap.String("client", conn.RemoteAddr().String()))
				conn.Close()
				continue
			}
			atomic.AddInt32(&activeTCPConns, 1)

			go func() {
				defer atomic.AddInt32(&activeTCPConns, -1)
				defer conn.Close()
				connID := generateRandomHex(4)
				logger.Debug("🔌 [TCP] 收到本地客户端连接", zap.String("id", connID), zap.String("client", conn.RemoteAddr().String()))

				logger.Debug("⏳ [TCP] 正在拨号远程 XHTTP 隧道...", zap.String("id", connID), zap.String("server", serverURL.Host))
				xc, err := DialXHTTP(ctx, serverURL, cfg, forwardTarget, "tcp")
				if err != nil {
					logger.Error("❌ [TCP] XHTTP 隧道拨号失败", zap.String("id", connID), zap.Error(err))
					return
				}
				defer xc.Close()
				logger.Debug("✅ [TCP] XHTTP 隧道拨号成功", zap.String("id", connID))

				var clientConn net.Conn = conn
				if dump {
					clientConn = &DumpConn{Conn: conn, Prefix: "Client Local - " + connID}
				}

				clientConn.SetDeadline(time.Now().Add(clientIdleTimeout))

				var closeOnce sync.Once
				closeBoth := func() {
					closeOnce.Do(func() {
						if xfc, ok := xc.(*xhttpFramedConn); ok {
							_ = xfc.WriteCloseFrame()
						}
						_ = clientConn.Close()
						_ = xc.Close()
					})
				}
				defer closeBoth()

				go func() {
					defer closeBoth()
					buf := make([]byte, 32*1024)
					// Local error variable: the downlink below owns the
					// outer `err`, and both run concurrently.
					var upErr error
					var written int64
					for {
						nr, er := clientConn.Read(buf)
						if nr > 0 {
							clientConn.SetDeadline(time.Now().Add(clientIdleTimeout))
							nw, ew := xc.Write(buf[:nr])
							if nw > 0 {
								written += int64(nw)
							}
							if ew != nil {
								upErr = ew
								break
							}
						}
						if er != nil {
							upErr = er
							break
						}
					}

					if upErr != nil && upErr != io.EOF {
						logger.Debug("⚠️ [TCP] 上行转发 (Local->Server) 异常结束", zap.String("id", connID), zap.Int64("bytes", written), zap.Error(upErr))
					} else {
						logger.Debug("🛑 [TCP] 上行转发 (Local->Server) 正常结束", zap.String("id", connID), zap.Int64("bytes", written))
					}
				}()

				downN, downErr := io.Copy(&idleRefresher{Conn: clientConn, idle: clientIdleTimeout}, xc)
				if downErr != nil && downErr != io.EOF {
					logger.Debug("⚠️ [TCP] 下行转发 (Server->Local) 异常结束", zap.String("id", connID), zap.Int64("bytes", downN), zap.Error(downErr))
				} else {
					logger.Debug("🛑 [TCP] 下行转发 (Server->Local) 正常结束", zap.String("id", connID), zap.Int64("bytes", downN))
				}
				closeBoth()
				logger.Debug("💀 [TCP] 本地会话清理完毕", zap.String("id", connID))
			}()
		}
	} else if u.Scheme == "udp" {
		pc, err := net.ListenPacket("udp", u.Host)
		if err != nil {
			logger.Fatal("UDP监听失败", zap.Error(err))
		}

		if dump {
			pc = &DumpPacketConn{
				PacketConn: pc,
				Prefix:     "Client Local[UDP]",
			}
		}

		logger.Info("🚀 Client(UDP) 启动成功", zap.String("addr", u.Host))
		go func() {
			<-ctx.Done()
			logger.Info("🛑 收到退出信号，正在关闭客户端 UDP 监听...")
			pc.Close()
		}()

		type udpSession struct {
			conn       net.Conn
			lastActive int64
		}
		sessionMap := make(map[string]*udpSession)
		var mu sync.Mutex

		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now().Unix()
					mu.Lock()
					for addr, sess := range sessionMap {
						if now-atomic.LoadInt64(&sess.lastActive) > 30 {
							logger.Debug("🧹 [UDP] 清理长时间空闲的本地 UDP 会话", zap.String("client", addr))
							sess.conn.Close()
							delete(sessionMap, addr)
						}
					}
					mu.Unlock()
				}
			}
		}()

		buf := make([]byte, maxUDPFrameSize)

		for {
			n, cAddr, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("❌ [UDP] 本地读取失败", zap.Error(err))
				continue
			}

			key := cAddr.String()

			mu.Lock()
			sess, exists := sessionMap[key]
			full := len(sessionMap) >= maxClientSessions
			mu.Unlock()

			if !exists {
				if full {
					logger.Warn("❌ [UDP] 拒绝本地新会话: 达到最大并发限制", zap.Int("limit", maxClientSessions), zap.String("client", key))
					continue
				}

				connID := generateRandomHex(4)
				logger.Debug("🔌 [UDP] 发现新本地客户端，准备建立隧道", zap.String("id", connID), zap.String("client", key))

				// Dial outside the lock: DialXHTTP can block for seconds on
				// the network, and holding mu meanwhile would stall the
				// reaper and every other local UDP client with it.
				xc, dialErr := DialXHTTP(ctx, serverURL, cfg, forwardTarget, "udp")
				if dialErr != nil {
					logger.Error("❌ [UDP] XHTTP 隧道拨号失败", zap.String("id", connID), zap.Error(dialErr))
					continue
				}
				logger.Debug("✅ [UDP] XHTTP 隧道拨号成功", zap.String("id", connID))

				mu.Lock()
				if racing, ok := sessionMap[key]; ok {
					// Another datagram from the same client won the race
					// while we were dialling; its tunnel is the one to use.
					mu.Unlock()
					xc.Close()
					sess = racing
				} else if len(sessionMap) >= maxClientSessions {
					mu.Unlock()
					xc.Close()
					logger.Warn("❌ [UDP] 拒绝本地新会话: 达到最大并发限制", zap.Int("limit", maxClientSessions), zap.String("client", key))
					continue
				} else {
					sess = &udpSession{conn: xc, lastActive: time.Now().Unix()}
					sessionMap[key] = sess
					mu.Unlock()

					go func(addr net.Addr, session *udpSession, id string) {
						defer session.conn.Close()
						defer func() {
							mu.Lock()
							delete(sessionMap, addr.String())
							mu.Unlock()
							logger.Debug("💀 [UDP] 本地会话清理完毕", zap.String("id", id), zap.String("client", addr.String()))
						}()

						dBuf := make([]byte, maxUDPFrameSize)
						for {
							l, err := readUDPFrameInto(session.conn, dBuf)
							if err != nil {
								if err != io.EOF && !strings.Contains(err.Error(), "closed network connection") {
									logger.Debug("⚠️ [UDP] 下行读取 Frame 失败", zap.String("id", id), zap.Error(err))
								} else {
									logger.Debug("🛑 [UDP] 下行监听结束 (EOF/Closed)", zap.String("id", id))
								}
								return
							}
							atomic.StoreInt64(&session.lastActive, time.Now().Unix())
							pc.WriteTo(dBuf[:l], addr)
						}
					}(cAddr, sess, connID)
				}
			}

			atomic.StoreInt64(&sess.lastActive, time.Now().Unix())
			if err := writeUDPFrame(sess.conn, buf[:n]); err != nil {
				logger.Debug("⚠️ [UDP] 写入上行 Frame 失败", zap.String("client", key), zap.Error(err))
			}
		}
	}
}
