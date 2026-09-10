package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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

const (
	// defaultMaxClientConns caps concurrent local connections per client
	// when ClientConfig.MaxConns is unset.
	defaultMaxClientConns = 2000

	// defaultClientIdleTimeout is how long a local TCP connection may stay
	// silent before it is dropped. Refreshed on every successful read;
	// configurable via ClientConfig.IdleTimeout.
	defaultClientIdleTimeout = 15 * time.Minute
)

var (
	// transportCache holds one HTTP/1.1 or h2 transport per endpoint. Sessions
	// share it so they reuse a single connection pool instead of each holding
	// up to workerCount sockets, which is what exhausted file descriptors and
	// hammered CDNs with connection churn. The cache is intentionally
	// package-level: transports are keyed per endpoint and sharing them
	// across Client instances in one process is safe and desirable.
	transportMu    sync.Mutex
	transportCache = map[string]http.RoundTripper{}

	// protoCache memoises the protocol negotiated for an endpoint. Package
	// level for the same reason as transportCache.
	protoMu    sync.Mutex
	protoCache = map[string]protoEntry{}

	// customTransportSerial gives clients with injected network dialers an
	// isolated transport cache namespace unless the embedder supplies an
	// explicit TransportKey. Reusing a transport created for another Android
	// Network / bound interface would route traffic through the wrong network.
	customTransportSerial atomic.Uint64
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

// pollHandle carries the cancel func of one in-flight empty GET so the closer
// can abort it instead of waiting out the server's longPollTimeout.
type pollHandle struct {
	cancel context.CancelFunc
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

func probeHTTP3(ctx context.Context, hostPort, sni string, timeout time.Duration, fingerprint string, dial QUICDialFunc, lg *zap.Logger) (bool, error) {
	logger := lg
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
		var sess *quic.Conn
		var err error
		if dial != nil {
			sess, err = dial(cctx, hostPort, tlsConf, qconf)
		} else {
			sess, err = quic.DialAddr(cctx, hostPort, tlsConf, qconf)
		}
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
func detectProtocol(ctx context.Context, cfg *DialConfig, nextProtos []string, isTLS bool, hostPort string) (string, error) {
	logger := cfg.lg()
	if !isTLS {
		if slices.Contains(nextProtos, "h2") {
			return "h2", nil
		}
		return "http/1.1", nil
	}

	key := strings.Join(nextProtos, ",") + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint + "|" + cfg.TransportKey
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
func sniffProtocol(ctx context.Context, cfg *DialConfig, nextProtos []string, hostPort string) (string, error) {
	logger := cfg.lg()
	alpnPref := strings.ToLower(strings.TrimSpace(cfg.ALPN))
	if alpnPref == "h3" || alpnPref == "auto" {
		logger.Debug("尝试使用 QUIC/HTTP3 探测", zap.String("hostport", hostPort), zap.String("sni", cfg.SNI))
		ok, perr := probeHTTP3(ctx, hostPort, cfg.SNI, h3ProbeTimeout, cfg.CertificateFingerprint, cfg.QUICDial, logger)
		if ok && perr == nil {
			logger.Debug("QUIC/HTTP3 探测成功，使用 HTTP/3", zap.String("host", hostPort))
			return "h3", nil
		}
		logger.Debug("QUIC/HTTP3 探测失败，回落至 TCP/TLS 探测", zap.String("host", hostPort), zap.Error(perr))
	}

	var conn net.Conn
	var err error
	if cfg.DialContext != nil {
		conn, err = cfg.DialContext(ctx, "tcp", hostPort)
	} else {
		conn, err = (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", hostPort)
	}
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
	log         *zap.Logger
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func (p *dialParams) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	logger := p.log
	var c net.Conn
	var err error
	if p.dialContext != nil {
		c, err = p.dialContext(ctx, "tcp", p.hostPort)
	} else {
		c, err = (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", p.hostPort)
	}
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
func selectTransport(protocol string, cfg *DialConfig, nextProtos []string, isTLS bool, hostPort string) (http.RoundTripper, bool) {
	logger := cfg.lg()
	if protocol == "h3" {
		key := protocol + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint + "|" + strings.Join(nextProtos, ",") + "|" + cfg.TransportKey
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
				// KeepAlivePeriod must stay below MaxIdleTimeout: pings keep a
				// healthy path alive while MaxIdleTimeout bounds how long a
				// silently-dead one (server restarted on the same port — its
				// socket close sends no QUIC closure frame) is trusted before
				// the next request errors out and the transport re-dials.
				KeepAlivePeriod: 10 * time.Second,
				MaxIdleTimeout:  15 * time.Second,
			},
			Dial: cfg.QUICDial,
		}
		transportCache[key] = rt
		return rt, false
	}

	key := protocol + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint + "|" + strings.Join(nextProtos, ",") + "|" + cfg.TransportKey

	transportMu.Lock()
	defer transportMu.Unlock()
	if rt, ok := transportCache[key]; ok {
		logger.Debug("♻️ [Dialer] 复用共享 Transport", zap.String("protocol", protocol), zap.String("hostport", hostPort))
		return rt, false
	}

	p := &dialParams{hostPort: hostPort, sni: cfg.SNI, fingerprint: cfg.CertificateFingerprint, nextProtos: nextProtos, isTLS: isTLS, log: cfg.lg(), dialContext: cfg.DialContext}

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

func DialXHTTP(ctx context.Context, serverURL *url.URL, cfg *DialConfig, targetAddr, network string) (net.Conn, error) {
	logger := cfg.lg()
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
	// spawned from this client, so mutating it from concurrent dials is a
	// data race — and pointless, since NewClient already seeds Path from the
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

	// Stream mode: one persistent GET carrying the downlink plus long POSTs
	// carrying the uplink. Falls back to the poll pump below when the
	// negotiation concludes the path cannot stream (see stream_client.go).
	modeKey := cfg.streamModeKey(protocol, hostPort)
	if cfg.streamDownlinkEnabled(modeKey) {
		uploadChunk := currentMaxSendBufSize()
		if cfg.ChunkSizeKB != 0 {
			uploadChunk = chunkSizeBytes(cfg.ChunkSizeKB)
		}
		conn, serr := dialXHTTPStream(streamDialArgs{
			ctx: ctx, cfg: cfg, rt: rt, ownTransport: ownTransport,
			client: &http.Client{Transport: rt},
			reqURL: reqURL, sessionID: sessionID, key: modeKey,
			targetAddr: targetAddr, network: network,
			localAddr: localAddr, remoteAddr: remoteAddr,
			uploadChunk: uploadChunk, logger: logger,
			events: cfg.events,
		})
		if serr == nil {
			return conn, nil
		}
		if !errors.Is(serr, errStreamUnavailable) {
			return nil, serr
		}
		logger.Warn("⚠️ [Stream] 流式下行在当前路径不可用，本会话回退长轮询",
			zap.String("session", sessionID), zap.Error(serr))
	}

	client := &http.Client{Transport: rt, Timeout: clientRequestTimeout}
	virtualConn := newMeekVirtualConn(sessionID, localAddr, remoteAddr, logger)
	uploadChunkSize := currentMaxSendBufSize()
	if cfg.ChunkSizeKB != 0 {
		uploadChunkSize = chunkSizeBytes(cfg.ChunkSizeKB)
	}

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	pumpDone := make(chan struct{})
	// pollSlot identifies the worker currently parked in an empty GET long
	// poll (the server holds it for the full longPollTimeout). The closer
	// cancels it to skip the pointless wait; slots are pointers so the
	// returning worker can tell whether its slot is still the live one.
	var pollMu sync.Mutex
	var pollSlot *pollHandle
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
					upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(currentAck, dispatchSeq, uploadChunkSize)
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

					// Empty polls (GETs) run on a child context the closer can
					// abort: the server parks them for the full longPollTimeout
					// when no downlink exists, and they carry no body, so
					// aborting one at close time is lossless. POSTs stay on
					// pumpCtx — the close frame may ride the last one.
					reqCtx := pumpCtx
					var handle *pollHandle
					if len(upData) == 0 {
						var cancelReq context.CancelFunc
						reqCtx, cancelReq = context.WithCancel(pumpCtx)
						handle = &pollHandle{cancel: cancelReq}
						pollMu.Lock()
						pollSlot = handle
						pollMu.Unlock()
						if virtualConn.closePending() {
							cancelReq()
						}
					}

					req, _ := http.NewRequestWithContext(reqCtx, method, reqURL, bodyReader)

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
					// No Connection header: it is a connection-specific field that
					// RFC 7540 forbids over HTTP/2, and Go's h2 transport strips it
					// on egress anyway. A strict CDN/WAF would reject a request that
					// carries it on an h2 stream.
					if cfg.Host != "" {
						req.Host = cfg.Host
					} else if cfg.SNI != "" {
						req.Host = cfg.SNI
					}
					req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5410.0 Safari/537.36 Client/"+Version)
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

					if handle != nil {
						// Clear the slot so the closer stops tracking this poll,
						// but do NOT cancel yet: the response body is consumed
						// below, and cancelling the request context kills the
						// stream mid-body. handle.cancel() runs after each
						// resp.Body.Close() instead.
						pollMu.Lock()
						if pollSlot == handle {
							pollSlot = nil
						}
						pollMu.Unlock()
					}

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
						// An empty poll aborted by the closer is not a network
						// failure: the pump is shutting down, so stop instead of
						// retrying and parking another 5s long poll.
						if handle != nil && (virtualConn.closePending() || virtualConn.isClosed()) {
							logger.Debug("🛑 [Pump] 关闭时中止空轮询，Worker 退出", zap.Int("worker", id))
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
					} else if resp.StatusCode == http.StatusOK {
						// A 200 without X-Ack means an intermediary dropped the
						// header; the uplink window cannot drain without it. The
						// next poll that carries X-Ack recovers, so this is a
						// diagnostic, not a retry trigger.
						logger.Warn("⚠️ [Pump] 200 响应缺少 X-Ack 头（疑似被 CDN/代理剥离），上行确认停滞", zap.String("session", sessionID))
					}

					if resp.StatusCode != http.StatusOK {
						downBuf := bytesBufPool.Get().(*bytes.Buffer)
						downBuf.Reset()
						downBuf.ReadFrom(resp.Body)
						bodyErr := downBuf.Bytes()
						resp.Body.Close()
						if handle != nil {
							handle.cancel()
						}

						// An edge-generated response carries no trustworthy X-Ack.
						// Rewind to the last acknowledgement before retrying, otherwise
						// a rejected POST has already advanced dispatchSeq and its
						// upload bytes are silently skipped forever. Replaying from the
						// peer's ACK is safe: the server drops duplicate sequence data.
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)

						// Credential rejections will not fix themselves on a retry;
						// surface them as a typed tunnel death with the real cause.
						if resp.StatusCode == http.StatusProxyAuthRequired || resp.StatusCode == http.StatusUnauthorized {
							if cfg.events != nil {
								cfg.events.emit(TunnelDied{SessionID: sessionID, Target: targetAddr, Network: network, Reason: "auth rejected", Detail: string(bodyErr)})
							}
							resp.Body.Close()
							bytesBufPool.Put(downBuf)
							return
						}
						if resp.StatusCode == http.StatusForbidden && cfg.events != nil {
							cfg.events.emit(TargetDenied{SessionID: sessionID, Target: targetAddr, Network: network})
						}

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
					if sSeqStr == "" {
						// A 200 without X-Seq cannot be placed in the reassembly
						// stream: feeding it at seq 0 would be silently dropped as a
						// stale retransmission once the read cursor has advanced, so
						// the tunnel would deadlock while the server looks healthy.
						// Treat it like an untrusted edge response — drain the body,
						// rewind to the last ack and ask the server to re-dispatch.
						logger.Warn("⚠️ [Pump] 200 响应缺少 X-Seq 头（疑似被 CDN/代理剥离），回退并重试", zap.String("session", sessionID))
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						if handle != nil {
							handle.cancel()
						}
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)
						time.Sleep(300 * time.Millisecond)
						continue
					}
					sSeq, _ := strconv.ParseUint(sSeqStr, 10, 64)

					// A CDN/WAF that ignores Accept-Encoding: identity and
					// no-transform will gzip/brotli the octet-stream body anyway.
					// The sequence numbers still advance, so the tunnel looks alive
					// in the logs, but the frame stream is now compressed garbage —
					// the classic "direct works, behind-CDN connects then breaks"
					// signature. Surface it instead of silently corrupting.
					if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
						logger.Warn("⚠️ [Pump] CDN/代理对隧道响应做了内容编码，帧流将被破坏（请在 CDN 侧对该路径禁用压缩）",
							zap.String("session", sessionID),
							zap.String("content_encoding", ce),
						)
					}

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
					if handle != nil {
						handle.cancel()
					}
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
				if pending > uploadChunkSize {
					want += int32(pending / uploadChunkSize)
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

		// Abort any parked empty long poll before waiting on pumpDone: the
		// server holds it for the full longPollTimeout (5s) when there is no
		// downlink, and it carries nothing, so waiting it out stalls every
		// Close by exactly that long. The close frame rides a POST instead.
		pollMu.Lock()
		handle := pollSlot
		pollMu.Unlock()
		if handle != nil {
			handle.cancel()
		}

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

	return newXHTTPConn(virtualConn, virtualConn, closer, virtualConn.local, virtualConn.remote, virtualConn), nil
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

// DialConfig is the low-level per-session client configuration consumed by
// [DialXHTTP]. Most embedders should use [ClientConfig] and [Client] instead;
// this type remains for custom wiring on top of the raw protocol.
type QUICDialFunc func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)

type DialConfig struct {
	// Path is the Split-HTTP endpoint path on the server (e.g. "/stream").
	Path string
	// SNI overrides the TLS SNI (ClientConfig.SNI in the SDK path).
	SNI string
	// Host overrides the HTTP Host header (ClientConfig.Host in the SDK path).
	Host string
	// Password is the pre-shared token (ClientConfig.PSK in the SDK path).
	Password string
	// ALPN selects the transport protocol: "h3", "h2", "h1" or "auto"
	// (ClientConfig.ALPN in the SDK path).
	ALPN string
	// CertificateFingerprint pins the server certificate
	// (ClientConfig.Fingerprint in the SDK path).
	CertificateFingerprint string
	// DialContext optionally supplies the TCP socket used for h1/h2 transports.
	// Embedders use it for interface binding and Android VpnService protection.
	DialContext func(context.Context, string, string) (net.Conn, error)
	// QUICDial optionally supplies the QUIC connection used by h3 transports.
	QUICDial QUICDialFunc
	// TransportKey identifies the routing policy behind the injected dialers.
	// Equal non-empty keys may share cached transports.
	TransportKey string
	// ChunkSizeKB caps each upstream HTTP request body for this session.
	// Zero uses the package default configured by SetChunkSizeKB.
	ChunkSizeKB int
	// StreamMode selects the downlink transport: "" or "auto" runs the
	// three-layer negotiation (capability header + TTFB path probe + stall
	// watchdog, cached per endpoint), "poll" forces the legacy long-poll mode,
	// "stream" forces the streaming downlink. See README.

	// log is the per-client logger, wired from ClientConfig.Logger (or the
	// package default). Unexported: embedders configure it via ClientConfig.
	log *zap.Logger

	// events is the per-client event hub, wired from SetEventHandler.
	// Unexported: embedders configure it via Client.SetEventHandler.
	events *eventHub

	// StreamMode selects the downlink transport: "" or "auto" runs the
	// three-layer negotiation (capability header + TTFB path probe + stall
	// watchdog, cached per endpoint), "poll" forces the legacy long-poll
	// mode, "stream" forces the streaming downlink. See README.
	StreamMode string
}

// lg returns the per-client logger, falling back to the package default when
// the config was built by hand without one (tests, low-level wiring).
func (c *DialConfig) lg() *zap.Logger {
	if c.log != nil {
		return c.log
	}
	return loggerPkg()
}

// ClientConfig configures a [Client]. At minimum set ServerURL and PSK;
// everything else has a sensible default.
type ClientConfig struct {
	// ServerURL is the xhttptunnel server endpoint, e.g.
	// "https://cdn.example.com:8443/stream".
	ServerURL string
	// PSK is the pre-shared token the server expects (Proxy-Authorization /
	// X-Auth-Token). Empty disables authentication.
	PSK string
	// SNI overrides the TLS SNI. Empty derives it from ServerURL's host.
	SNI string
	// Host overrides the HTTP Host header. Empty derives it from ServerURL.
	Host string
	// ALPN selects the transport protocol: "h3", "h2", "h1" or "auto"
	// (default) which probes HTTP/3 and falls back gracefully.
	ALPN string
	// StreamMode selects the downlink transport: "" or "auto" (default) runs
	// the three-layer negotiation (capability header + TTFB path probe +
	// stall watchdog, cached per endpoint), "poll" forces the legacy
	// long-poll mode, "stream" forces the streaming downlink. Invalid values
	// are rejected by NewClient.
	StreamMode string
	// Fingerprint is the expected server certificate SHA-256 fingerprint for
	// pinning. Strongly recommended: without it TLS verification is skipped
	// and an on-path attacker can terminate the tunnel.
	Fingerprint string
	// Target is where ListenAndServe forwards local connections when the
	// embedding program does not dial per-connection through DialContext.
	// Required in that mode (an empty target fails at dial time); ignored
	// when every connection is opened via DialContext. Accepts "host:port"
	// for TCP listeners; UDP listeners forward to the same host:port over
	// UDP.
	Target string
	// MaxConns caps concurrent local connections/sessions. 0 selects the
	// default (2000).
	MaxConns int
	// IdleTimeout drops a local TCP connection after this much silence. 0
	// selects the default (15 minutes). Applies to connections accepted by
	// ListenAndServe; sessions opened via DialContext are owned by their
	// caller and have no idle timeout.
	IdleTimeout time.Duration
	// Dump hex-dumps traffic on the local forwarder connections to stdout
	// (debugging only). The HTTP poll/stream leg itself is not dumped.
	Dump bool
	// Logger is the per-instance logger: every log line this client emits goes
	// here, independently of other clients in the process. Nil inherits the
	// package logger (see SetLogger). This no longer swaps the global logger.
	Logger *zap.Logger
	// DialContext and QUICDial let embedders control the underlying sockets.
	// They are optional; nil preserves the normal system dialers.
	DialContext func(context.Context, string, string) (net.Conn, error)
	QUICDial    QUICDialFunc
	// TransportKey allows clients with the same injected routing policy to
	// share cached HTTP transports. Empty isolates each injected client.
	TransportKey string
	// ChunkSizeKB caps each upstream HTTP request body for this client.
	// Zero uses the package default configured by SetChunkSizeKB.
	ChunkSizeKB int
}

// Client is an embeddable xhttptunnel client.
//
// The primary primitive is [Client.DialContext]: it returns a net.Conn whose
// bytes travel through the Split-HTTP tunnel to addr on the server side, so
// it drops into anything that accepts a dial function — most notably
// http.Transport's DialContext for routing an entire HTTP client through the
// tunnel.
//
// [Client.ListenAndServe] alternatively runs the same local TCP/UDP
// forwarder the xhttptunnel CLI runs, forwarding every accepted local
// connection to ClientConfig.Target.
type Client struct {
	serverURL   *url.URL
	dialCfg     *DialConfig
	target      string
	maxConns    int
	idleTimeout time.Duration
	dump        bool
	log         *zap.Logger

	// dialCount is the number of live tunnel sessions, shared by
	// ListenAndServe forwarder sessions and programmatic dials, so one
	// MaxConns budget covers both.
	dialCount atomic.Int64

	// events delivers typed lifecycle/session events to the embedder.
	events *eventHub

	mu       sync.Mutex
	closers  []io.Closer
	closed   bool
	stopOnce sync.Once
}

// NewClient validates cfg and prepares the client. It does not open any
// network connection; transports are established lazily on the first dial.
func NewClient(cfg ClientConfig) (*Client, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.StreamMode)) {
	case "", "auto", "poll", "stream":
	default:
		// Fail loudly: a typo here would silently disable (or force) the
		// streaming downlink with no other symptom.
		return nil, fmt.Errorf("tunnel: invalid StreamMode %q (want \"\", \"auto\", \"poll\" or \"stream\")", cfg.StreamMode)
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("tunnel: ServerURL is required")
	}
	serverURL, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("tunnel: parse server URL %q: %w", cfg.ServerURL, err)
	}
	if serverURL.Scheme != "http" && serverURL.Scheme != "https" {
		return nil, fmt.Errorf("tunnel: server URL must use http:// or https://, got %q", cfg.ServerURL)
	}

	sni := serverURL.Hostname()
	if cfg.SNI != "" {
		sni = cfg.SNI
	}
	host := serverURL.Host
	if cfg.Host != "" {
		host = cfg.Host
	}
	alpn := cfg.ALPN
	if alpn == "" {
		alpn = "auto"
	}
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxClientConns
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultClientIdleTimeout
	}
	transportKey := strings.TrimSpace(cfg.TransportKey)
	if transportKey == "" && (cfg.DialContext != nil || cfg.QUICDial != nil) {
		transportKey = fmt.Sprintf("custom-%d", customTransportSerial.Add(1))
	}

	c := &Client{
		serverURL:   serverURL,
		target:      cfg.Target,
		maxConns:    maxConns,
		idleTimeout: idleTimeout,
		dump:        cfg.Dump,
		events:      newEventHub(nil),
		log:         cfg.Logger,
	}
	c.dialCfg = &DialConfig{
		Password:               cfg.PSK,
		Path:                   serverURL.Path,
		SNI:                    sni,
		Host:                   host,
		ALPN:                   alpn,
		CertificateFingerprint: cfg.Fingerprint,
		DialContext:            cfg.DialContext,
		QUICDial:               cfg.QUICDial,
		TransportKey:           transportKey,
		ChunkSizeKB:            cfg.ChunkSizeKB,
		StreamMode:             cfg.StreamMode,
		events:                 c.events,
		log:                    cfg.Logger,
	}

	logger.Debug("🔧 客户端配置初始化", zap.String("SNI", sni), zap.String("Host", host), zap.String("Target", cfg.Target), zap.String("ALPN", alpn), zap.String("CertificateFingerprint", cfg.Fingerprint))

	// The TLS dials below set InsecureSkipVerify and only install
	// verifyFingerprint, which is a no-op when no fingerprint is configured.
	// That combination means the server certificate is accepted sight unseen,
	// so an on-path attacker can terminate the tunnel. Say so loudly rather
	// than letting the operator assume the padlock is real.
	if serverURL.Scheme == "https" && cfg.Fingerprint == "" {
		logger.Warn("⚠️ 未配置证书指纹 (fingerprint)：TLS 证书将不被校验，存在中间人风险。建议设置 fingerprint 做证书锁定。")
	}
	return c, nil
}

// DialContext opens a tunnelled stream to addr on the server side. network
// must be "tcp" (a byte stream) or "udp" (datagram framing — prefer DialUDP,
// which makes the framing contract explicit).
//
// The signature matches net.Dialer's, so the client plugs into
// http.Transport.DialContext, gRPC and database drivers directly. Sessions
// opened here count against ClientConfig.MaxConns; when the limit is reached
// the dial fails with [ErrSessionLimit] instead of being queued.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := c.dialTracked(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// Hand ownership to the caller: when they close the conn the session
	// slot is released through the wrapped Close.
	return conn, nil
}

// DialUDP opens a tunnelled UDP session to addr. The returned conn is NOT a
// UDP socket: it carries length-prefixed datagram frames that must be written
// and read with WriteUDPFrame / ReadUDPFrameInto (a bare Write of a datagram
// would be interpreted as a frame header). TCP-style consumers cannot use it,
// which is why UDP gets a dedicated entry point instead of hiding behind the
// net.Dialer-shaped DialContext.
func (c *Client) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return c.dialTracked(ctx, "udp", addr)
}

// ActiveDials reports the number of sessions currently open through
// DialContext/DialUDP (and the per-connection sessions of ListenAndServe).
func (c *Client) ActiveDials() int {
	return int(c.dialCount.Load())
}

// SetEventHandler installs a handler for typed tunnel lifecycle events
// (TunnelEstablished, Reconnecting, TunnelDied, TargetDenied). Events are
// dispatched on a dedicated goroutine with panic recovery, so a handler can
// never block or crash the tunnel's data path; delivery is best-effort (an
// event is dropped if the dispatch buffer is full). Call it before the first
// dial — a handler set later still receives queued events, but early events
// (the first TunnelEstablished) may already have drained.
func (c *Client) SetEventHandler(h func(Event)) {
	if c.events != nil {
		c.events.start(h)
	}
}

// emitClient delivers ev through the client's event hub (no-op when the hub
// is absent, i.e. low-level DialXHTTP users).
func (c *Client) emitClient(ev Event) {
	if c.events != nil {
		c.events.emit(ev)
	}
}

// dialTracked dials a tunnel session under the MaxConns budget. The returned
// conn's Close releases the slot. ListenAndServe shares the same counter, so
// forwarder sessions and programmatic dials together honour one limit.
// lg returns the instance logger, falling back to the package logger when
// no per-instance one was configured.
func (c *Client) lg() *zap.Logger {
	if c.log != nil {
		return c.log
	}
	return logger
}

func (c *Client) dialTracked(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("tunnel: unsupported network %q (want tcp or udp)", network)
	}
	for {
		n := c.dialCount.Add(1)
		if n <= int64(c.maxConns) {
			break
		}
		c.dialCount.Add(-1)
		return nil, fmt.Errorf("tunnel: %w (limit %d)", ErrSessionLimit, c.maxConns)
	}
	conn, err := DialXHTTP(ctx, c.serverURL, c.dialCfg, addr, network)
	if err != nil {
		c.dialCount.Add(-1)
		return nil, err
	}
	return &trackedConn{Conn: conn, client: c}, nil
}

// trackedConn releases its MaxConns slot exactly once, when the caller
// closes the session.
type trackedConn struct {
	net.Conn
	client  *Client
	release sync.Once
}

func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	t.release.Do(func() { t.client.dialCount.Add(-1) })
	return err
}

// registerCloser tracks a listener so Close() can tear it down.
func (c *Client) registerCloser(cl io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = cl.Close()
		return
	}
	c.closers = append(c.closers, cl)
}

func (c *Client) unregisterCloser(cl io.Closer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, v := range c.closers {
		if v == cl {
			c.closers = append(c.closers[:i], c.closers[i+1:]...)
			return
		}
	}
}

// Close shuts down every listener started by ListenAndServe. Sessions dialled
// through DialContext are owned by their caller and are not affected. Safe to
// call more than once.
func (c *Client) Close() error {
	var err error
	c.stopOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		closers := c.closers
		c.closers = nil
		c.mu.Unlock()
		for _, cl := range closers {
			if e := cl.Close(); e != nil && err == nil {
				err = e
			}
		}
		// Stop the event dispatch goroutine: without this, any client that
		// registered a handler via SetEventHandler leaks its dispatcher
		// (blocked on range h.ch) for the rest of the process lifetime.
		c.events.close()
	})
	return err
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// ListenAndServe runs the local forwarder: listenAddr accepts the scheme
// prefixes "tcp://" (default), "udp://" or a bare "host:port". It blocks
// until ctx is cancelled, the listener fails irrecoverably, or [Client.Close]
// is called. TCP mode forwards each accepted connection to Target over the
// tunnel; UDP mode multiplexes local peers onto per-peer tunnel sessions.
func (c *Client) ListenAndServe(ctx context.Context, listenAddr string) error {
	if !strings.Contains(listenAddr, "://") {
		listenAddr = "tcp://" + listenAddr
	}
	u, err := url.Parse(listenAddr)
	if err != nil {
		return fmt.Errorf("tunnel: parse listen address %q: %w", listenAddr, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	switch u.Scheme {
	case "tcp":
		return c.serveTCP(ctx, u.Host)
	case "udp":
		return c.serveUDP(ctx, u.Host)
	default:
		return fmt.Errorf("tunnel: unsupported listen scheme %q (want tcp:// or udp://)", u.Scheme)
	}
}

func (c *Client) serveTCP(ctx context.Context, hostPort string) error {
	logger := c.lg()
	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		return fmt.Errorf("tunnel: TCP listen %s: %w", hostPort, err)
	}
	c.registerCloser(ln)
	defer c.unregisterCloser(ln)

	logger.Info("🚀 Client 启动成功", zap.String("addr", hostPort), zap.String("ALPN", c.dialCfg.ALPN))
	go func() {
		<-ctx.Done()
		logger.Info("🛑 收到退出信号，正在关闭客户端 TCP 监听...")
		ln.Close()
	}()

	var activeTCPConns int32

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || c.isClosed() {
				return nil
			}
			logger.Error("❌ Accept 接收本地连接失败", zap.Error(err))
			continue
		}

		if atomic.LoadInt32(&activeTCPConns) >= int32(c.maxConns) {
			logger.Warn("❌ [TCP] 拒绝本地连接: 达到最大并发连接数限制", zap.Int("limit", c.maxConns), zap.String("client", conn.RemoteAddr().String()))
			conn.Close()
			continue
		}
		atomic.AddInt32(&activeTCPConns, 1)

		go func() {
			defer atomic.AddInt32(&activeTCPConns, -1)
			defer conn.Close()
			connID := generateRandomHex(4)
			logger.Debug("🔌 [TCP] 收到本地客户端连接", zap.String("id", connID), zap.String("client", conn.RemoteAddr().String()))

			logger.Debug("⏳ [TCP] 正在拨号远程 XHTTP 隧道...", zap.String("id", connID), zap.String("server", c.serverURL.Host))
			xc, err := c.dialTracked(ctx, "tcp", c.target)
			if err != nil {
				logger.Error("❌ [TCP] XHTTP 隧道拨号失败", zap.String("id", connID), zap.Error(err))
				return
			}
			defer xc.Close()
			logger.Debug("✅ [TCP] XHTTP 隧道拨号成功", zap.String("id", connID))

			var clientConn net.Conn = conn
			if c.dump {
				clientConn = &DumpConn{Conn: conn, Prefix: "Client Local - " + connID}
			}

			clientConn.SetDeadline(time.Now().Add(c.idleTimeout))

			var closeOnce sync.Once
			closeBoth := func() {
				closeOnce.Do(func() {
					if xfc, ok := xc.(*XHTTPConn); ok {
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
						clientConn.SetDeadline(time.Now().Add(c.idleTimeout))
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

			downN, downErr := io.Copy(&idleRefresher{Conn: clientConn, idle: c.idleTimeout}, xc)
			if downErr != nil && downErr != io.EOF {
				logger.Debug("⚠️ [TCP] 下行转发 (Server->Local) 异常结束", zap.String("id", connID), zap.Int64("bytes", downN), zap.Error(downErr))
			} else {
				logger.Debug("🛑 [TCP] 下行转发 (Server->Local) 正常结束", zap.String("id", connID), zap.Int64("bytes", downN))
			}
			closeBoth()
			logger.Debug("💀 [TCP] 本地会话清理完毕", zap.String("id", connID))
		}()
	}
}

func (c *Client) serveUDP(ctx context.Context, hostPort string) error {
	logger := c.lg()
	pc, err := net.ListenPacket("udp", hostPort)
	if err != nil {
		return fmt.Errorf("tunnel: UDP listen %s: %w", hostPort, err)
	}
	c.registerCloser(pc)
	defer c.unregisterCloser(pc)

	if c.dump {
		pc = &DumpPacketConn{
			PacketConn: pc,
			Prefix:     "Client Local[UDP]",
		}
	}

	logger.Info("🚀 Client(UDP) 启动成功", zap.String("addr", hostPort))
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
			if ctx.Err() != nil || c.isClosed() {
				return nil
			}
			logger.Error("❌ [UDP] 本地读取失败", zap.Error(err))
			continue
		}

		key := cAddr.String()

		mu.Lock()
		sess, exists := sessionMap[key]
		full := len(sessionMap) >= c.maxConns
		mu.Unlock()

		if !exists {
			if full {
				logger.Warn("❌ [UDP] 拒绝本地新会话: 达到最大并发限制", zap.Int("limit", c.maxConns), zap.String("client", key))
				continue
			}

			connID := generateRandomHex(4)
			logger.Debug("🔌 [UDP] 发现新本地客户端，准备建立隧道", zap.String("id", connID), zap.String("client", key))

			// Dial outside the lock: DialXHTTP can block for seconds on
			// the network, and holding mu meanwhile would stall the
			// reaper and every other local UDP client with it.
			xc, dialErr := c.dialTracked(ctx, "udp", c.target)
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
			} else if len(sessionMap) >= c.maxConns {
				mu.Unlock()
				xc.Close()
				logger.Warn("❌ [UDP] 拒绝本地新会话: 达到最大并发限制", zap.Int("limit", c.maxConns), zap.String("client", key))
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
						l, err := ReadUDPFrameInto(session.conn, dBuf)
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
		if err := WriteUDPFrame(sess.conn, buf[:n]); err != nil {
			logger.Debug("⚠️ [UDP] 写入上行 Frame 失败", zap.String("client", key), zap.Error(err))
		}
	}
}
