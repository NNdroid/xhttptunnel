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
	// bwExchangeTimeout bounds one bandwidth exchange attempt. It is a fraction
	// of a poll: the exchange must never become the slow path, and it does not
	// carry tunnel data, so it is free to fail and retry next interval.
	bwExchangeTimeout = 5 * time.Second
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

	// protoInflight / transportInflight collapse concurrent cache misses for
	// the same endpoint into one piece of work. Without them a cold cache (or
	// one that expired a second ago) lets N concurrent dials each pay for a
	// QUIC probe plus a TCP/TLS handshake, and lets N transports be built for
	// one endpoint with all but the last one silently discarded — its pooled
	// connections then sit idle until IdleConnTimeout instead of being reused.
	protoInflight     inflightGroup
	transportInflight inflightGroup
)

type protoEntry struct {
	protocol string
	expiry   time.Time
}

// inflightGroup is a minimal per-key singleflight: the first caller for a key
// runs fn, later callers wait for and reuse its result instead of repeating
// the work. It exists so this package does not have to pull in
// golang.org/x/sync for one call site.
type inflightGroup struct {
	mu sync.Mutex
	m  map[string]*inflightCall
}

type inflightCall struct {
	done sync.WaitGroup
	val  interface{}
	err  error
}

// Do runs fn at most once per key at a time. fn MUST be safe to skip: a
// caller that finds the value already cached while waiting should return that
// value instead of redoing the work.
func (g *inflightGroup) Do(key string, fn func() (interface{}, error)) (interface{}, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*inflightCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.done.Wait()
		return c.val, c.err
	}
	c := &inflightCall{}
	c.done.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()

	g.mu.Lock()
	// Only remove our own entry: a later caller may already have registered a
	// fresh one after we finished.
	if g.m[key] == c {
		delete(g.m, key)
	}
	g.mu.Unlock()
	c.done.Done()
	return c.val, c.err
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
		InsecureSkipVerify:    fingerprint != "", // explicit pin replaces CA verification
		ServerName:            sni,
		NextProtos:            []string{"h3"},
		VerifyPeerCertificate: verifyFingerprint(fingerprint),
	}

	qconf := &quic.Config{}

	logger.Debug("🔎 probeHTTP3 starting QUIC handshake probe", zap.String("hostport", hostPort), zap.String("sni", sni), zap.Duration("timeout", timeout))

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
		logger.Debug("🔎 probeHTTP3 timed out / cancelled", zap.String("hostport", hostPort), zap.Error(cctx.Err()))
		return false, cctx.Err()
	case res := <-ch:
		if res.err != nil {
			logger.Debug("🔎 probeHTTP3 handshake failed", zap.String("hostport", hostPort), zap.Error(res.err))
			return false, res.err
		}
		if cerr := res.sess.CloseWithError(0, "probe done"); cerr != nil {
			logger.Debug("🔎 probeHTTP3: CloseWithError returned", zap.Error(cerr))
		}
		logger.Debug("🔎 probeHTTP3 handshake succeeded, QUIC/HTTP3 supported", zap.String("hostport", hostPort))
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

	protoMu.Lock()
	if e, ok := protoCache[key]; ok && time.Now().Before(e.expiry) {
		protoMu.Unlock()
		logger.Debug("[Sniffer] ♻️ reusing cached protocol probe result", zap.String("hostport", hostPort), zap.String("protocol", e.protocol))
		return e.protocol, nil
	}
	protoMu.Unlock()

	// Cache miss: collapse concurrent misses for this endpoint into one probe.
	// Otherwise N dials arriving together each pay for a QUIC handshake plus a
	// TCP/TLS handshake, which is exactly the cold-start stampede the cache was
	// meant to prevent.
	v, err := protoInflight.Do(key, func() (interface{}, error) {
		protoMu.Lock()
		if e, ok := protoCache[key]; ok && time.Now().Before(e.expiry) {
			protoMu.Unlock()
			return e.protocol, nil
		}
		protoMu.Unlock()
		return sniffProtocol(ctx, cfg, nextProtos, hostPort)
	})
	if err != nil {
		return "", err
	}
	protocol, _ := v.(string)

	protoMu.Lock()
	protoCache[key] = protoEntry{protocol: protocol, expiry: time.Now().Add(protoCacheTTL)}
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
		logger.Debug("🔎 attempting QUIC/HTTP3 probe", zap.String("hostport", hostPort), zap.String("sni", cfg.SNI))
		ok, perr := probeHTTP3(ctx, hostPort, cfg.SNI, h3ProbeTimeout, cfg.CertificateFingerprint, cfg.QUICDial, logger)
		if ok && perr == nil {
			logger.Debug("✅ QUIC/HTTP3 probe succeeded, using HTTP/3", zap.String("host", hostPort))
			return "h3", nil
		}
		logger.Debug("⚠️ QUIC/HTTP3 probe failed, falling back to TCP/TLS probe", zap.String("host", hostPort), zap.Error(perr))
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

	utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: cfg.CertificateFingerprint != "", NextProtos: nextProtos, VerifyPeerCertificate: verifyFingerprint(cfg.CertificateFingerprint)}
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
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, dialTimeout)
	defer cancelHandshake()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
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
	logger.Debug("[Sniffer] ✅ TLS probe completed", zap.String("ALPN", protocol), zap.String("SNI", cfg.SNI))
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
	// brutal applies TCP Brutal to the freshly connected socket, or nil when
	// this client does not configure it. nil means the dial path is exactly
	// what it was before brutal existed.
	brutal func(net.Conn)
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
		logger.Error("❌ [Dialer] failed to establish underlying connection", zap.Error(err))
		return nil, err
	}
	// Brutal belongs on the socket, not on the HTTP leg, so it is applied to
	// the bare TCP connection before TLS runs on top of it: the first
	// handshake byte is already rate-limited. It is deliberately here rather
	// than in a net.Dialer Control hook, which would only reach one of the two
	// dial paths — an embedder's injected DialContext bypasses it.
	if p.brutal != nil {
		p.brutal(c)
	}
	if !p.isTLS {
		return c, nil
	}

	utlsConfig := &utls.Config{ServerName: p.sni, InsecureSkipVerify: p.fingerprint != "", NextProtos: p.nextProtos, VerifyPeerCertificate: verifyFingerprint(p.fingerprint)}
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
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, dialTimeout)
	defer cancelHandshake()
	if err := tlsC.HandshakeContext(handshakeCtx); err != nil {
		logger.Error("❌ [Dialer] TLS handshake failed", zap.Error(err))
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
	key := protocol + "|" + hostPort + "|" + cfg.SNI + "|" + cfg.CertificateFingerprint + "|" + strings.Join(nextProtos, ",") + "|" + cfg.TransportKey

	transportMu.Lock()
	if rt, ok := transportCache[key]; ok {
		transportMu.Unlock()
		logger.Debug("♻️ [Dialer] reusing shared Transport", zap.String("protocol", protocol), zap.String("hostport", hostPort))
		return rt, false
	}
	transportMu.Unlock()

	// Cache miss: build the transport once per endpoint even when many dials
	// arrive together. Building two and keeping the second would orphan the
	// first one's connection pool until IdleConnTimeout expired.
	v, err := transportInflight.Do(key, func() (interface{}, error) {
		transportMu.Lock()
		if rt, ok := transportCache[key]; ok {
			transportMu.Unlock()
			return rt, nil
		}
		transportMu.Unlock()

		rt := buildTransport(protocol, cfg, nextProtos, isTLS, hostPort)

		transportMu.Lock()
		if existing, ok := transportCache[key]; ok {
			// Lost a race with another builder: keep the winner so there is
			// exactly one pool per endpoint.
			transportMu.Unlock()
			return existing, nil
		}
		transportCache[key] = rt
		transportMu.Unlock()
		return rt, nil
	})
	if err != nil {
		return nil, false
	}
	rt, _ := v.(http.RoundTripper)
	return rt, false
}

// buildTransport constructs the per-endpoint RoundTripper for a negotiated
// protocol. Called at most once per endpoint key (see selectTransport).
func buildTransport(protocol string, cfg *DialConfig, nextProtos []string, isTLS bool, hostPort string) http.RoundTripper {
	logger := cfg.lg()
	if protocol == "h3" {
		logger.Debug("🚀 [Dialer] preparing HTTP/3 (QUIC) transport")
		return &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    cfg.CertificateFingerprint != "",
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
	}

	p := &dialParams{
		hostPort:    hostPort,
		sni:         cfg.SNI,
		fingerprint: cfg.CertificateFingerprint,
		nextProtos:  nextProtos,
		isTLS:       isTLS,
		log:         cfg.lg(),
		dialContext: cfg.DialContext,
		brutal:      newBrutalApplier(cfg),
	}

	if protocol == "h2" {
		logger.Debug("🚀 [Dialer] preparing HTTP/2 transport")
		return &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return p.dial(ctx, network, addr)
			},
		}
	}

	logger.Debug("🚀 [Dialer] preparing HTTP/1.1 transport")
	t1 := &http.Transport{
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        sharedMaxIdleConns,
		MaxIdleConnsPerHost: sharedMaxIdleConns,
		DisableKeepAlives:   false,
		IdleConnTimeout:     90 * time.Second,
	}
	t1.DialTLSContext = p.dial
	t1.DialContext = p.dial
	return t1
}

func serverEndpoint(u *url.URL, path string) (isTLS bool, hostPort, reqURL string) {
	isTLS = u.Scheme == "https"
	port := u.Port()
	if port == "" {
		if isTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostPort = net.JoinHostPort(u.Hostname(), port)
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	reqURL = fmt.Sprintf("%s://%s%s", scheme, hostPort, path)
	return
}

func DialXHTTP(ctx context.Context, serverURL *url.URL, cfg *DialConfig, targetAddr, network string) (net.Conn, error) {
	logger := cfg.lg()
	isTLS, hostPort, reqURL := serverEndpoint(serverURL, cfg.Path)
	// Deliberately NOT writing cfg.Path here. cfg is shared by every session
	// spawned from this client, so mutating it from concurrent dials is a
	// data race — and pointless, since NewClient already seeds Path from the
	// server URL. reqURL above reads cfg.Path, which is that same value.
	nextProtos := buildNextProtos(cfg.ALPN)

	protocol, err := detectProtocol(ctx, cfg, nextProtos, isTLS, hostPort)
	if err != nil {
		return nil, err
	}

	// The connection pool is shared, so a session no longer owns one specific
	// socket and there is no meaningful per-session local address to report.
	localAddr := stringAddr("tunnel-local")
	remoteAddr := stringAddr(hostPort)

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
		if strings.EqualFold(strings.TrimSpace(cfg.StreamMode), "stream") {
			return nil, serr
		}
		logger.Warn("⚠️ [Stream] streaming downlink unavailable on this path, this session falls back to long polling",
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
	logger.Debug("🚀 starting client HTTP data pump", zap.String("session", sessionID), zap.String("target", targetAddr), zap.String("transport", fmt.Sprintf("%T", rt)))

	go func() {
		defer close(pumpDone)
		defer pumpCancel()
		defer virtualConn.Close()
		defer logger.Debug("💀 client HTTP data pump stopped", zap.String("session", sessionID))

		var ackedByServer uint64
		var dispatchSeq uint64
		var windowMu sync.Mutex
		var triggerRetry int32
		var emptyPollers int32

		restartCount := 0

		for !virtualConn.isClosed() && !virtualConn.closePending() {
			if restartCount > 0 {
				if restartCount > 6 {
					logger.Error("❌ [Pump] data pump restart limit reached (over 90s), giving up recovery, closing tunnel", zap.String("session", sessionID))
					break
				}

				backoff := time.Duration(1<<restartCount) * time.Second
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
				logger.Warn("⚠️ [Pump] severe network error, data pump exited, will auto-restart after exponential backoff",
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
					req.Header.Set("User-Agent", clientUserAgent)
					// Signed credentials: the PSK itself is never sent, only its
					// HMAC over a per-request nonce. The nonce is what makes
					// replay impossible, so a failure here is fatal rather than
					// retryable — retrying would just keep drawing the same
					// broken entropy source and mint predictable nonces.
					if authErr := setAuthHeaders(req, cfg.Password, sessionID, targetAddr); authErr != nil {
						logger.Error("❌ [Pump] could not draw a nonce, closing the tunnel",
							zap.String("session", sessionID),
							zap.Error(authErr),
						)
						virtualConn.setCloseErr(fmt.Errorf("tunnel: could not generate a nonce: %w", authErr))
						virtualConn.Close()
						pumpCancel()
						return
					}
					req.Header.Set(ProtoHeader, strconv.Itoa(offeredProtoVersion))
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

					// Hot path: this runs once per poll. Checking the level
					// first keeps the zap.Field slice from being allocated
					// (and formatted) on every round when debug is off.
					if ce := logger.Check(zap.DebugLevel, "📤 [Pump] issuing HTTP poll request"); ce != nil {
						ce.Write(
							zap.String("session", sessionID),
							zap.Uint64("Client_Seq", currentSeq),
							zap.Uint64("Client_Ack", myAck),
							zap.Int("Up_Bytes", len(upData)),
							zap.Int("worker", id),
						)
					}

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
							logger.Debug("🛑 [Pump] context cancelled, worker exiting", zap.Int("worker", id))
							break
						}
						// An empty poll aborted by the closer is not a network
						// failure: the pump is shutting down, so stop instead of
						// retrying and parking another 5s long poll.
						if handle != nil && (virtualConn.closePending() || virtualConn.isClosed()) {
							logger.Debug("🛑 [Pump] aborting empty poll on close, worker exiting", zap.Int("worker", id))
							break
						}
						logger.Debug("⚠️ [Pump] HTTP poll failed, will retry", zap.String("session", sessionID), zap.Error(err))
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)
						if atomic.AddInt32(&consecutiveErrors, 1) > 20 {
							logger.Warn("❌ [Pump] too many consecutive errors, worker exiting to trigger a data pump restart", zap.Int("worker", id))
							break
						}
						// Interruptible: a teardown during the backoff must not
						// leave the worker parked for the full interval.
						if !sleepCtx(pumpCtx, 300*time.Millisecond) {
							break
						}
						continue
					}
					atomic.StoreInt32(&consecutiveErrors, 0)

					var sAck uint64
					if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" && resp.StatusCode == http.StatusOK {
						sAck, _ = strconv.ParseUint(sAckStr, 10, 64)
						if !virtualConn.writeBuf.validAck(sAck) {
							resp.Body.Close()
							virtualConn.setCloseErr(errors.New("tunnel: invalid peer acknowledgement"))
							virtualConn.Close()
							pumpCancel()
							return
						}
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
						logger.Warn("⚠️ [Pump] 200 response missing X-Ack header (likely stripped by a CDN/proxy), uplink acknowledgement stalled", zap.String("session", sessionID))
					}

					if resp.StatusCode != http.StatusOK {
						downBuf := bytesBufPool.Get().(*bytes.Buffer)
						downBuf.Reset()
						downBuf.ReadFrom(io.LimitReader(resp.Body, 4096))
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

						// Credential and policy rejections will not fix themselves on a
						// retry. The 403 belongs here too: the allowlist runs before a
						// session is registered, so there is nothing to poll and every
						// retry hits the same refusal. 429 and 504 below stay
						// recoverable because those are transient edge states.
						//
						// Closing the virtual conn is what actually stops the pump: a
						// bare worker return only exits this goroutine, and the loop
						// below respawns the whole worker set and the refusal comes
						// straight back (up to 7 restarts, up to 30s of backoff each).
						if resp.StatusCode == http.StatusProxyAuthRequired ||
							resp.StatusCode == http.StatusUnauthorized ||
							resp.StatusCode == http.StatusForbidden {
							if cfg.events != nil {
								if resp.StatusCode == http.StatusForbidden {
									cfg.events.emit(TargetDenied{SessionID: sessionID, Target: targetAddr, Network: network})
									cfg.events.emit(TunnelDied{SessionID: sessionID, Target: targetAddr, Network: network, Reason: "target denied", Detail: string(bodyErr)})
								} else {
									cfg.events.emit(TunnelDied{SessionID: sessionID, Target: targetAddr, Network: network, Reason: "auth rejected", Detail: string(bodyErr)})
								}
							}
							logger.Warn("❌ [Pump] server refused the request, closing the tunnel",
								zap.String("session", sessionID),
								zap.Int("status", resp.StatusCode),
								zap.String("error_body", string(bodyErr)),
							)
							virtualConn.setCloseErr(fmt.Errorf("tunnel: server refused the request (HTTP %d)", resp.StatusCode))
							virtualConn.Close()
							pumpCancel()
							bytesBufPool.Put(downBuf)
							return
						}

						// 504 (Gateway Timeout) / 524 (Cloudflare Timeout) are normal
						// long-poll timeouts — go straight to the next poll round.
						if resp.StatusCode == http.StatusGatewayTimeout || resp.StatusCode == 524 {
							logger.Debug("⏱️ [Pump] CDN/gateway poll timeout, starting the next poll immediately",
								zap.String("session", sessionID),
								zap.Int("status", resp.StatusCode),
							)
							bytesBufPool.Put(downBuf)
							continue
						}

						// 429 Too Many Requests: hit a CDN/WAF rate limit, back off briefly.
						if resp.StatusCode == http.StatusTooManyRequests {
							logger.Warn("⚠️ [Pump] hit CDN/WAF rate limit (429 Too Many Requests), backing off...",
								zap.String("session", sessionID),
							)
							bytesBufPool.Put(downBuf)
							if !sleepCtx(pumpCtx, 1*time.Second) {
								break
							}
							continue
						}

						logger.Error("❌ [Pump] received an unexpected HTTP status code",
							zap.String("session", sessionID),
							zap.Int("status", resp.StatusCode),
							zap.String("error_body", string(bodyErr)),
						)

						bytesBufPool.Put(downBuf)
						if !sleepCtx(pumpCtx, 1*time.Second) {
							break
						}
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
						logger.Warn("⚠️ [Pump] 200 response missing X-Seq header (likely stripped by a CDN/proxy), rewinding and retrying", zap.String("session", sessionID))
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						if handle != nil {
							handle.cancel()
						}
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)
						if !sleepCtx(pumpCtx, 300*time.Millisecond) {
							break
						}
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
						logger.Warn("⚠️ [Pump] the CDN/proxy content-encoded the tunnel response, the frame stream will be corrupted (disable compression for this path at the CDN)",
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
							_, errBody = virtualConn.PutReadDataContext(pumpCtx, downSeq, readChunk[:n])
							if errBody != nil {
								break
							}
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
						logger.Warn("⚠️ [Pump] failed to read downlink body or it ended unexpectedly, triggering a safe retransmit", zap.Error(errBody))

						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						atomic.StoreInt32(&triggerRetry, 1)
						if !sleepCtx(pumpCtx, 300*time.Millisecond) {
							break
						}
						continue
					}

					if ce := logger.Check(zap.DebugLevel, "📥 [Pump] received HTTP poll response"); ce != nil {
						ce.Write(
							zap.String("session", sessionID),
							zap.Uint64("Server_Seq", sSeq),
							zap.Uint64("Server_Ack", sAck),
							zap.Int("Down_Bytes", totalDownBytes),
						)
					}

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
						// Idle anti-spin pause. Interruptible so a closing
						// session does not wait out the full 100ms.
						if !sleepCtx(pumpCtx, 100*time.Millisecond) {
							break
						}
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
				logger.Debug("🧹 [Dialer] closing HTTP/3 Transport", zap.String("session", sessionID))
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
				logger.Debug("⏱️ [Pump] close-frame flush timed out, force-cancelling the data pump", zap.String("session", sessionID))
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
	// Brutal configures TCP Brutal on this client's TCP tunnel sockets, and
	// with it the bandwidth exchange that lets each side advertise how fast
	// it can ingest. ClientConfig.Brutal in the SDK path.
	Brutal BrutalConfig

	// bwRateFn returns the ingest capacity the peer advertised in the last
	// bandwidth exchange, in bytes/s. Zero means no exchange has succeeded
	// yet. Unexported: it is wired by NewClient from the client's own state,
	// and a hand-built config leaves it nil, which reads as zero.
	bwRateFn func() uint64

	// brutalWarns deduplicates the per-socket failure messages across every
	// pooled connection this client opens. One gate per config, so a missing
	// kernel module is reported once rather than once per connection.
	brutalWarns *warnGate
}

// bwRate reports the rate negotiated with the peer, if any. It is the value
// the dial path merges against the configured ceiling.
func (c *DialConfig) bwRate() uint64 {
	if c.bwRateFn == nil {
		return 0
	}
	return c.bwRateFn()
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
	// PSK is the pre-shared key. It is never sent: each request carries a
	// fresh nonce plus its HMAC-SHA256 over the nonce, session id and target,
	// so a captured request leaks nothing and cannot be replayed. Empty
	// disables authentication.
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
	// pinning (required for self-signed certificates). When empty, the client
	// verifies the normal CA chain and SNI hostname, suitable for CDN edges.
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
	// Brutal configures TCP Brutal on the client's TCP tunnel sockets.
	// Invalid combinations are rejected by NewClient. HTTP/3 sessions run over
	// QUIC/UDP, which brutal does not cap, so the setting has no effect on
	// them; the bandwidth exchange is skipped for a pure-h3 client.
	Brutal BrutalConfig
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

	// bwNegotiated is the ingest capacity the server advertised in the last
	// successful bandwidth exchange, in bytes/s. Zero means nothing has been
	// negotiated, so the configured rate stands alone.
	bwNegotiated atomic.Uint64
	// bwDone is set once an exchange fails because the server does not
	// implement it. The loop is never retried after that, so a client pointed
	// at an older server spends at most one session on the probe per process.
	bwDone atomic.Bool
	// bwBusy is 1 while one exchange attempt is in flight, so a dial burst
	// cannot fan the probe out into many concurrent requests.
	bwBusy atomic.Int32
	// bwLastAttempt is the Unix second of the last attempt, which throttles
	// the exchange to at most one per bw_interval regardless of dial volume.
	bwLastAttempt atomic.Int64

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
	if err := cfg.Brutal.Validate("client"); err != nil {
		return nil, err
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
		Brutal:                 cfg.Brutal,
		bwRateFn:               func() uint64 { return c.bwNegotiated.Load() },
		brutalWarns:            newWarnGate(),
		events:                 c.events,
		log:                    cfg.Logger,
	}

	if cfg.Brutal.Enabled && !brutalAvailable() {
		// brutal's syscalls are Linux-only, so on any other platform the
		// per-connection hook is never installed at all. Say so once at startup
		// instead of once per pooled connection.
		c.lg().Warn("⚠️ [TCP] TCP Brutal is configured but it is only available on Linux; the tunnel runs without it")
	}

	logger.Debug("🔧 client configuration initialised", zap.String("SNI", sni), zap.String("Host", host), zap.String("Target", cfg.Target), zap.String("ALPN", alpn), zap.String("CertificateFingerprint", cfg.Fingerprint))

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
	// A tunnel dial is the moment to refresh a negotiated bandwidth: the
	// client is provably alive and a socket is about to be opened, which is
	// exactly when the value matters. Non-blocking by contract — see
	// maybeBwExchange — so this never adds latency to the dial.
	if c.dialCfg.Brutal.bwCapable() {
		c.maybeBwExchange(ctx)
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
	tracked := &trackedConn{Conn: conn, client: c}
	// Release the MaxConns slot the moment the tunnel dies on its own
	// (peer closed / transport failure), not only when the caller closes it.
	// Without this, a caller that forgets to Close a dead session leaks its
	// slot for the process lifetime and can eventually lock itself out of
	// MaxConns. The release is idempotent via tracked.release.
	if doneable, ok := conn.(interface{ Done() <-chan struct{} }); ok {
		go func() {
			<-doneable.Done()
			tracked.releaseSlot()
		}()
	}
	return tracked, nil
}

// maybeBwExchange starts a bandwidth exchange if one is due, and returns
// immediately. The exchange is a full request round trip and a tunnel dial
// must not wait for it, so it runs on its own goroutine. bw_busy keeps at
// most one attempt in flight, and bw_last_attempt caps the cadence at
// bw_interval no matter how many dials arrive.
//
// This is deliberately a per-dial check rather than a ticker goroutine:
// nothing needs a negotiated rate while the client is idle, so an idle client
// leaks no goroutine and spends no sessions. A client that keeps tunneling
// therefore re-negotiates naturally, at least once per bw_interval.
func (c *Client) maybeBwExchange(ctx context.Context) {
	if c.bwDone.Load() {
		return
	}
	interval := time.Duration(c.dialCfg.Brutal.BWInterval) * time.Second
	if time.Since(time.Unix(c.bwLastAttempt.Load(), 0)) < interval {
		return
	}
	if !c.bwBusy.CompareAndSwap(0, 1) {
		return
	}
	// Re-check after winning the race: a concurrent dial may have started the
	// attempt while this one was deciding.
	if time.Since(time.Unix(c.bwLastAttempt.Load(), 0)) < interval {
		c.bwBusy.Store(0)
		return
	}
	c.bwLastAttempt.Store(time.Now().Unix())
	go func() {
		defer c.bwBusy.Store(0)
		if !c.doBwExchange(ctx) {
			c.bwDone.Store(true)
		}
	}()
}

// doBwExchange runs one bandwidth exchange and applies the result. It
// reports whether the loop should be attempted again: false means the server
// will never answer one and further attempts are pure waste.
//
// The two failure classes are kept apart on purpose. A request that did not
// even complete — server unreachable, timeout, nonce entropy broken — may
// recur, so the loop survives it and retries after bw_interval. A request that
// completed but was not an exchange is permanent: an older server rejects
// TargetBwExchange like any unparseable target, so retrying it can only burn
// sessions.
func (c *Client) doBwExchange(ctx context.Context) bool {
	cfg := c.dialCfg
	logger := c.lg()
	bc := cfg.Brutal

	ctx, cancel := context.WithTimeout(ctx, bwExchangeTimeout)
	defer cancel()
	if c.isClosed() {
		return false
	}

	isTLS, hostPort, reqURL := serverEndpoint(c.serverURL, cfg.Path)
	nextProtos := buildNextProtos(cfg.ALPN)

	protocol, err := detectProtocol(ctx, cfg, nextProtos, isTLS, hostPort)
	if err != nil {
		return true // unreachable: transient
	}
	if protocol == "h3" {
		// HTTP/3 tunnels run over QUIC/UDP and brutal caps TCP sockets, so
		// there is nothing here to negotiate a rate for. Not a failure.
		return true
	}
	rt, _ := selectTransport(protocol, cfg, nextProtos, isTLS, hostPort)
	if rt == nil {
		return true
	}

	sessionID := generateRandomHex(16)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, http.NoBody)
	if err != nil {
		return false
	}
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	// Deliberately not sending a stream request type: the exchange branch on
	// the server runs before stream-mode dispatch, and advertising a type the
	// handler ignores would only be a wasted byte.
	if cfg.Host != "" {
		req.Host = cfg.Host
	} else if cfg.SNI != "" {
		req.Host = cfg.SNI
	}
	req.Header.Set("User-Agent", clientUserAgent)
	if bc.BWAdvertise > 0 {
		req.Header.Set(BwHeader, strconv.FormatUint(bc.BWAdvertise, 10))
	}
	// The existing signed-nonce auth covers the special target with no change:
	// the signature binds the target string, and TargetBwExchange is exactly
	// what the server will read back out of X-Target.
	if err := setAuthHeaders(req, cfg.Password, sessionID, TargetBwExchange); err != nil {
		logger.Error("❌ [BW] could not draw a nonce for the bandwidth exchange", zap.Error(err))
		return false
	}
	req.Header.Set(ProtoHeader, strconv.Itoa(offeredProtoVersion))
	req.Header.Set("X-Target", TargetBwExchange)
	req.Header.Set("X-Network", "tcp")
	req.Header.Set("X-Session-ID", sessionID)

	resp, err := (&http.Client{Transport: rt, Timeout: bwExchangeTimeout}).Do(req)
	if err != nil {
		return true // unreachable: transient
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		// A non-200 means the server rejected the special target as an
		// ordinary address, which is what an older server does. Never retry.
		logger.Warn("⚠️ [BW] the server does not support the bandwidth exchange; keeping the configured rate",
			zap.Int("status", resp.StatusCode))
		return false
	}
	if !hasBrutalBwCap(resp.Header.Get(CapsHeader)) {
		logger.Warn("⚠️ [BW] the server answered an exchange request without advertising the capability; not retrying",
			zap.Int("status", resp.StatusCode))
		return false
	}
	advertised := resp.Header.Get(BwHeader)
	if advertised == "" {
		// The server implemented the protocol but declined to advertise.
		// Nothing to apply; the exchange itself succeeded.
		return true
	}
	v, ok := parseBwValue(advertised)
	if !ok {
		logger.Warn("⚠️ [BW] ignoring an invalid bandwidth advertisement", zap.String("value", advertised))
		return true
	}
	c.applyBw(v)
	return true
}

// applyBw records a peer's advertised ingest capacity and applies the rate it
// results in. The configured rate stays a ceiling (mergeBrutalRate), so a
// peer can only lower the send rate, never raise it.
//
// Reaching existing sockets is indirect: the transport pools own them. A
// brutal group shares its rate across members, so one setsockopt on any member
// updates them all, and a freshly dialled connection reads bwNegotiated and
// applies the new value — which is what pushes the group. Without a group every
// connection carries its own rate, so the idle ones have to be dropped and
// redialled. Either way the update is best effort: a connection mid-transfer
// keeps the rate it was opened with until it is recycled.
func (c *Client) applyBw(advertised uint64) {
	effective := mergeBrutalRate(c.dialCfg.Brutal.Rate, advertised)
	if effective == 0 {
		return
	}
	if advertised == c.bwNegotiated.Swap(advertised) {
		return // unchanged: nothing to push
	}
	logger := c.lg()
	if ce := logger.Check(zap.InfoLevel, "📶 [BW] applied bandwidth negotiated with the server"); ce != nil {
		ce.Write(
			zap.Uint64("peer_advertised", advertised),
			zap.Uint64("configured_ceiling", c.dialCfg.Brutal.Rate),
			zap.Uint64("effective_rate", effective),
			zap.Uint64("group_id", c.dialCfg.Brutal.GroupID),
		)
	}
	flushIdleTunnelConns()
}

// flushIdleTunnelConns drops the idle keep-alive sockets of every cached
// transport so the next request redials them and picks up the rate that is in
// force. Only idle sockets are closed; a connection carrying a session in
// flight is left exactly as it is.
func flushIdleTunnelConns() {
	transportMu.Lock()
	defer transportMu.Unlock()
	for _, rt := range transportCache {
		if flusher, ok := rt.(interface{ CloseIdleConnections() }); ok {
			flusher.CloseIdleConnections()
		}
	}
}

// trackedConn releases its MaxConns slot exactly once — either when the
// caller closes the session or when the underlying tunnel dies, whichever
// happens first.
type trackedConn struct {
	net.Conn
	client  *Client
	release sync.Once
}

func (t *trackedConn) releaseSlot() {
	t.release.Do(func() { t.client.dialCount.Add(-1) })
}

func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	t.releaseSlot()
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

	logger.Info("🚀 Client started successfully", zap.String("addr", hostPort), zap.String("ALPN", c.dialCfg.ALPN))
	go func() {
		<-ctx.Done()
		logger.Info("🛑 shutdown signal received, closing the client TCP listener...")
		ln.Close()
	}()

	var activeTCPConns int32

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || c.isClosed() {
				return nil
			}
			logger.Error("❌ failed to Accept a local connection", zap.Error(err))
			continue
		}

		if atomic.LoadInt32(&activeTCPConns) >= int32(c.maxConns) {
			logger.Warn("❌ [TCP] refused local connection: reached max concurrent connections", zap.Int("limit", c.maxConns), zap.String("client", conn.RemoteAddr().String()))
			conn.Close()
			continue
		}
		atomic.AddInt32(&activeTCPConns, 1)

		go func() {
			defer atomic.AddInt32(&activeTCPConns, -1)
			defer conn.Close()
			connID := generateRandomHex(4)
			logger.Debug("🔌 [TCP] accepted a local client connection", zap.String("id", connID), zap.String("client", conn.RemoteAddr().String()))

			logger.Debug("⏳ [TCP] dialing the remote XHTTP tunnel...", zap.String("id", connID), zap.String("server", c.serverURL.Host))
			xc, err := c.dialTracked(ctx, "tcp", c.target)
			if err != nil {
				logger.Error("❌ [TCP] XHTTP tunnel dial failed", zap.String("id", connID), zap.Error(err))
				return
			}
			defer xc.Close()
			logger.Debug("✅ [TCP] XHTTP tunnel dial succeeded", zap.String("id", connID))

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
					logger.Debug("⚠️ [TCP] uplink relay (local->server) ended abnormally", zap.String("id", connID), zap.Int64("bytes", written), zap.Error(upErr))
				} else {
					logger.Debug("🛑 [TCP] uplink relay (local->server) ended normally", zap.String("id", connID), zap.Int64("bytes", written))
				}
			}()

			downN, downErr := io.Copy(&idleRefresher{Conn: clientConn, idle: c.idleTimeout}, xc)
			if downErr != nil && downErr != io.EOF {
				logger.Debug("⚠️ [TCP] downlink relay (server->local) ended abnormally", zap.String("id", connID), zap.Int64("bytes", downN), zap.Error(downErr))
			} else {
				logger.Debug("🛑 [TCP] downlink relay (server->local) ended normally", zap.String("id", connID), zap.Int64("bytes", downN))
			}
			closeBoth()
			logger.Debug("💀 [TCP] local session cleaned up", zap.String("id", connID))
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

	logger.Info("🚀 Client(UDP) started successfully", zap.String("addr", hostPort))
	go func() {
		<-ctx.Done()
		logger.Info("🛑 shutdown signal received, closing the client UDP listener...")
		pc.Close()
	}()

	type udpSession struct {
		// lastActive must be atomic.Int64, not int64: on 32-bit targets a
		// plain int64 reached via atomic.LoadInt64/StoreInt64 traps with
		// "unaligned 64-bit atomic operation". atomic.Int64 is always
		// 8-byte aligned. (The struct is heap-allocated, so placing it first
		// would also work, but the atomic type is self-enforcing.)
		lastActive atomic.Int64
		conn       net.Conn
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
					if now-sess.lastActive.Load() > 30 {
						logger.Debug("🧹 [UDP] reclaiming a long-idle local UDP session", zap.String("client", addr))
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
			logger.Error("❌ [UDP] local read failed", zap.Error(err))
			continue
		}

		key := cAddr.String()

		mu.Lock()
		sess, exists := sessionMap[key]
		full := len(sessionMap) >= c.maxConns
		mu.Unlock()

		if !exists {
			if full {
				logger.Warn("❌ [UDP] refused local session: reached max concurrent connections", zap.Int("limit", c.maxConns), zap.String("client", key))
				continue
			}

			connID := generateRandomHex(4)
			logger.Debug("🔌 [UDP] new local client detected, establishing tunnel", zap.String("id", connID), zap.String("client", key))

			// Dial outside the lock: DialXHTTP can block for seconds on
			// the network, and holding mu meanwhile would stall the
			// reaper and every other local UDP client with it.
			xc, dialErr := c.dialTracked(ctx, "udp", c.target)
			if dialErr != nil {
				logger.Error("❌ [UDP] XHTTP tunnel dial failed", zap.String("id", connID), zap.Error(dialErr))
				continue
			}
			logger.Debug("✅ [UDP] XHTTP tunnel dial succeeded", zap.String("id", connID))

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
				logger.Warn("❌ [UDP] refused local session: reached max concurrent connections", zap.Int("limit", c.maxConns), zap.String("client", key))
				continue
			} else {
				sess = &udpSession{conn: xc}
				sess.lastActive.Store(time.Now().Unix())
				sessionMap[key] = sess
				mu.Unlock()

				go func(addr net.Addr, session *udpSession, id string) {
					defer session.conn.Close()
					defer func() {
						mu.Lock()
						delete(sessionMap, addr.String())
						mu.Unlock()
						logger.Debug("💀 [UDP] local session cleaned up", zap.String("id", id), zap.String("client", addr.String()))
					}()

					dBuf := make([]byte, maxUDPFrameSize)
					for {
						l, err := ReadUDPFrameInto(session.conn, dBuf)
						if err != nil {
							if err != io.EOF && !strings.Contains(err.Error(), "closed network connection") {
								logger.Debug("⚠️ [UDP] failed to read downlink frame", zap.String("id", id), zap.Error(err))
							} else {
								logger.Debug("🛑 [UDP] downlink listener ended (EOF/closed)", zap.String("id", id))
							}
							return
						}
						session.lastActive.Store(time.Now().Unix())
						pc.WriteTo(dBuf[:l], addr)
					}
				}(cAddr, sess, connID)
			}
		}

		sess.lastActive.Store(time.Now().Unix())
		if err := WriteUDPFrame(sess.conn, buf[:n]); err != nil {
			logger.Debug("⚠️ [UDP] failed to write uplink frame", zap.String("client", key), zap.Error(err))
		}
	}
}
