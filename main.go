package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var logger *zap.Logger

func initLogger(levelStr string) {
	config := zap.NewProductionConfig()
	config.Encoding = "console"
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(levelStr)); err != nil {
		level = zap.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(level)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, _ = config.Build()
	zap.ReplaceGlobals(logger)
}

// ==========================================
// 1. 基础结构
// ==========================================

type Config struct {
	Path     string
	SNI      string
	Host     string
	Password string
	ALPN     string
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// DumpConn: 流量透视拦截器
type DumpConn struct {
	net.Conn
	Prefix string
}

func (c *DumpConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬇️ 读取 %d 字节 ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

func (c *DumpConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬆️ 发送 %d 字节 ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

func readUDPFrameInto(r io.Reader, buf []byte) (int, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	if int(length) > len(buf) {
		return 0, fmt.Errorf("too large")
	}
	if _, err := io.ReadFull(r, buf[:length]); err != nil {
		return 0, err
	}
	return int(length), nil
}

func writeUDPFrame(w io.Writer, payload []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ==========================================
// 2. Meek 虚拟连接 (带数据抢救)
// ==========================================

type meekVirtualConn struct {
	sessionID  string
	local      net.Addr
	remote     net.Addr
	readCond   *sync.Cond
	readBuf    bytes.Buffer
	writeMutex sync.Mutex
	writeBuf   bytes.Buffer
	closed     bool
	lastActive int64
}

func newMeekVirtualConn(sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		sessionID:  sessionID,
		local:      local,
		remote:     remote,
		readCond:   sync.NewCond(&sync.Mutex{}),
		lastActive: time.Now().Unix(),
	}
}

func (c *meekVirtualConn) Read(p []byte) (int, error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	for c.readBuf.Len() == 0 && !c.closed {
		c.readCond.Wait()
	}
	if c.closed && c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *meekVirtualConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeBuf.Write(p)
}

func (c *meekVirtualConn) HasWriteData() bool {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeBuf.Len() > 0
}

func (c *meekVirtualConn) takeWriteBuf(max int) []byte {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBuf.Len() == 0 {
		return nil
	}
	takeLen := c.writeBuf.Len()
	if takeLen > max {
		takeLen = max
	}
	data := make([]byte, takeLen)
	c.writeBuf.Read(data)
	return data
}

// 核心功能：数据抢救
func (c *meekVirtualConn) putWriteBufFront(data []byte) {
	if len(data) == 0 {
		return
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	newData := make([]byte, len(data)+c.writeBuf.Len())
	copy(newData, data)
	copy(newData[len(data):], c.writeBuf.Bytes())
	c.writeBuf = *bytes.NewBuffer(newData)
}

func (c *meekVirtualConn) putReadBuf(data []byte) {
	if len(data) == 0 {
		return
	}
	c.readCond.L.Lock()
	c.readBuf.Write(data)
	c.readCond.Broadcast()
	c.readCond.L.Unlock()
}

func (c *meekVirtualConn) updateActive() {
	atomic.StoreInt64(&c.lastActive, time.Now().Unix())
}

func (c *meekVirtualConn) Close() error {
	c.readCond.L.Lock()
	c.closed = true
	c.readCond.Broadcast()
	c.readCond.L.Unlock()
	return nil
}

func (c *meekVirtualConn) LocalAddr() net.Addr                { return c.local }
func (c *meekVirtualConn) RemoteAddr() net.Addr               { return c.remote }
func (c *meekVirtualConn) SetDeadline(t time.Time) error      { return nil }
func (c *meekVirtualConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *meekVirtualConn) SetWriteDeadline(t time.Time) error { return nil }

// ==========================================
// 3. XHTTP 动态 Padding 与 EOF 信令装甲
// ==========================================

type xhttpFramedConn struct {
	r          io.Reader
	w          io.Writer
	closer     func() error
	local      net.Addr
	remote     net.Addr
	targetAddr string
	network    string
	mu         sync.Mutex
	readBuf    []byte
	frameBuf   []byte
	hdrBuf     []byte
	payloadBuf []byte
	closeCh    chan struct{}
	closedFlag int32
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	conn := &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		frameBuf: make([]byte, 32768), hdrBuf: make([]byte, 4), payloadBuf: make([]byte, 16384),
		closeCh: make(chan struct{}),
	}
	go conn.heartbeatLoop()
	return conn
}

// EOF 终结信令
func (c *xhttpFramedConn) WriteCloseFrame() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	frame := make([]byte, 4)
	binary.BigEndian.PutUint16(frame[0:2], 0xFFFF)
	binary.BigEndian.PutUint16(frame[2:4], 0)
	_, err := c.w.Write(frame)
	return err
}

func (c *xhttpFramedConn) heartbeatLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.Write(nil)
		case <-c.closeCh:
			return
		}
	}
}

func (c *xhttpFramedConn) writeSingleFrame(chunk []byte) error {
	chunkSize := len(chunk)
	var padLenInt int
	if chunkSize == 0 {
		padLenInt = 32 + mrand.Intn(128)
	} else if chunkSize < 512 {
		padLenInt = (600 + mrand.Intn(600)) - chunkSize
		if padLenInt < 0 {
			padLenInt = mrand.Intn(256)
		}
	} else {
		padLenInt = 16 + mrand.Intn(112)
	}

	frameLen := 4 + padLenInt + chunkSize
	if frameLen > len(c.frameBuf) {
		c.frameBuf = make([]byte, frameLen)
	}
	frame := c.frameBuf[:frameLen]

	binary.BigEndian.PutUint16(frame[0:2], uint16(chunkSize))
	binary.BigEndian.PutUint16(frame[2:4], uint16(padLenInt))
	if padLenInt > 0 {
		io.ReadFull(rand.Reader, frame[4:4+padLenInt])
	}
	if chunkSize > 0 {
		copy(frame[4+padLenInt:], chunk)
	}

	_, err := c.w.Write(frame)
	return err
}

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, c.writeSingleFrame(nil)
	}

	written := 0
	maxPayload := 16384
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPayload {
			chunkSize = maxPayload
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]
		if err := c.writeSingleFrame(chunk); err != nil {
			return written, err
		}
		written += chunkSize
	}
	return written, nil
}

func (c *xhttpFramedConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		if _, err := io.ReadFull(c.r, c.hdrBuf); err != nil {
			return 0, err
		}
		payloadLen := int(binary.BigEndian.Uint16(c.hdrBuf[0:2]))
		padLen := int(binary.BigEndian.Uint16(c.hdrBuf[2:4]))

		if padLen > 0 {
			if _, err := io.CopyN(io.Discard, c.r, int64(padLen)); err != nil {
				return 0, err
			}
		}

		if payloadLen == 0xFFFF {
			return 0, io.EOF
		}
		if payloadLen == 0 {
			continue
		}

		if payloadLen > len(c.payloadBuf) {
			c.payloadBuf = make([]byte, payloadLen)
		}
		payload := c.payloadBuf[:payloadLen]
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return 0, err
		}

		n := copy(p, payload)
		if n < payloadLen {
			c.readBuf = payload[n:]
		}
		return n, nil
	}
}

func (c *xhttpFramedConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1) {
		close(c.closeCh)
		return c.closer()
	}
	return nil
}

func (c *xhttpFramedConn) LocalAddr() net.Addr                { return c.local }
func (c *xhttpFramedConn) RemoteAddr() net.Addr               { return c.remote }
func (c *xhttpFramedConn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpFramedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpFramedConn) SetWriteDeadline(t time.Time) error { return nil }

// ==========================================
// 4. 客户端极速稳态轮询拨号器 (带熔断机制)
// ==========================================

func DialXHTTP(serverURL *url.URL, cfg *Config, targetAddr, network string) (net.Conn, error) {
	isTLS := serverURL.Scheme == "https"
	basePort := serverURL.Port()
	if basePort == "" {
		if isTLS {
			basePort = "443"
		} else {
			basePort = "80"
		}
	}

	var nextProtos []string
	switch strings.ToLower(cfg.ALPN) {
	case "h1", "http/1.1":
		nextProtos = []string{"http/1.1"}
	case "h2":
		nextProtos = []string{"h2"}
	default:
		nextProtos = []string{"h2", "http/1.1"}
	}

	firstConn, err := net.DialTimeout("tcp", net.JoinHostPort(serverURL.Hostname(), basePort), 10*time.Second)
	if err != nil {
		return nil, err
	}

	var protocol string
	if isTLS {
		utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos}
		tlsConn := utls.UClient(firstConn, utlsConfig, utls.HelloChrome_Auto)
		if err := tlsConn.Handshake(); err != nil {
			firstConn.Close()
			return nil, err
		}
		firstConn = tlsConn
		protocol = tlsConn.ConnectionState().NegotiatedProtocol
		logger.Debug("TLS 探测成功", zap.String("ALPN", protocol))
	} else {
		protocol = "http/1.1"
		logger.Debug("使用明文连接", zap.String("Protocol", protocol))
	}

	var dialMut sync.Mutex
	var firstConnUsed bool
	coreDial := func() (net.Conn, error) {
		dialMut.Lock()
		if !firstConnUsed {
			firstConnUsed = true
			dialMut.Unlock()
			return firstConn, nil
		}
		dialMut.Unlock()
		c, err := net.DialTimeout("tcp", net.JoinHostPort(serverURL.Hostname(), basePort), 10*time.Second)
		if err != nil {
			return nil, err
		}
		if isTLS {
			utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos}
			tlsC := utls.UClient(c, utlsConfig, utls.HelloChrome_Auto)
			if err := tlsC.Handshake(); err != nil {
				c.Close()
				return nil, err
			}
			return tlsC, nil
		}
		return c, nil
	}

	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	reqURL := fmt.Sprintf("%s://%s%s", scheme, cfg.SNI, cfg.Path)
	sessionID := generateRandomHex(16)

	var rt http.RoundTripper
	if protocol == "h2" {
		rt = &http2.Transport{
			AllowHTTP:      true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) { return coreDial() },
		}
	} else {
		// 扩大连接池防并发耗尽
		t1 := &http.Transport{ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 200}
		if isTLS {
			t1.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return coreDial() }
		} else {
			t1.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return coreDial() }
		}
		rt = t1
	}

	client := &http.Client{Transport: rt, Timeout: 30 * time.Second}
	virtualConn := newMeekVirtualConn(sessionID, firstConn.LocalAddr(), firstConn.RemoteAddr())

	go func() {
		defer virtualConn.Close()
		consecutiveErrors := 0 // 熔断计数器

		for !virtualConn.closed {
			upData := virtualConn.takeWriteBuf(32768)

			req, _ := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(upData))
			req.ContentLength = int64(len(upData))
			if cfg.Host != "" {
				req.Host = cfg.Host
			}
			if cfg.Password != "" {
				req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Password)
			}
			req.Header.Set("X-Target", targetAddr)
			req.Header.Set("X-Network", network)
			req.Header.Set("X-Session-ID", sessionID)
			req.Header.Set("Content-Type", "application/octet-stream")

			resp, err := client.Do(req)

			if err != nil {
				// 数据抢救
				if len(upData) > 0 {
					virtualConn.putWriteBufFront(upData)
				}

				consecutiveErrors++
				if consecutiveErrors > 5 {
					// 连续 5 次失败（约 3 秒），直接熔断释放，防止永远挂起产生死锁！
					logger.Error("❌ [Client] 连接严重超时, 触发熔断保护", zap.String("session", sessionID))
					break
				}
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// 成功则重置错误计数
			consecutiveErrors = 0
			downData, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if len(downData) > 0 {
				virtualConn.putReadBuf(downData)
			}

			if len(upData) == 0 && len(downData) == 0 && !virtualConn.HasWriteData() {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	return newXhttpFramedConn(virtualConn, virtualConn, virtualConn.Close, virtualConn.local, virtualConn.remote), nil
}

// ==========================================
// 5. 服务端 Listener
// ==========================================

var (
	meekSessions = make(map[string]*meekVirtualConn)
	meekMutex    sync.RWMutex
	cleanerOnce  sync.Once
)

type XHTTPListener struct {
	connCh        chan *xhttpFramedConn
	ln            net.Listener
	expectedToken string
	RequestCount  uint64
}

func (l *XHTTPListener) Accept() (net.Conn, error) {
	conn, ok := <-l.connCh
	if !ok {
		return nil, fmt.Errorf("closed")
	}
	return conn, nil
}
func (l *XHTTPListener) Close() error   { return l.ln.Close() }
func (l *XHTTPListener) Addr() net.Addr { return l.ln.Addr() }

func ListenXHTTP(listenAddr, path, token, certFile, keyFile string) (*XHTTPListener, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	xl := &XHTTPListener{connCh: make(chan *xhttpFramedConn, 256), ln: ln, expectedToken: token}

	cleanerOnce.Do(func() {
		go func() {
			for {
				time.Sleep(1 * time.Minute)
				now := time.Now().Unix()
				meekMutex.Lock()
				for id, v := range meekSessions {
					if now-atomic.LoadInt64(&v.lastActive) > 120 {
						v.Close()
						delete(meekSessions, id)
					}
				}
				meekMutex.Unlock()
			}
		}()
	})

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&xl.RequestCount, 1)

		target := r.Header.Get("X-Target")
		network := r.Header.Get("X-Network")
		sessionID := r.Header.Get("X-Session-ID")

		if sessionID == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if xl.expectedToken != "" && r.Header.Get("Proxy-Authorization") != "Bearer "+xl.expectedToken {
			http.Error(w, "Proxy Auth Required", http.StatusProxyAuthRequired)
			return
		}

		meekMutex.Lock()
		vConn, exists := meekSessions[sessionID]
		if !exists {
			vConn = newMeekVirtualConn(sessionID, stringAddr(r.Host), stringAddr(r.RemoteAddr))
			meekSessions[sessionID] = vConn
			meekMutex.Unlock()

			xConn := newXhttpFramedConn(vConn, vConn, func() error {
				meekMutex.Lock()
				delete(meekSessions, sessionID)
				meekMutex.Unlock()
				return vConn.Close()
			}, vConn.local, vConn.remote)
			xConn.targetAddr = target
			xConn.network = network

			xl.connCh <- xConn
			logger.Debug("🆕 [Server] 收到全新隧道会话", zap.String("session", sessionID))
		} else {
			vConn.updateActive()
			meekMutex.Unlock()
		}

		upData, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if len(upData) > 0 {
			vConn.putReadBuf(upData)
		}

		var downData []byte
		if len(upData) > 0 {
			downData = vConn.takeWriteBuf(65536)
		} else {
			startWait := time.Now()
			for {
				downData = vConn.takeWriteBuf(65536)
				if downData != nil || time.Since(startWait) > 100*time.Millisecond || vConn.closed {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(downData)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if len(downData) > 0 {
			w.Write(downData)
		}
	})

	server := &http.Server{IdleTimeout: 1 * time.Hour}

	if certFile != "" && keyFile != "" {
		server.Handler = mux
		go func() {
			if err := server.ServeTLS(ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Fatal("TLS 异常退出", zap.Error(err))
			}
		}()
	} else {
		server.Handler = h2c.NewHandler(mux, &http2.Server{IdleTimeout: 1 * time.Hour})
		go func() {
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				logger.Fatal("H2C 异常退出", zap.Error(err))
			}
		}()
	}
	return xl, nil
}

// ==========================================
// 6. 主逻辑与路由
// ==========================================

func main() {
	mode := flag.String("mode", "", "client or server")
	listen := flag.String("listen", "127.0.0.1:1080", "Listen addr")
	serverURLFlag := flag.String("server", "https://abc.com/stream", "Server URL")
	forward := flag.String("forward", "8.8.8.8:53", "Forward target")
	defaultTarget := flag.String("default-target", "tcp://127.0.0.1:80", "Default target")
	psk := flag.String("psk", "my-secret-token", "PSK")
	sniFlag := flag.String("sni", "", "Custom TLS SNI")
	hostFlag := flag.String("host", "", "Custom HTTP Host header")
	alpnFlag := flag.String("alpn", "auto", "Force ALPN protocol")
	certFlag := flag.String("cert", "", "TLS Cert")
	keyFlag := flag.String("key", "", "TLS Key")
	logLevelFlag := flag.String("loglevel", "info", "Log level")
	dumpFlag := flag.Bool("dump", false, "Dump Hex")
	flag.Parse()

	initLogger(*logLevelFlag)
	defer logger.Sync()

	if *mode == "client" {
		runClient(*listen, *serverURLFlag, *forward, *psk, *sniFlag, *hostFlag, *alpnFlag, *dumpFlag)
	} else if *mode == "server" {
		runServer(*listen, "/stream", *defaultTarget, *psk, *certFlag, *keyFlag, *dumpFlag)
	} else {
		logger.Fatal("请指定模式")
	}
}

func runClient(listenStr, serverURLStr, forwardTarget, psk, customSNI, customHost, alpn string, dump bool) {
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

	cfg := &Config{Password: psk, Path: serverURL.Path, SNI: sni, Host: host, ALPN: alpn}

	if u.Scheme == "tcp" {
		ln, err := net.Listen("tcp", u.Host)
		if err != nil {
			logger.Fatal("TCP监听失败", zap.Error(err))
		}
		logger.Info("🚀 Client 启动成功", zap.String("addr", u.Host), zap.String("ALPN", alpn))

		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go func() {
				defer conn.Close()
				xc, err := DialXHTTP(serverURL, cfg, forwardTarget, "tcp")
				if err != nil {
					logger.Error("❌ 拨号失败", zap.Error(err))
					return
				}
				defer xc.Close()

				var clientConn net.Conn = conn
				if dump {
					clientConn = &DumpConn{Conn: conn, Prefix: "Client Local"}
				}

				go func() {
					io.Copy(xc, clientConn)
					if xfc, ok := xc.(*xhttpFramedConn); ok {
						xfc.WriteCloseFrame()
					}
					clientConn.Close()
				}()
				io.Copy(clientConn, xc)
			}()
		}
	} else if u.Scheme == "udp" {
		pc, err := net.ListenPacket("udp", u.Host)
		if err != nil {
			logger.Fatal("UDP监听失败", zap.Error(err))
		}
		logger.Info("🚀 Client(UDP) 启动成功")
		// UDP逻辑保持不变...
		sessionMap := make(map[string]net.Conn)
		var mu sync.Mutex
		buf := make([]byte, 65535)
		for {
			n, cAddr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}

			mu.Lock()
			xc, exists := sessionMap[cAddr.String()]
			if !exists {
				xc, err = DialXHTTP(serverURL, cfg, forwardTarget, "udp")
				if err != nil {
					mu.Unlock()
					continue
				}
				sessionMap[cAddr.String()] = xc
				go func(addr net.Addr, conn net.Conn) {
					defer conn.Close()
					defer func() { mu.Lock(); delete(sessionMap, addr.String()); mu.Unlock() }()
					dBuf := make([]byte, 65535)
					for {
						l, err := readUDPFrameInto(conn, dBuf)
						if err != nil {
							return
						}
						pc.WriteTo(dBuf[:l], addr)
					}
				}(cAddr, xc)
			}
			mu.Unlock()
			writeUDPFrame(xc, buf[:n])
		}
	}
}

func runServer(listenAddr, path, defaultTargetStr, psk, certFile, keyFile string, dump bool) {
	defURL, err := url.Parse(defaultTargetStr)
	if err != nil {
		logger.Fatal("解析失败", zap.Error(err))
	}

	var host string
	if strings.Contains(listenAddr, "://") {
		u, _ := url.Parse(listenAddr)
		host = u.Host
	} else {
		host = listenAddr
	}

	xl, err := ListenXHTTP(host, path, psk, certFile, keyFile)
	if err != nil {
		logger.Fatal("Server 监听失败", zap.Error(err))
	}
	logger.Info("🚀 Server 启动成功", zap.String("listen", host))

	for {
		conn, err := xl.Accept()
		if err != nil {
			continue
		}

		go func(xc *xhttpFramedConn) {
			defer xc.Close()
			target, network := xc.targetAddr, xc.network
			if target == "" {
				target = defURL.Host
			}
			if network == "" {
				network = defURL.Scheme
			}

			if network == "tcp" {
				rc, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					logger.Error("❌ 无法连接目标服务", zap.Error(err))
					xc.WriteCloseFrame()
					return
				}
				defer rc.Close()

				var targetConn net.Conn = rc
				if dump {
					targetConn = &DumpConn{Conn: rc, Prefix: "Server Target"}
				}

				go func() {
					io.Copy(targetConn, xc)
					if c, ok := targetConn.(interface{ CloseWrite() error }); ok {
						c.CloseWrite()
					} else {
						targetConn.Close()
					}
				}()
				io.Copy(xc, targetConn)
				xc.WriteCloseFrame()

			} else if network == "udp" {
				rc, err := net.DialTimeout("udp", target, 5*time.Second)
				if err != nil {
					return
				}
				defer rc.Close()
				go func() {
					uBuf := make([]byte, 65535)
					for {
						n, err := readUDPFrameInto(xc, uBuf)
						if err != nil {
							return
						}
						rc.Write(uBuf[:n])
					}
				}()
				dBuf := make([]byte, 65535)
				for {
					n, err := rc.Read(dBuf)
					if err != nil {
						return
					}
					writeUDPFrame(xc, dBuf[:n])
				}
			}
		}(conn.(*xhttpFramedConn))
	}
}
