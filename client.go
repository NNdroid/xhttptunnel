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

var (
	maxClientSessions = 2000
)

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
	cfg.Path = serverURL.Path

	nextProtos := buildNextProtos(cfg.ALPN)

	logger.Debug("[Sniffer] ⏳ 正在探测底层连接...", zap.String("host", serverURL.Hostname()), zap.String("port", basePort), zap.Strings("protos", nextProtos))
	firstConn, err := net.DialTimeout("tcp", net.JoinHostPort(serverURL.Hostname(), basePort), 10*time.Second)
	if err != nil {
		return nil, err
	}

	localAddr := firstConn.LocalAddr()
	remoteAddr := firstConn.RemoteAddr()

	var protocol string
	if isTLS {
		alpnPref := strings.ToLower(strings.TrimSpace(cfg.ALPN))
		if alpnPref == "h3" || alpnPref == "auto" {
			hostPort := net.JoinHostPort(serverURL.Hostname(), basePort)
			logger.Debug("尝试使用 QUIC/HTTP3 探测", zap.String("hostport", hostPort), zap.String("sni", cfg.SNI))
			ok, perr := probeHTTP3(context.Background(), hostPort, cfg.SNI, 1800*time.Millisecond, cfg.CertificateFingerprint)
			if ok && perr == nil {
				protocol = "h3"
				_ = firstConn.Close() // 关键：已探测并切换至 QUIC/H3，立即释放预建的 TCP Socket，防止连接泄漏
				logger.Debug("QUIC/HTTP3 探测成功，使用 HTTP/3", zap.String("host", serverURL.Hostname()))
			} else {
				logger.Debug("QUIC/HTTP3 探测失败，回落至 TCP/TLS 探测", zap.String("host", serverURL.Hostname()), zap.Error(perr))
			}
		}

		if protocol == "" {
			utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos, VerifyPeerCertificate: verifyFingerprint(cfg.CertificateFingerprint)}
			tlsConn := utls.UClient(firstConn, utlsConfig, utls.HelloChrome_Auto)

			if err := tlsConn.BuildHandshakeState(); err != nil {
				firstConn.Close()
				return nil, fmt.Errorf("utls build handshake state failed: %w", err)
			}

			for _, ext := range tlsConn.Extensions {
				if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
					alpnExt.AlpnProtocols = nextProtos
					break
				}
			}

			if err := tlsConn.Handshake(); err != nil {
				firstConn.Close()
				return nil, err
			}
			firstConn = tlsConn
			neg := tlsConn.ConnectionState().NegotiatedProtocol
			if neg == "" {
				if slices.Contains(nextProtos, "h2") {
					protocol = "h2"
				} else {
					protocol = "http/1.1"
				}
			} else {
				protocol = neg
			}
			logger.Debug("[Sniffer] ✅ TLS 探测完成", zap.String("ALPN", protocol), zap.String("SNI", cfg.SNI))
		}
	} else {
		protocol = "http/1.1"
		if slices.Contains(nextProtos, "h2") {
			protocol = "h2"
		}
		logger.Debug("[Sniffer] ✅ 尝试明文HTTP", zap.String("ALPN", protocol))
	}

	var connConsumed atomic.Bool
	coreDial := func() (net.Conn, error) {
		if connConsumed.CompareAndSwap(false, true) {
			return firstConn, nil
		}

		logger.Debug("⏳ [Dialer] 补充建立底层 TCP/TLS 连接...")
		c, err := net.DialTimeout("tcp", net.JoinHostPort(serverURL.Hostname(), basePort), 10*time.Second)
		if err != nil {
			logger.Error("❌ [Dialer] 补充连接建立失败", zap.Error(err))
			return nil, err
		}
		if isTLS {
			utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos, VerifyPeerCertificate: verifyFingerprint(cfg.CertificateFingerprint)}
			tlsC := utls.UClient(c, utlsConfig, utls.HelloChrome_Auto)

			if err := tlsC.BuildHandshakeState(); err != nil {
				c.Close()
				return nil, fmt.Errorf("utls build handshake state failed: %w", err)
			}

			for _, ext := range tlsC.Extensions {
				if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
					alpnExt.AlpnProtocols = nextProtos
					break
				}
			}

			if err := tlsC.Handshake(); err != nil {
				logger.Error("❌ [Dialer] 补充 TLS 握手失败", zap.Error(err))
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
	realHostPort := net.JoinHostPort(serverURL.Hostname(), basePort)
	reqURL := fmt.Sprintf("%s://%s%s", scheme, realHostPort, cfg.Path)
	sessionID := generateRandomHex(16)

	var rt http.RoundTripper
	if protocol == "h3" {
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/3 (QUIC) 作为传输", zap.String("session", sessionID))
		rt = &http3.Transport{
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
	} else if protocol == "h2" {
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/2 作为传输", zap.String("session", sessionID))
		rt = &http2.Transport{
			AllowHTTP:      true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) { return coreDial() },
		}
	} else {
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/1.1 作为传输", zap.String("session", sessionID))
		t1 := &http.Transport{ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 100, MaxConnsPerHost: 100, DisableKeepAlives: false}
		if isTLS {
			t1.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return coreDial() }
		} else {
			t1.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return coreDial() }
		}
		rt = t1
	}

	client := &http.Client{Transport: rt, Timeout: 90 * time.Second}
	virtualConn := newMeekVirtualConn(sessionID, localAddr, remoteAddr)

	pumpCtx, pumpCancel := context.WithCancel(ctx)
	logger.Debug("🚀 启动客户端 HTTP 数据泵", zap.String("session", sessionID), zap.String("target", targetAddr), zap.String("transport", fmt.Sprintf("%T", rt)))

	go func() {
		defer virtualConn.Close()
		defer logger.Debug("💀 客户端 HTTP 数据泵已停止", zap.String("session", sessionID))

		var ackedByServer uint64
		var dispatchSeq uint64
		var windowMu sync.Mutex
		var triggerRetry int32
		var emptyPollers int32

		workerCount := 8
		restartCount := 0

		for !virtualConn.closed {
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
			if virtualConn.closed || pumpCtx.Err() != nil {
				break
			}

			var consecutiveErrors int32
			var wg sync.WaitGroup

			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					for !virtualConn.closed {
						windowMu.Lock()
						currentAck := atomic.LoadUint64(&ackedByServer)
						if dispatchSeq < currentAck {
							dispatchSeq = currentAck
						}
						upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(currentAck, dispatchSeq, maxsendBufSize)
						if len(upData) == 0 {
							if atomic.LoadInt32(&emptyPollers) >= 1 {
								windowMu.Unlock()
								virtualConn.writeBuf.mu.Lock()
								virtualConn.writeBuf.cond.Wait()
								virtualConn.writeBuf.mu.Unlock()
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
							bodyReader = bytes.NewReader(upData)
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
						if cfg.Host != "" {
							req.Host = cfg.Host
						} else if cfg.SNI != "" {
							req.Host = cfg.SNI
						}
						req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5410.0 Safari/537.36 Client/"+Version)
						if cfg.Password != "" {
							req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Password)
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
							virtualConn.writeBuf.cond.Broadcast()
						}

						if err != nil {
							safelyPutSendBuf(upBufPtr)
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
							safelyPutSendBuf(upBufPtr)

							downBuf := bytesBufPool.Get().(*bytes.Buffer)
							downBuf.Reset()
							downBuf.ReadFrom(resp.Body)
							bodyErr := downBuf.Bytes()
							resp.Body.Close()

							logger.Error("❌ [Pump] 收到异常 HTTP 状态码",
								zap.String("session", sessionID),
								zap.Int("status", resp.StatusCode),
								zap.String("error_body", string(bodyErr)),
							)

							bytesBufPool.Put(downBuf)
							time.Sleep(2 * time.Second)
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
							safelyPutSendBuf(upBufPtr)

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

						safelyPutSendBuf(upBufPtr)

						if len(upData) == 0 && totalDownBytes == 0 && virtualConn.writeBuf.Len() == 0 {
							time.Sleep(100 * time.Millisecond)
						}
					}
				}(i)
			}
			wg.Wait()
			restartCount++
		}

		if rt3, ok := rt.(*http3.Transport); ok {
			logger.Debug("🧹 [Dialer] 关闭 HTTP/3 Transport", zap.String("session", sessionID))
			rt3.Close()
		}
	}()

	return newXhttpFramedConn(virtualConn, virtualConn, func() error { pumpCancel(); return virtualConn.Close() }, virtualConn.local, virtualConn.remote), nil
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

				clientConn.SetDeadline(time.Now().Add(5 * time.Minute))

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
					var written int64
					for {
						nr, er := clientConn.Read(buf)
						if nr > 0 {
							clientConn.SetDeadline(time.Now().Add(5 * time.Minute))
							nw, ew := xc.Write(buf[:nr])
							if nw > 0 {
								written += int64(nw)
							}
							if ew != nil {
								err = ew
								break
							}
						}
						if er != nil {
							err = er
							break
						}
					}
					n := written

					if err != nil && err != io.EOF {
						logger.Debug("⚠️ [TCP] 上行转发 (Local->Server) 异常结束", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
					} else {
						logger.Debug("🛑 [TCP] 上行转发 (Local->Server) 正常结束", zap.String("id", connID), zap.Int64("bytes", n))
					}
				}()

				n, err := io.Copy(clientConn, xc)
				if err != nil && err != io.EOF {
					logger.Debug("⚠️ [TCP] 下行转发 (Server->Local) 异常结束", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
				} else {
					logger.Debug("🛑 [TCP] 下行转发 (Server->Local) 正常结束", zap.String("id", connID), zap.Int64("bytes", n))
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

			mu.Lock()
			sess, exists := sessionMap[cAddr.String()]
			if !exists {
				if len(sessionMap) >= maxClientSessions {
					mu.Unlock()
					logger.Warn("❌ [UDP] 拒绝本地新会话: 达到最大并发限制", zap.Int("limit", maxClientSessions), zap.String("client", cAddr.String()))
					continue
				}

				connID := generateRandomHex(4)
				logger.Debug("🔌 [UDP] 发现新本地客户端，准备建立隧道", zap.String("id", connID), zap.String("client", cAddr.String()))

				xc, err := DialXHTTP(ctx, serverURL, cfg, forwardTarget, "udp")
				if err != nil {
					logger.Error("❌ [UDP] XHTTP 隧道拨号失败", zap.String("id", connID), zap.Error(err))
					mu.Unlock()
					continue
				}
				logger.Debug("✅ [UDP] XHTTP 隧道拨号成功", zap.String("id", connID))

				sess = &udpSession{conn: xc, lastActive: time.Now().Unix()}
				sessionMap[cAddr.String()] = sess

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
			mu.Unlock()

			atomic.StoreInt64(&sess.lastActive, time.Now().Unix())
			if err := writeUDPFrame(sess.conn, buf[:n]); err != nil {
				logger.Debug("⚠️ [UDP] 写入上行 Frame 失败", zap.String("client", cAddr.String()), zap.Error(err))
			}
		}
	}
}
