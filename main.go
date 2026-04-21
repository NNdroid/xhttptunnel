package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	mbig "math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	logger         *zap.Logger
	maxsendBufSize = 900 * 1000
	maxframeSize   = 990 * 1000
	padPoolLen     = 64 * 1024
	padPool        []byte
	// 适配 GetSlice 的最大请求量 (Server 端请求了 900K)
	sendBuf = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 990*1000)
			return &b
		},
	}
	// bytes.Buffer 池：用于替代高频且昂贵的 io.ReadAll
	bytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

func init() {
	// 随机填充池初始化
	padPool = make([]byte, padPoolLen)
	io.ReadFull(rand.Reader, padPool)
}

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
// 2. 高性能可靠传输缓冲区 (Seq/Ack 机制)
// ==========================================

type reliableBuffer struct {
	mu         sync.RWMutex
	data       []byte // 原始数据缓冲区
	baseOffset uint64 // 当前 data[0] 对应的绝对偏移量 (Seq)
}

func (rb *reliableBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.data = append(rb.data, p...)
	return len(p), nil
}

// GetSlice 获取从指定偏移量开始的数据，并清理掉已被对端确认 (Ack) 的旧数据
func (rb *reliableBuffer) GetSlice(remoteAck uint64, dispatchSeq uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// 1. 清理对端已经确认收到的数据
	if remoteAck > rb.baseOffset {
		skip := remoteAck - rb.baseOffset
		if skip <= uint64(len(rb.data)) {
			rb.data = rb.data[skip:]
			rb.baseOffset = remoteAck

			// 【惰性緊縮】：如果底層陣列膨脹超過 4MB 且空間浪費過半，才真正釋放記憶體
			if cap(rb.data) > 4*1024*1024 && len(rb.data) < cap(rb.data)/2 {
				newData := make([]byte, len(rb.data))
				copy(newData, rb.data)
				rb.data = newData
			}
		} else {
			rb.data = nil
			rb.baseOffset = remoteAck
		}
	}

	// 修正派发起点：如果派发指针落后于已确认位置（说明发生了重传重置），则从当前最老的数据开始
	if dispatchSeq < rb.baseOffset {
		dispatchSeq = rb.baseOffset
	}

	// 计算相对于当前缓冲区头部的偏移量
	offsetInBuf := dispatchSeq - rb.baseOffset
	if offsetInBuf >= uint64(len(rb.data)) {
		return nil, dispatchSeq, nil // 没有新数据可以派发
	}

	// 截取分片
	availLen := uint64(len(rb.data)) - offsetInBuf
	length := int(availLen)
	if length > maxLen {
		length = maxLen
	}

	// 使用内存池进行拷贝
	bufPtr := sendBuf.Get().(*[]byte)
	res := (*bufPtr)[:length]
	copy(res, rb.data[offsetInBuf:offsetInBuf+uint64(length)])

	// 返回：数据切片, 本次实际使用的Seq, 内存池指针
	return res, dispatchSeq, bufPtr
}

func (rb *reliableBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.data)
}

// ==========================================
// 3. Meek 虚拟连接 (集成可靠传输)
// ==========================================

type meekVirtualConn struct {
	sessionID string
	local     net.Addr
	remote    net.Addr

	readCond    *sync.Cond
	readBuf     bytes.Buffer
	nextReadSeq uint64            // 我方期待收到的下一个 Seq
	oooBuf      map[uint64][]byte // 乱序缓存

	writeBuf *reliableBuffer // 替换原来的 bytes.Buffer

	closed          bool
	lastActive      int64
	downDispatchSeq uint64     // 服务端下发给客户端的任务游标
	downWindowMu    sync.Mutex // 保护下发游标的并发锁
}

func newMeekVirtualConn(sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		sessionID:  sessionID,
		local:      local,
		remote:     remote,
		readCond:   sync.NewCond(&sync.Mutex{}),
		writeBuf:   &reliableBuffer{},
		lastActive: time.Now().Unix(),
		oooBuf:     make(map[uint64][]byte),
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
	// TCP 背壓限制 (Flow Control)
	// 防止本地端上傳過快導致記憶體暴漲 100MB+，限制積壓上限為 4MB
	for {
		if c.closed {
			return 0, io.ErrClosedPipe
		}
		if c.writeBuf.Len() < 4*1024*1024 {
			break
		}
		time.Sleep(5 * time.Millisecond) // 阻塞，強迫本地 VPN/代理 客戶端減速
	}
	return c.writeBuf.Write(p)
}

// PutReadData 乱序重组
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	if len(data) > 0 {
		if seq == c.nextReadSeq {
			// 1. 序號正好匹配，寫入緩衝區
			c.readBuf.Write(data)
			c.nextReadSeq += uint64(len(data))

			// 2. 檢查暫存區有沒有「未來的包」現在可以接上了
			for {
				if nextData, ok := c.oooBuf[c.nextReadSeq]; ok {
					c.readBuf.Write(nextData)
					delete(c.oooBuf, c.nextReadSeq)
					c.nextReadSeq += uint64(len(nextData))
				} else {
					break
				}
			}
			c.readCond.Broadcast()
		} else if seq > c.nextReadSeq {
			// 3. 序號太新了，先存進 map
			if len(c.oooBuf) < 1024 { // 防止惡意內存撐爆
				// 因为外层使用了 bytesBufPool，这里必须分配独立内存拷贝！
				dataCopy := make([]byte, len(data))
				copy(dataCopy, data)
				c.oooBuf[seq] = dataCopy
			}
		}
	}
	return c.nextReadSeq
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
// 4. XHTTP 动态 Padding 与 EOF 信令装甲
// ==========================================

type xhttpFramedConn struct {
	r             io.Reader
	w             io.Writer
	closer        func() error
	local         net.Addr
	remote        net.Addr
	targetAddr    string
	network       string
	mu            sync.Mutex
	readBuf       []byte
	frameBuf      []byte
	hdrBuf        []byte
	payloadBuf    []byte
	closeCh       chan struct{}
	closedFlag    int32
	lastWriteTime int64
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	conn := &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		frameBuf: make([]byte, maxframeSize), hdrBuf: make([]byte, 6), payloadBuf: make([]byte, maxsendBufSize),
		closeCh:       make(chan struct{}),
		lastWriteTime: time.Now().Unix(),
	}
	go conn.heartbeatLoop()
	return conn
}

func (c *xhttpFramedConn) WriteCloseFrame() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	frame := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
	_, err := c.w.Write(frame)
	return err
}

func (c *xhttpFramedConn) heartbeatLoop() {
	// 巡逻周期设为 5 秒（不用频繁唤醒），但判断阈值依然是 20 秒
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// 获取上次真实发送数据的时间
			last := atomic.LoadInt64(&c.lastWriteTime)

			// 如果距离上次发包已经过去了 20 秒，说明连接处于绝对空闲状态
			if time.Now().Unix()-last >= 20 {
				c.Write(nil) // 发送空，这会自动触发上面的 StoreInt64 刷新时间
			}
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

	frameLen := 6 + padLenInt + chunkSize
	// 判断cap是否足够
	if frameLen > cap(c.frameBuf) {
		// 如果 不够使用2倍扩容
		newCap := cap(c.frameBuf) * 2
		if newCap < frameLen {
			newCap = frameLen
		}
		c.frameBuf = make([]byte, frameLen, newCap)
	} else {
		//  足够，直接拉伸
		c.frameBuf = c.frameBuf[:frameLen]
	}
	//写入header
	binary.BigEndian.PutUint32(c.frameBuf[0:4], uint32(chunkSize)) // payload length
	binary.BigEndian.PutUint16(c.frameBuf[4:6], uint16(padLenInt)) // padding length
	//填充padding
	if padLenInt > 0 {
		offset := mrand.Intn(padPoolLen - padLenInt)
		copy(c.frameBuf[6:6+padLenInt], padPool[offset:offset+padLenInt])
	}
	// 写入payload
	if chunkSize > 0 {
		copy(c.frameBuf[6+padLenInt:], chunk)
	}

	_, err := c.w.Write(c.frameBuf)
	return err
}

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	atomic.StoreInt64(&c.lastWriteTime, time.Now().Unix())
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, c.writeSingleFrame(nil)
	}

	written := 0
	maxPayload := maxframeSize
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
	if len(c.readBuf) > 0 { // 没有len信息，所以readBuf有就直接返回
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		if _, err := io.ReadFull(c.r, c.hdrBuf); err != nil {
			return 0, err
		}
		rawPayloadLen := binary.BigEndian.Uint32(c.hdrBuf[0:4])
		padLen := int(binary.BigEndian.Uint16(c.hdrBuf[4:6]))

		// 直接复用 c.payloadBuf 当作“垃圾桶”来接收 padding
		if padLen > 0 {
			if padLen > cap(c.payloadBuf) {
				c.payloadBuf = make([]byte, padLen)
			}
			if _, err := io.ReadFull(c.r, c.payloadBuf[:padLen]); err != nil {
				return 0, err
			}
		}

		// 处理特殊信令和空帧
		if rawPayloadLen == uint32(0xFFFFFFFF) {
			return 0, io.EOF
		}
		if rawPayloadLen == 0 {
			continue
		}

		payloadLen := int(rawPayloadLen)

		// 计算可以直接读入 buffer `p` 的长度
		readIntoP := payloadLen
		if readIntoP > len(p) {
			readIntoP = len(p) // buffer 容量有限，只能装下这么多了
		}
		// 数据直接从 io.Reader 灌入用户的 p
		if _, err := io.ReadFull(c.r, p[:readIntoP]); err != nil {
			return 0, err
		}

		// 如果用户的 p 太小，剩下的 payload 必须读入内部 buffer 暂存
		leftover := payloadLen - readIntoP
		if leftover > 0 {
			// 使用 cap 而不是 len 来判断，最大程度减少 make() 重新分配内存的次数
			if leftover > cap(c.payloadBuf) {
				c.payloadBuf = make([]byte, leftover)
			}
			leftoverBuf := c.payloadBuf[:leftover]

			if _, err := io.ReadFull(c.r, leftoverBuf); err != nil {
				// 如果前面给用户的 p 已经读了 readIntoP 字节，
				// 这里哪怕断开，也应该把已读到的长度返回给上层
				return readIntoP, err
			}
			// 保存这部分没被拿走的数据，供下一次 Read 消费
			c.readBuf = leftoverBuf
		}
		return readIntoP, nil
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
// 5. 客户端极速稳态轮询拨号器 (滑动窗口整合)
// ==========================================

// helper: 根据 cfg.ALPN 构建用于 TLS 探测/握手的 NextProtos 列表
func buildNextProtos(alpn string) []string {
	alpn = strings.ToLower(strings.TrimSpace(alpn))
	switch alpn {
	case "h1", "http/1.1":
		return []string{"http/1.1"}
	case "h2":
		return []string{"h2", "http/1.1"}
	case "h3":
		// 针对 QUIC/HTTP3，包含常见 h3 变体以提高兼容性
		return []string{"h3", "h3-32", "h3-31", "h3-30", "h3-29", "h2", "http/1.1"}
	default: // auto
		return []string{"h3", "h3-32", "h3-31", "h3-30", "h3-29", "h2", "http/1.1"}
	}
}

// probeHTTP3: 使用 quic.DialAddr 尝试一次轻量的 QUIC/TLS 握手探测（短超时）。
// hostPort 格式 "example.com:443"，sni 为 TLS ServerName，timeout 推荐 1500-2500ms。
func probeHTTP3(ctx context.Context, hostPort, sni string, timeout time.Duration) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		NextProtos:         []string{"h3", "h3-32", "h3-31", "h3-30", "h3-29"},
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
		// 握手成功，立即关闭会话释放服务端资源
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

	// 根据配置构建 NextProtos（包含 h3 变体以提高兼容性）
	nextProtos := buildNextProtos(cfg.ALPN)

	logger.Debug("[Sniffer] ⏳ 正在探测底层连接...", zap.String("host", serverURL.Hostname()), zap.String("port", basePort), zap.Strings("protos", nextProtos))
	firstConn, err := net.DialTimeout("tcp", net.JoinHostPort(serverURL.Hostname(), basePort), 10*time.Second)
	if err != nil {
		return nil, err
	}

	var protocol string // 空字符串表示尚未确定
	if isTLS {
		// 优先尝试 QUIC/HTTP3 探测（仅在用户期望 h3 或 auto 时）
		alpnPref := strings.ToLower(strings.TrimSpace(cfg.ALPN))
		if alpnPref == "h3" || alpnPref == "auto" {
			hostPort := net.JoinHostPort(serverURL.Hostname(), basePort) // 默认 UDP 端口与 TCP 端口相同，通常是 443
			logger.Debug("尝试使用 QUIC/HTTP3 探测", zap.String("hostport", hostPort), zap.String("sni", cfg.SNI))
			ok, perr := probeHTTP3(context.Background(), hostPort, cfg.SNI, 1800*time.Millisecond)
			if ok && perr == nil {
				protocol = "h3"
				logger.Debug("QUIC/HTTP3 探测成功，使用 HTTP/3", zap.String("host", serverURL.Hostname()))
			} else {
				logger.Debug("QUIC/HTTP3 探测失败，回落至 TCP/TLS 探测", zap.String("host", serverURL.Hostname()), zap.Error(perr))
			}
		}

		// 如果尚未确定为 h3，就继续做 TCP+TLS(uTLS) 探测以判断 h2/h1
		if protocol == "" {
			utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos}
			tlsConn := utls.UClient(firstConn, utlsConfig, utls.HelloChrome_Auto)

			// 提前构建握手状态
			if err := tlsConn.BuildHandshakeState(); err != nil {
				firstConn.Close() // 必须显式关闭底层连接，防止泄露
				return nil, fmt.Errorf("utls build handshake state failed: %w", err)
			}

			// 找到 ALPN 扩展并强行修改为 nextProtos
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
				// 未协商到 ALPN；按 nextProtos 回退到合理值
				if slices.Contains(nextProtos, "h2") {
					protocol = "h2"
				} else {
					protocol = "http/1.1"
				}
			} else {
				// 有协商结果，可能是 "h2" 或 "http/1.1" 等
				protocol = neg
			}
			logger.Debug("[Sniffer] ✅ TLS 探测完成", zap.String("ALPN", protocol), zap.String("SNI", cfg.SNI))
		}
	} else {
		// 明文，仅尝试 http/2 via TCP (h2c) 或 http/1.1
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
			utlsConfig := &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true, NextProtos: nextProtos}
			tlsC := utls.UClient(c, utlsConfig, utls.HelloChrome_Auto)

			// 提前构建握手状态
			if err := tlsC.BuildHandshakeState(); err != nil {
				c.Close() // 必须显式关闭底层连接，防止泄露
				return nil, fmt.Errorf("utls build handshake state failed: %w", err)
			}

			// 找到 ALPN 扩展并强行修改为 nextProtos
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
	// 根据探测/配置决定使用哪类 Transport
	if protocol == "h3" {
		logger.Debug("🚀 [Dialer] 准备使用 HTTP/3 (QUIC) 作为传输", zap.String("session", sessionID))
		rt = &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         cfg.SNI,
				NextProtos:         []string{"h3", "h3-32", "h3-31", "h3-30", "h3-29"},
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
	virtualConn := newMeekVirtualConn(sessionID, firstConn.LocalAddr(), firstConn.RemoteAddr())

	logger.Debug("🚀 启动客户端 HTTP 数据泵", zap.String("session", sessionID), zap.String("target", targetAddr), zap.String("transport", fmt.Sprintf("%T", rt)))

	// 客户端数据泵
	go func() {
		defer virtualConn.Close()
		defer logger.Debug("💀 客户端 HTTP 数据泵已停止", zap.String("session", sessionID))

		var ackedByServer uint64    // 记录服务端已经确认的 Seq
		var dispatchSeq uint64      // 任务派发线（发送线）
		var windowMu sync.Mutex     // 保护两个游标的并发操作
		var consecutiveErrors int32 // 错误计数
		var triggerRetry int32      // 是否携带 X-Retry
		var emptyPollers int32      // 当前正在空手去服务端拉取数据的 Worker 数量

		workerCount := 8
		var wg sync.WaitGroup

		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for !virtualConn.closed {
					// 抢占任务：从写缓冲中划走一段数据
					windowMu.Lock()
					currentAck := atomic.LoadUint64(&ackedByServer)
					// 如果派发游标落后（重传重置），强制对齐
					if dispatchSeq < currentAck {
						dispatchSeq = currentAck
					}
					// GetSlice 实现了核心的滑动窗口：传入对方已确认的 Ack，返回当前应发的数据及对应的 Seq
					upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(currentAck, dispatchSeq, maxsendBufSize)
					// 空载限流
					if len(upData) == 0 {
						// 如果没有上行数据，只允许最多 2 个 Worker 去服务端进行长轮询
						if atomic.LoadInt32(&emptyPollers) >= 2 {
							windowMu.Unlock()
							time.Sleep(50 * time.Millisecond) // 其他 Worker 本地待命，不发 HTTP 请求
							continue
						}
						atomic.AddInt32(&emptyPollers, 1) // 登记为一个空载探子
						dispatchSeq = currentSeq          // 对齐游标
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
						// 空包轮询改用 GET，彻底绕过代理对 POST 的 411 拦截
						method = http.MethodGet
						bodyReader = http.NoBody
					}

					req, _ := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)

					if len(upData) > 0 {
						req.ContentLength = int64(len(upData))
					} else {
						// 由于 GET 请求极易被 CDN/代理 缓存，
						// 必须加上随机时间戳强制穿透，保证每次都能拿到最新的下行数据
						q := req.URL.Query()
						q.Set("t", strconv.FormatInt(time.Now().UnixNano(), 36))
						req.URL.RawQuery = q.Encode()
					}

					// 全局防缓存头，给代理双重警告
					req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
					if cfg.Host != "" {
						req.Host = cfg.Host
					} else if cfg.SNI != "" {
						req.Host = cfg.SNI
					}
					if cfg.Password != "" {
						req.Header.Set("Proxy-Authorization", "Bearer "+cfg.Password)
					}
					req.Header.Set("X-Target", targetAddr)
					req.Header.Set("X-Network", network)
					req.Header.Set("X-Session-ID", sessionID)

					virtualConn.readCond.L.Lock()
					myAck := virtualConn.nextReadSeq
					virtualConn.readCond.L.Unlock()

					// 将 Seq 和 Ack 写入 HTTP 头
					req.Header.Set("X-Seq", strconv.FormatUint(currentSeq, 10))
					req.Header.Set("X-Ack", strconv.FormatUint(myAck, 10))
					// GET 请求绝对不能带 Content-Type，否则会被 Azure/严格代理 直接 400 拦截！
					if len(upData) > 0 {
						req.Header.Set("Content-Type", "application/octet-stream")
					}
					// 消费并清除重传信号
					// 如果 triggerRetry 是 1，把它改成 0，并且给当前请求加上 X-Retry
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

					// 请求结束，注销空载探子身份
					if len(upData) == 0 {
						atomic.AddInt32(&emptyPollers, -1)
					}

					if err != nil {
						if upBufPtr != nil {
							sendBuf.Put(upBufPtr)
						}
						logger.Debug("⚠️ [Pump] HTTP 轮询失败，准备重试", zap.String("session", sessionID), zap.Error(err))
						// 【并发核心策略】：一旦出错，重置派发游标到已确认点，触发重传
						windowMu.Lock()
						dispatchSeq = atomic.LoadUint64(&ackedByServer)
						windowMu.Unlock()
						// 激活重传求救信号，通知服务端也回退下行游标！
						atomic.StoreInt32(&triggerRetry, 1)
						if atomic.AddInt32(&consecutiveErrors, 1) > 20 {
							break
						}
						time.Sleep(300 * time.Millisecond)
						continue
					}
					atomic.StoreInt32(&consecutiveErrors, 0)

					// 2. 处理响应头的 Ack，推进清理线
					if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" {
						sAck, _ := strconv.ParseUint(sAckStr, 10, 64)
						for {
							old := atomic.LoadUint64(&ackedByServer)
							if sAck <= old || atomic.CompareAndSwapUint64(&ackedByServer, old, sAck) {
								break
							}
						}
					}

					// 拦截非 200 OK 的异常状态码！
					if resp.StatusCode != http.StatusOK {
						if upBufPtr != nil {
							sendBuf.Put(upBufPtr)
						}

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

					// 更新服务端的 Ack (决定我们下次滑动窗口推多远)
					var sAck uint64
					if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" {
						sAck, _ = strconv.ParseUint(sAckStr, 10, 64)
						for {
							oldAck := atomic.LoadUint64(&ackedByServer)
							if sAck <= oldAck || atomic.CompareAndSwapUint64(&ackedByServer, oldAck, sAck) {
								break
							}
						}
					}

					// 处理服务端的 Seq 及其数据
					sSeqStr := resp.Header.Get("X-Seq")
					sSeq, _ := strconv.ParseUint(sSeqStr, 10, 64)

					downBuf := bytesBufPool.Get().(*bytes.Buffer)
					downBuf.Reset()
					_, errBody := downBuf.ReadFrom(resp.Body)
					downData := downBuf.Bytes()
					resp.Body.Close()

					// 严格校验下行数据的完整性
					if errBody != nil {
						logger.Warn("⚠️ [Pump] 读取下行 Body 失败，触发安全重传", zap.Error(errBody))
						bytesBufPool.Put(downBuf)
						if upBufPtr != nil {
							sendBuf.Put(upBufPtr)
						}

						// 触发重传机制
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
						zap.Int("Down_Bytes", len(downData)),
					)

					if len(downData) > 0 || sSeqStr != "" {
						virtualConn.PutReadData(sSeq, downData)
					}

					// 归还pool
					bytesBufPool.Put(downBuf)
					if upBufPtr != nil {
						sendBuf.Put(upBufPtr)
					}

					// 如果当前轮询是完全空载的（没发也没收），稍微歇一下防止榨干 CPU
					if len(upData) == 0 && len(downData) == 0 && virtualConn.writeBuf.Len() == 0 {
						time.Sleep(100 * time.Millisecond)
					}
				}
			}(i)
		}
		//在这里等待 8 个 Worker 退出
		wg.Wait()

		// 如果使用的是 http3.Transport，需要在退出时调用 Close
		if rt3, ok := rt.(*http3.Transport); ok {
			logger.Debug("🧹 [Dialer] 关闭 HTTP/3 Transport", zap.String("session", sessionID))
			rt3.Close()
		}
	}()

	return newXhttpFramedConn(virtualConn, virtualConn, virtualConn.Close, virtualConn.local, virtualConn.remote), nil
}

// ==========================================
// 6. 服务端 Listener (整合滑动窗口)
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

func ListenXHTTP(ctx context.Context, listenAddr, path, token, certFile, keyFile string) (*XHTTPListener, error) {
	listenAddr = strings.TrimPrefix(listenAddr, "tcp://")
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	xl := &XHTTPListener{connCh: make(chan *xhttpFramedConn, 256), ln: ln, expectedToken: token}

	// 后台清理
	cleanerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done(): // 收到退出信号，停止清理协程
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

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("👀 [HTTP] 收到原始 HTTP 请求",
			zap.String("method", r.Method),
			zap.String("remote", r.RemoteAddr),
			zap.String("session", r.Header.Get("X-Session-ID")),
			zap.String("auth", r.Header.Get("Proxy-Authorization")),
		)
		atomic.AddUint64(&xl.RequestCount, 1)

		target := r.Header.Get("X-Target")
		network := r.Header.Get("X-Network")
		sessionID := r.Header.Get("X-Session-ID")

		if sessionID == "" {
			logger.Warn("❌ [HTTP] 拒绝请求: 缺少 Session ID", zap.String("remote", r.RemoteAddr))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if xl.expectedToken != "" && r.Header.Get("Proxy-Authorization") != "Bearer "+xl.expectedToken {
			logger.Warn("❌ [HTTP] 拒绝请求: 密码错误或未授权",
				zap.String("remote", r.RemoteAddr),
				zap.String("got_token", r.Header.Get("Proxy-Authorization")),
				zap.String("expected", "Bearer "+xl.expectedToken),
			)
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

		// 1. 处理上行请求 (包含 Seq 和 Ack)
		cSeq, _ := strconv.ParseUint(r.Header.Get("X-Seq"), 10, 64)
		cAck, _ := strconv.ParseUint(r.Header.Get("X-Ack"), 10, 64)

		upBuf := bytesBufPool.Get().(*bytes.Buffer)
		upBuf.Reset()
		_, errBody := upBuf.ReadFrom(r.Body)
		upData := upBuf.Bytes()
		r.Body.Close()

		// 如果读取 Body 报错（如 Nginx 提前切断），绝不能把残缺数据送进状态机！
		if errBody != nil {
			logger.Warn("⚠️ [HTTP] 读取上行 Body 失败或不完整，丢弃该包", zap.Error(errBody))
			bytesBufPool.Put(upBuf)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return // 直接退出，客户端会超时并触发 Go-Back-N 完美重传
		}

		// 写入数据并获取服务端的确认号 (我的期望读指针)
		myUpAck := vConn.PutReadData(cSeq, upData)

		logger.Debug("📥 [HTTP] 解析上行请求",
			zap.String("session", sessionID),
			zap.Uint64("Client_Seq", cSeq),
			zap.Uint64("Client_Ack", cAck),
			zap.Int("Up_Bytes", len(upData)),
			zap.Uint64("Server_Expect_Ack", myUpAck),
		)

		// 归还pool
		bytesBufPool.Put(upBuf)

		// 2. 准备下行数据
		// 只有当接收到有效心跳或数据时，才进行延迟回包优化
		var downData []byte
		var myDownSeq uint64
		var downBufPtr *[]byte

		// 定义闭包：安全地加锁切取下行数据，并推进服务端的派发游标
		fetchDownData := func() bool {
			vConn.downWindowMu.Lock()
			defer vConn.downWindowMu.Unlock()

			// 同步客户端状态：如果客户端带来的 Ack 大于服务端的派发游标，说明发生了重连跳变，强制对齐
			// 另外，如果你在客户端超时重传时加了特殊 Header (如 X-Retry: 1)，也可以在这里把 downDispatchSeq 强行回退到 cAck 触发服务端 Go-Back-N
			if vConn.downDispatchSeq < cAck || r.Header.Get("X-Retry") == "1" {
				vConn.downDispatchSeq = cAck
			}

			// 切取本次请求负责运送的数据 (传入 cAck 清理内存，传入 downDispatchSeq 获取新任务)
			downData, myDownSeq, downBufPtr = vConn.writeBuf.GetSlice(cAck, vConn.downDispatchSeq, maxsendBufSize)

			// 必须使用 myDownSeq 来绝对赋值，绝不能用 +=
			if len(downData) > 0 {
				vConn.downDispatchSeq = myDownSeq + uint64(len(downData))
				return true
			}

			vConn.downDispatchSeq = myDownSeq
			return false
		}

		if len(upData) > 0 {
			// 如果客户端带来了上行数据，我们就顺便尝试带一点下行数据回去
			fetchDownData()
		} else {
			// 如果是客户端的空载心跳/拉取请求，触发长轮询等待下行数据
			startWait := time.Now()
			for {
				if fetchDownData() || time.Since(startWait) > 2*time.Second || vConn.closed {
					break
				}
				time.Sleep(20 * time.Millisecond)
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
		w.WriteHeader(http.StatusOK)
		if len(downData) > 0 {
			w.Write(downData)
		}

		// 归还pool
		if downBufPtr != nil {
			sendBuf.Put(downBufPtr)
		}
	})

	server := &http.Server{IdleTimeout: 1 * time.Hour}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		logger.Info("🛑 正在优雅关闭 HTTP 服务器...")
		server.Shutdown(shutdownCtx)
	}()

	if certFile != "" && keyFile != "" {
		// TLS 情况：启动 TCP(TLS) 服务并同时尝试启动 HTTP/3 (QUIC) UDP 服务
		server.Handler = mux

		// TCP/TLS HTTP server （支持 h2）
		go func() {
			logger.Info("🔐 [Server] 启动 TCP(TLS) HTTP 服务器", zap.String("addr", listenAddr))
			if err := server.ServeTLS(ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Fatal("TLS 异常退出", zap.Error(err))
			}
		}()

		// HTTP/3 (QUIC) server
		go func() {
			logger.Info("🔐 [Server] 尝试启动 HTTP/3 (QUIC) 服务器", zap.String("addr", listenAddr))
			h3Server := &http3.Server{
				Addr:    listenAddr,
				Handler: mux,
			}
			go func() {
				<-ctx.Done()
				h3Server.Close() // 退出时关闭 UDP监听
			}()
			if err := h3Server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP/3 异常退出", zap.Error(err))
			}
		}()

	} else {
		// 非 TLS 情况：保留原来的 h2c（明文 HTTP/2 over TCP）行为
		server.Handler = h2c.NewHandler(mux, &http2.Server{IdleTimeout: 1 * time.Hour})
		go func() {
			logger.Info("🚀 [Server] 启动明文 HTTP (h2c) 服务器", zap.String("addr", listenAddr))
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				logger.Fatal("H2C 异常退出", zap.Error(err))
			}
		}()
	}
	return xl, nil
}

// generateSelfSignedCert 生成一个有效期为 10 年的自签名证书并保存到指定路径
func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: mbig.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"xhttptunnel-selfsigned"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10), // 10 年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// 写入证书文件
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	// 写入私钥文件
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}

	return nil
}

// ==========================================
// 7. 主逻辑与路由
// ==========================================

func main() {
	mode := flag.String("mode", "", "client or server")
	listen := flag.String("listen", "127.0.0.1:1080 (Server) tcp://127.0.0.1:1080 (Client)", "Listen addr")
	serverURLFlag := flag.String("server", "https://abc.com/stream", "Server URL")
	forward := flag.String("forward", "8.8.8.8:53", "Forward target")
	defaultTarget := flag.String("default-target", "tcp://127.0.0.1:80", "Default target")
	psk := flag.String("psk", "my-secret-token", "PSK")
	sniFlag := flag.String("sni", "www.bing.com", "Custom TLS SNI")
	path := flag.String("path", "/stream", "Custom Path (Server Only)")
	hostFlag := flag.String("host", "www.bing.com", "Custom HTTP Host header")
	alpnFlag := flag.String("alpn", "auto", "Force ALPN protocol (h3/h2/h1/auto)")
	certFlag := flag.String("cert", "", "TLS Cert")
	keyFlag := flag.String("key", "", "TLS Key")
	logLevelFlag := flag.String("loglevel", "debug", "Log level") // 增强默认为 debug
	dumpFlag := flag.Bool("dump", false, "Dump Hex")
	selfSignFlag := flag.Bool("selfsign", false, "Auto generate self-signed certificate (Server only)")
	flag.Parse()

	initLogger(*logLevelFlag)
	defer logger.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *mode == "client" {
		runClient(ctx, *listen, *serverURLFlag, *forward, *psk, *sniFlag, *hostFlag, *alpnFlag, *dumpFlag)
	} else if *mode == "server" {
		cert, key := *certFlag, *keyFlag
		if *selfSignFlag && (cert == "" && key == "") {
			cert = "cert.pem"
			key = "key.pem"
			// 检查文件是否已存在，不存在则生成
			if _, err := os.Stat(cert); os.IsNotExist(err) {
				if err := generateSelfSignedCert(cert, key); err != nil {
					logger.Fatal("❌ 自动生成自签名证书失败", zap.Error(err))
				}
				logger.Info("I 已自动生成自签名证书", zap.String("cert", cert), zap.String("key", key))
			}
			*certFlag = cert
			*keyFlag = key
		}
		runServer(ctx, *listen, *path, *defaultTarget, *psk, *certFlag, *keyFlag, *dumpFlag)
	} else {
		logger.Fatal("请指定模式: -mode client 或 -mode server")
	}
}

func runClient(ctx context.Context, listenStr, serverURLStr, forwardTarget, psk, customSNI, customHost, alpn string, dump bool) {
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
	logger.Debug("🔧 客户端配置初始化", zap.String("SNI", cfg.SNI), zap.String("Host", cfg.Host), zap.String("Target", forwardTarget), zap.String("ALPN", cfg.ALPN))

	if u.Scheme == "tcp" {
		ln, err := net.Listen("tcp", u.Host)
		if err != nil {
			logger.Fatal("TCP监听失败", zap.Error(err))
		}
		logger.Info("🚀 Client 启动成功", zap.String("addr", u.Host), zap.String("ALPN", alpn))
		//监听退出信号，打断 ln.Accept()
		go func() {
			<-ctx.Done()
			logger.Info("🛑 收到退出信号，正在关闭客户端 TCP 监听...")
			ln.Close()
		}()

		for {
			conn, err := ln.Accept()
			if err != nil {
				// 区分是优雅退出导致的错误，还是真实的报错
				if ctx.Err() != nil {
					return
				}

				logger.Error("❌ Accept 接收本地连接失败", zap.Error(err))
				continue
			}

			go func() {
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

				// 上行：Local Client -> XHTTP Server
				go func() {
					n, err := io.Copy(xc, clientConn)
					if err != nil && err != io.EOF {
						logger.Debug("⚠️ [TCP] 上行转发 (Local->Server) 异常结束", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
					} else {
						logger.Debug("🛑 [TCP] 上行转发 (Local->Server) 正常结束", zap.String("id", connID), zap.Int64("bytes", n))
					}

					if xfc, ok := xc.(*xhttpFramedConn); ok {
						xfc.WriteCloseFrame()
					}
					clientConn.Close()
				}()

				// 下行：XHTTP Server -> Local Client
				n, err := io.Copy(clientConn, xc)
				if err != nil && err != io.EOF {
					logger.Debug("⚠️ [TCP] 下行转发 (Server->Local) 异常结束", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
				} else {
					logger.Debug("🛑 [TCP] 下行转发 (Server->Local) 正常结束", zap.String("id", connID), zap.Int64("bytes", n))
				}
				logger.Debug("💀 [TCP] 本地会话清理完毕", zap.String("id", connID))
			}()
		}
	} else if u.Scheme == "udp" {
		pc, err := net.ListenPacket("udp", u.Host)
		if err != nil {
			logger.Fatal("UDP监听失败", zap.Error(err))
		}
		logger.Info("🚀 Client(UDP) 启动成功", zap.String("addr", u.Host))
		//监听退出信号，打断 pc.ReadFrom()
		go func() {
			<-ctx.Done()
			logger.Info("🛑 收到退出信号，正在关闭客户端 UDP 监听...")
			pc.Close()
		}()

		sessionMap := make(map[string]net.Conn)
		var mu sync.Mutex
		buf := make([]byte, 65535)

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
			xc, exists := sessionMap[cAddr.String()]
			if !exists {
				connID := generateRandomHex(4)
				logger.Debug("🔌 [UDP] 发现新本地客户端，准备建立隧道", zap.String("id", connID), zap.String("client", cAddr.String()))

				xc, err = DialXHTTP(ctx, serverURL, cfg, forwardTarget, "udp")
				if err != nil {
					logger.Error("❌ [UDP] XHTTP 隧道拨号失败", zap.String("id", connID), zap.Error(err))
					mu.Unlock()
					continue
				}
				logger.Debug("✅ [UDP] XHTTP 隧道拨号成功", zap.String("id", connID))

				sessionMap[cAddr.String()] = xc

				// 下行：XHTTP Server -> Local Client (UDP)
				go func(addr net.Addr, conn net.Conn, id string) {
					defer conn.Close()
					defer func() {
						mu.Lock()
						delete(sessionMap, addr.String())
						mu.Unlock()
						logger.Debug("💀 [UDP] 本地会话清理完毕", zap.String("id", id), zap.String("client", addr.String()))
					}()

					dBuf := make([]byte, 65535)
					for {
						l, err := readUDPFrameInto(conn, dBuf)
						if err != nil {
							if err != io.EOF && !strings.Contains(err.Error(), "closed network connection") {
								logger.Debug("⚠️ [UDP] 下行读取 Frame 失败", zap.String("id", id), zap.Error(err))
							} else {
								logger.Debug("🛑 [UDP] 下行监听结束 (EOF/Closed)", zap.String("id", id))
							}
							return
						}
						// logger.Debug("🔽 [UDP] 转发下行数据", zap.String("id", id), zap.Int("bytes", l))
						pc.WriteTo(dBuf[:l], addr)
					}
				}(cAddr, xc, connID)
			}
			mu.Unlock()

			// 上行：Local Client -> XHTTP Server (UDP)
			// logger.Debug("🔼 [UDP] 转发上行数据", zap.String("client", cAddr.String()), zap.Int("bytes", n))
			if err := writeUDPFrame(xc, buf[:n]); err != nil {
				logger.Debug("⚠️ [UDP] 写入上行 Frame 失败", zap.String("client", cAddr.String()), zap.Error(err))
			}
		}
	}
}

func runServer(ctx context.Context, listenAddr, path, defaultTargetStr, psk, certFile, keyFile string, dump bool) {
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

	xl, err := ListenXHTTP(ctx, host, path, psk, certFile, keyFile)
	if err != nil {
		logger.Fatal("Server 监听失败", zap.Error(err))
	}
	logger.Info("🚀 Server 启动成功", zap.String("listen", host))
	//监听全局退出，关闭虚拟 Listener
	go func() {
		<-ctx.Done()
		logger.Info("🛑 收到退出信号，停止接收新会话...")
		xl.Close()
	}()

	for {
		conn, err := xl.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.Info("✅ 主服务已安全退出")
				return
			}

			logger.Error("❌ Accept 接收连接失败", zap.Error(err))
			continue
		}
		if xc, ok := conn.(*xhttpFramedConn); ok {
			logger.Debug("📥 [Accept] 成功接收底层虚拟连接",
				zap.String("client_addr", xc.RemoteAddr().String()),
				zap.String("local_addr", xc.LocalAddr().String()),
				zap.String("req_target", xc.targetAddr),
				zap.String("req_network", xc.network),
			)
		} else {
			// 兜底逻辑，防范未知类型的 Conn
			logger.Debug("📥 [Accept] 成功接收连接 (未知底层类型)",
				zap.String("client_addr", conn.RemoteAddr().String()),
			)
		}

		go func(xc *xhttpFramedConn) {
			defer xc.Close()

			// 为了日志追踪，生成一个简单的短 ID
			connID := generateRandomHex(4)
			logger.Debug("🔌 接收到新客户端请求", zap.String("id", connID), zap.String("remote", xc.RemoteAddr().String()))

			target, network := xc.targetAddr, xc.network
			if target == "" {
				target = defURL.Host
			}
			if network == "" {
				network = defURL.Scheme
			}

			logger.Debug("🎯 解析目标路由", zap.String("id", connID), zap.String("network", network), zap.String("target", target))

			if network == "tcp" {
				logger.Debug("⏳ 正在拨号 TCP 目标服务...", zap.String("id", connID), zap.String("target", target))
				rc, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					logger.Error("❌ 无法连接 TCP 目标服务", zap.String("id", connID), zap.String("target", target), zap.Error(err))
					xc.WriteCloseFrame()
					return
				}
				defer rc.Close()
				logger.Debug("✅ TCP 目标服务连接成功", zap.String("id", connID), zap.String("target", target))

				var targetConn net.Conn = rc
				if dump {
					targetConn = &DumpConn{Conn: rc, Prefix: "Server Target - " + connID}
				}

				// 上行：Client -> Target
				go func() {
					n, err := io.Copy(targetConn, xc)
					if err != nil && err != io.EOF {
						logger.Debug("⚠️ TCP 上行 (Client->Target) 异常结束", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
					} else {
						logger.Debug("🛑 TCP 上行 (Client->Target) 正常结束", zap.String("id", connID), zap.Int64("bytes", n))
					}

					if c, ok := targetConn.(interface{ CloseWrite() error }); ok {
						c.CloseWrite()
					} else {
						targetConn.Close()
					}
				}()

				// 下行：Target -> Client
				n, err := io.Copy(xc, targetConn)
				if err != nil && err != io.EOF {
					logger.Debug("⚠️ TCP 下行 (Target->Client) 异常结束", zap.String("id", connID), zap.Int64("bytes", n), zap.Error(err))
				} else {
					logger.Debug("🛑 TCP 下行 (Target->Client) 正常结束", zap.String("id", connID), zap.Int64("bytes", n))
				}
				xc.WriteCloseFrame()
				logger.Debug("💀 TCP 会话清理完毕", zap.String("id", connID))

			} else if network == "udp" {
				logger.Debug("⏳ 正在拨号 UDP 目标服务...", zap.String("id", connID), zap.String("target", target))
				rc, err := net.DialTimeout("udp", target, 5*time.Second)
				if err != nil {
					logger.Error("❌ 无法连接 UDP 目标服务", zap.String("id", connID), zap.String("target", target), zap.Error(err))
					return
				}
				defer rc.Close()
				logger.Debug("✅ UDP 目标服务连接成功", zap.String("id", connID), zap.String("target", target))

				// 上行：Client -> Target (UDP)
				go func() {
					uBuf := make([]byte, 65535)
					for {
						n, err := readUDPFrameInto(xc, uBuf)
						if err != nil {
							if err != io.EOF {
								logger.Debug("⚠️ UDP 上行读取 Frame 失败", zap.String("id", connID), zap.Error(err))
							} else {
								logger.Debug("🛑 UDP 上行读取 Frame 结束 (EOF)", zap.String("id", connID))
							}
							return
						}
						// logger.Debug("🔼 转发 UDP 上行数据", zap.String("id", connID), zap.Int("bytes", n)) // 流量大时可注释掉
						rc.Write(uBuf[:n])
					}
				}()

				// 下行：Target -> Client (UDP)
				dBuf := make([]byte, 65535)
				for {
					n, err := rc.Read(dBuf)
					if err != nil {
						if strings.Contains(err.Error(), "use of closed network connection") {
							logger.Debug("🛑 UDP 下行监听结束 (连接已关闭)", zap.String("id", connID))
						} else {
							logger.Debug("⚠️ UDP 下行读取目标数据失败", zap.String("id", connID), zap.Error(err))
						}
						return
					}
					// logger.Debug("🔽 转发 UDP 下行数据", zap.String("id", connID), zap.Int("bytes", n)) // 流量大时可注释掉
					writeUDPFrame(xc, dBuf[:n])
				}
			} else {
				logger.Warn("⚠️ 未知的网络类型", zap.String("id", connID), zap.String("network", network))
			}
		}(conn.(*xhttpFramedConn))
	}
}
