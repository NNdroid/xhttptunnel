package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	maxsendBufSize = 900 * 1000
	maxframeSize   = 990 * 1000

	// sendBuf: 适配 GetSlice 的最大请求量 (Server 端请求 900K)
	sendBuf = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 990*1000)
			return &b
		},
	}
	// bytesBufPool: 用于替代高频且昂贵的 io.ReadAll
	bytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

func safelyPutSendBuf(bufPtr *[]byte) {
	if bufPtr != nil && cap(*bufPtr) >= maxsendBufSize {
		sendBuf.Put(bufPtr)
	}
}

// ==========================================
// 高性能可靠传输环形缓冲区 (Ring Buffer + Seq/Ack)
// ==========================================

type reliableBuffer struct {
	mu         sync.Mutex
	cond       *sync.Cond
	buf        []byte // 预先分配的固定大小数组，永不扩容
	head       int    // 写入游标
	tail       int    // 读取/清理游标
	count      int    // 缓冲区内目前的有效数据长度
	baseOffset uint64 // tail 所对应的绝对网络序号 (Seq)
	maxSize    int
	closed     bool
}

func newReliableBuffer(maxSize int) *reliableBuffer {
	rb := &reliableBuffer{
		maxSize: maxSize,
		buf:     make([]byte, maxSize),
	}
	rb.cond = sync.NewCond(&rb.mu)
	return rb
}

func (rb *reliableBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	written := 0
	pLen := len(p)

	// 如果数据大于可用空间，分批阻塞写入 (Backpressure)
	for written < pLen {
		for rb.count >= rb.maxSize && !rb.closed {
			rb.cond.Wait()
		}
		if rb.closed {
			return written, io.ErrClosedPipe
		}

		avail := rb.maxSize - rb.count
		toWrite := pLen - written
		if toWrite > avail {
			toWrite = avail
		}

		firstPart := rb.maxSize - rb.head
		if toWrite <= firstPart {
			copy(rb.buf[rb.head:], p[written:written+toWrite])
			rb.head = (rb.head + toWrite) % rb.maxSize
		} else {
			copy(rb.buf[rb.head:], p[written:written+firstPart])
			copy(rb.buf[0:], p[written+firstPart:written+toWrite])
			rb.head = toWrite - firstPart
		}

		rb.count += toWrite
		written += toWrite
	}

	if written > 0 {
		rb.cond.Broadcast()
	}

	return written, nil
}

// GetSlice 获取从指定偏移量开始的数据，并清理掉已被对端确认 (Ack) 的旧数据
func (rb *reliableBuffer) GetSlice(remoteAck uint64, dispatchSeq uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// 清理对端已经确认收到的数据 (推进 tail 游标)
	freed := false
	if remoteAck > rb.baseOffset {
		skip := int(remoteAck - rb.baseOffset)
		if skip > rb.count {
			skip = rb.count
		}
		if skip > 0 {
			rb.tail = (rb.tail + skip) % rb.maxSize
			rb.count -= skip
			rb.baseOffset += uint64(skip)
			freed = true
		}
	}

	if freed {
		rb.cond.Broadcast()
	}

	if dispatchSeq < rb.baseOffset {
		dispatchSeq = rb.baseOffset
	}

	offsetInBuf := int(dispatchSeq - rb.baseOffset)
	if offsetInBuf >= rb.count {
		return nil, dispatchSeq, nil
	}

	availLen := rb.count - offsetInBuf
	length := availLen
	if length > maxLen {
		length = maxLen
	}

	bufPtr := sendBuf.Get().(*[]byte)
	if cap(*bufPtr) < length {
		newBuf := make([]byte, length)
		bufPtr = &newBuf
	}
	res := (*bufPtr)[:length]

	startIdx := (rb.tail + offsetInBuf) % rb.maxSize
	firstPart := rb.maxSize - startIdx

	if length <= firstPart {
		copy(res, rb.buf[startIdx:startIdx+length])
	} else {
		copy(res[:firstPart], rb.buf[startIdx:startIdx+firstPart])
		copy(res[firstPart:], rb.buf[0:length-firstPart])
	}

	return res, dispatchSeq, bufPtr
}

func (rb *reliableBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}

func (rb *reliableBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.closed = true
	rb.cond.Broadcast()
}

// ==========================================
// Meek 虚拟连接 (集成可靠传输与滑动窗口)
// ==========================================

type meekVirtualConn struct {
	sessionID string
	local     net.Addr
	remote    net.Addr

	readCond    *sync.Cond
	readBuf     bytes.Buffer
	nextReadSeq uint64            // 我方期待收到的下一个 Seq
	oooBuf      map[uint64][]byte // 乱序缓存

	writeBuf *reliableBuffer

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
		writeBuf:   newReliableBuffer(4 * 1024 * 1024), // 最大 4MB 缓存
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
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.writeBuf.Write(p)
}

// PutReadData 乱序重组
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	if c.closed {
		return c.nextReadSeq
	}

	if len(data) > 0 {
		if seq == c.nextReadSeq {
			c.readBuf.Write(data)
			c.nextReadSeq += uint64(len(data))

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
			if len(c.oooBuf) < 1024 {
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
	c.oooBuf = nil
	c.readCond.Broadcast()
	c.readCond.L.Unlock()

	if c.writeBuf != nil {
		c.writeBuf.Close()
	}
	return nil
}

func (c *meekVirtualConn) LocalAddr() net.Addr                { return c.local }
func (c *meekVirtualConn) RemoteAddr() net.Addr               { return c.remote }
func (c *meekVirtualConn) SetDeadline(t time.Time) error      { return nil }
func (c *meekVirtualConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *meekVirtualConn) SetWriteDeadline(t time.Time) error { return nil }
