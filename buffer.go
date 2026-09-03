package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	// defaultChunkSize is the largest upstream payload carried by a single
	// poll request. It is deliberately well below the 1MB default of
	// nginx's client_max_body_size so tunnels survive CDNs and WAFs that
	// cap request bodies at 1MB. Raise it only if the whole path is known
	// to allow bigger bodies.
	defaultChunkSize = 256 * 1000
	// framePaddingBudget is headroom added on top of a chunk so that a frame
	// header plus random padding always fits into the wire buffer.
	framePaddingBudget = 90 * 1000

	// maxOutOfOrderChunks bounds the number of slots in the out-of-order
	// reassembly cache. When it is full the producer blocks (see
	// waitForOutOfOrderRoom) instead of dropping the chunk: the peer hands
	// bytes out from its dispatch cursor, which has already moved past a
	// dropped chunk, so nothing would ever resend it — dropping silently
	// corrupts the stream.
	maxOutOfOrderChunks = 1024

	// maxReassemblyBytes caps how much in-order payload may sit in the
	// reassembly buffer waiting for the local reader. Without a cap a peer
	// whose target has stalled can grow it without limit — one slow session
	// was enough to take the whole process down.
	maxReassemblyBytes = 4 * 1024 * 1024

	// maxOutOfOrderBytes caps the total size of the out-of-order cache.
	// Counting chunks alone is not a bound: a single chunk can be hundreds
	// of KB, so 1024 of them would be ~350MB per session.
	maxOutOfOrderBytes = 4 * 1024 * 1024
)

var (
	maxsendBufSize = defaultChunkSize
	maxframeSize   = defaultChunkSize + framePaddingBudget

	// sendBuf: sized to fit GetSlice's max request length
	sendBuf = sync.Pool{
		New: func() interface{} {
			b := make([]byte, maxframeSize)
			return &b
		},
	}
	// bytesBufPool: replaces the frequent and expensive io.ReadAll
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
// High-performance reliable-transfer ring buffer (Ring Buffer + Seq/Ack)
// ==========================================

type reliableBuffer struct {
	mu         sync.Mutex
	cond       *sync.Cond
	buf        []byte // pre-allocated fixed-size array, never grows
	head       int    // write cursor
	tail       int    // read/cleanup cursor
	count      int    // current number of valid bytes in the buffer
	baseOffset uint64 // absolute network sequence number (Seq) that tail maps to
	maxSize    int
	closed     bool
}

func newReliableBuffer(maxSize int) *reliableBuffer {
	rb := &reliableBuffer{
		maxSize: maxSize,
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
	// Most sessions spend their lifetime waiting on a long poll. Allocate the
	// backing ring only for sessions that actually upload data; eagerly
	// reserving this multi-megabyte buffer for every admitted session makes a
	// high-concurrency CDN deployment run out of memory while idle.
	if rb.buf == nil {
		rb.buf = make([]byte, rb.maxSize)
	}

	written := 0
	pLen := len(p)

	// If the data exceeds the available space, write in blocking batches (backpressure)
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

// GetSlice returns data starting at the given offset and discards old data
// already acknowledged (Ack) by the peer.
func (rb *reliableBuffer) GetSlice(remoteAck uint64, dispatchSeq uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Discard data the peer has already acknowledged (advance the tail cursor)
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

// undispatched reports how many buffered bytes have not been handed out by
// GetSlice yet. GetSlice moves the dispatch cursor independently of the Ack
// cursor, so Len() alone cannot tell whether the peer has been given
// everything we hold.
func (rb *reliableBuffer) undispatched(dispatchSeq uint64) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if dispatchSeq < rb.baseOffset {
		dispatchSeq = rb.baseOffset
	}
	offset := int(dispatchSeq - rb.baseOffset)
	if offset >= rb.count {
		return 0
	}
	return rb.count - offset
}

// broadcast wakes every goroutine parked on the condition variable. Callers
// that do not already hold rb.mu must use this instead of touching cond
// directly, otherwise a waiter sitting between its predicate check and Wait()
// can miss the signal.
func (rb *reliableBuffer) broadcast() {
	rb.mu.Lock()
	rb.cond.Broadcast()
	rb.mu.Unlock()
}

// wait parks the caller until something broadcasts (typically new data being
// written or a close). The caller MUST re-check its predicate afterwards — a
// spurious wakeup is always possible. Encapsulates the lock+Wait so callers
// never touch rb.cond directly.
func (rb *reliableBuffer) wait() {
	rb.mu.Lock()
	rb.cond.Wait()
	rb.mu.Unlock()
}

// waitLongPoll parks the caller until the buffer is non-empty, the context is
// cancelled, or the timeout elapses. The caller MUST re-run its fetch logic
// after this returns (a wakeup does not guarantee data is available). This
// centralises the cond + timer + context wakeup dance so callers never have to
// touch rb.cond or rb.mu directly, which previously invited the same
// lost-wakeup class of bug that broadcast() was introduced to prevent.
func (rb *reliableBuffer) waitLongPoll(ctx context.Context, timeout time.Duration) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.count != 0 {
		return
	}
	stopCtx := context.AfterFunc(ctx, func() { rb.broadcast() })
	timer := time.AfterFunc(timeout, func() { rb.broadcast() })
	rb.cond.Wait()
	timer.Stop()
	stopCtx()
}

func (rb *reliableBuffer) Close() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.closed = true
	rb.cond.Broadcast()
}

// ==========================================
// Meek virtual connection (reliable transfer + sliding window integrated)
// ==========================================

type meekVirtualConn struct {
	sessionID string
	local     net.Addr
	remote    net.Addr

	readCond    *sync.Cond
	readBuf     bytes.Buffer
	nextReadSeq uint64            // next Seq we expect to receive
	oooBuf      map[uint64][]byte // out-of-order cache
	oooBytes    int               // total bytes held by oooBuf

	writeBuf *reliableBuffer

	closedFlag      atomic.Bool // set once Close() wins; safe to read without the lock
	closeRequested  atomic.Bool // graceful stop: ship what is queued, then exit
	lastActive      int64
	downDispatchSeq uint64     // server->client dispatch cursor
	downWindowMu    sync.Mutex // guards concurrent access to the dispatch cursor
}

func newMeekVirtualConn(sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		sessionID:  sessionID,
		local:      local,
		remote:     remote,
		readCond:   sync.NewCond(&sync.Mutex{}),
		writeBuf:   newReliableBuffer(4 * 1024 * 1024), // 4MB max buffer
		lastActive: time.Now().Unix(),
		oooBuf:     make(map[uint64][]byte),
	}
}

func (c *meekVirtualConn) Read(p []byte) (int, error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	for c.readBuf.Len() == 0 && !c.isClosed() {
		c.readCond.Wait()
	}
	if c.isClosed() && c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	n, err := c.readBuf.Read(p)
	// Wake any producer parked on backpressure in PutReadData.
	if n > 0 {
		c.readCond.Broadcast()
	}
	return n, err
}

func (c *meekVirtualConn) isClosed() bool { return c.closedFlag.Load() }

// requestClose asks the polling goroutines to hand over whatever is still
// queued — most importantly an EOF/close frame — and then stop. Resources are
// not released here; Close() still has to run once the pump has exited.
func (c *meekVirtualConn) requestClose() {
	if c.closeRequested.CompareAndSwap(false, true) {
		c.writeBuf.broadcast()
	}
}

func (c *meekVirtualConn) closePending() bool { return c.closeRequested.Load() }

// waitDrained blocks until every buffered downlink byte has been handed to the
// peer, or the timeout expires. The server uses it before dropping a session so
// the final close frame is not lost to a request that never got sent.
func (c *meekVirtualConn) waitDrained(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		c.downWindowMu.Lock()
		pending := c.writeBuf.undispatched(c.downDispatchSeq)
		c.downWindowMu.Unlock()
		if pending == 0 || c.isClosed() {
			return
		}
		if !time.Now().Before(deadline) {
			logger.Warn("[Session] downlink drain timed out, closing with data still queued", zap.String("session", c.sessionID))
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (c *meekVirtualConn) Write(p []byte) (int, error) {
	if c.isClosed() {
		return 0, io.ErrClosedPipe
	}
	return c.writeBuf.Write(p)
}

// PutReadData reorders out-of-order data and returns the cumulative Ack: the
// next sequence number the peer must send from.
//
// Both buffers it touches are bounded, and hitting a bound blocks the producer
// instead of dropping the chunk. Dropping looks cheaper but silently corrupts
// the stream: the sender hands out bytes from its dispatch cursor, which has
// already moved past a dropped chunk, so nothing would ever resend it. Parking
// the producer instead pushes the backpressure all the way out to the local
// socket, which is what a real transport does.
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	if c.isClosed() || len(data) == 0 {
		return c.nextReadSeq
	}

	// The dispatch below is a loop, not a one-shot branch. A chunk that arrives
	// ahead of the read cursor can become contiguous — or already delivered —
	// while it sits parked waiting for room in the out-of-order cache. Filing
	// it blind strands it there forever: drainContiguous only ever looks at
	// oooBuf[nextReadSeq], so a chunk filed at a seq the cursor has already
	// passed is never drained, and its bytes are silently lost.
	waited := false
	for {
		switch {
		case seq < c.nextReadSeq:
			// Stale retransmission: these bytes are already in readBuf.
			return c.nextReadSeq

		case seq == c.nextReadSeq:
			c.waitForReassemblyRoom(len(data))
			if c.isClosed() {
				return c.nextReadSeq
			}
			c.readBuf.Write(data)
			c.nextReadSeq += uint64(len(data))
			c.drainContiguous()
			c.readCond.Broadcast()
			return c.nextReadSeq

		default: // seq > nextReadSeq: genuinely ahead of the read cursor.
			if _, dup := c.oooBuf[seq]; dup {
				return c.nextReadSeq
			}
			// waitForOutOfOrderRoom returns immediately once there is room, so
			// without this guard the loop would spin forever. One wait is
			// enough: if the gap was filled meanwhile, the next iteration
			// re-dispatches this chunk down the contiguous path above.
			if waited {
				dataCopy := make([]byte, len(data))
				copy(dataCopy, data)
				c.oooBuf[seq] = dataCopy
				c.oooBytes += len(dataCopy)
				return c.nextReadSeq
			}
			c.waitForOutOfOrderRoom(len(data))
			if c.isClosed() {
				return c.nextReadSeq
			}
			waited = true
		}
	}
}

// drainContiguous flushes every cached chunk that now sits immediately after
// the read cursor. Caller must hold readCond.L.
func (c *meekVirtualConn) drainContiguous() {
	for {
		nextData, ok := c.oooBuf[c.nextReadSeq]
		if !ok {
			return
		}
		c.waitForReassemblyRoom(len(nextData))
		if c.isClosed() {
			return
		}
		delete(c.oooBuf, c.nextReadSeq)
		c.oooBytes -= len(nextData)
		c.readBuf.Write(nextData)
		c.nextReadSeq += uint64(len(nextData))
	}
}

// waitForReassemblyRoom parks until the reassembly buffer can take n more
// bytes. Caller must hold readCond.L; it is released while waiting.
func (c *meekVirtualConn) waitForReassemblyRoom(n int) {
	if c.readBuf.Len()+n <= maxReassemblyBytes {
		return
	}
	logger.Debug("[Buffer] 重组缓冲已满，对上游施加背压",
		zap.String("session", c.sessionID),
		zap.Int("buffered", c.readBuf.Len()),
		zap.Int("incoming", n),
	)
	for c.readBuf.Len()+n > maxReassemblyBytes && !c.isClosed() {
		c.readCond.Wait()
	}
}

// waitForOutOfOrderRoom parks until the out-of-order cache can take another n
// bytes. Caller must hold readCond.L; it is released while waiting.
func (c *meekVirtualConn) waitForOutOfOrderRoom(n int) {
	if len(c.oooBuf) < maxOutOfOrderChunks && c.oooBytes+n <= maxOutOfOrderBytes {
		return
	}
	logger.Debug("[Buffer] 乱序缓存已满，对上游施加背压",
		zap.String("session", c.sessionID),
		zap.Int("chunks", len(c.oooBuf)),
		zap.Int("bytes", c.oooBytes),
	)
	for (len(c.oooBuf) >= maxOutOfOrderChunks || c.oooBytes+n > maxOutOfOrderBytes) && !c.isClosed() {
		c.readCond.Wait()
	}
}

func (c *meekVirtualConn) updateActive() {
	atomic.StoreInt64(&c.lastActive, time.Now().Unix())
}

func (c *meekVirtualConn) Close() error {
	if !c.closedFlag.CompareAndSwap(false, true) {
		return nil
	}
	c.readCond.L.Lock()
	c.oooBuf = nil
	c.oooBytes = 0
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
