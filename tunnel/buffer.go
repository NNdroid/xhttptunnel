package tunnel

import (
	"bytes"
	"context"
	"fmt"
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
	// maxsendBufSize is configured once during normal startup, but tests and
	// embedders may reconfigure it while HTTP transports are still returning
	// pooled request bodies. Keep the hot-path read lock-free and race-free.
	maxsendBufSize atomic.Int64

	// sendBuf: sized to fit GetSlice's max request length
	sendBuf = sync.Pool{
		New: func() interface{} {
			b := make([]byte, currentMaxFrameSize())
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

func init() {
	maxsendBufSize.Store(defaultChunkSize)
}

func currentMaxSendBufSize() int {
	return int(maxsendBufSize.Load())
}

func currentMaxFrameSize() int {
	return currentMaxSendBufSize() + framePaddingBudget
}

func safelyPutSendBuf(bufPtr *[]byte) {
	if bufPtr != nil && cap(*bufPtr) >= currentMaxSendBufSize() {
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
	if remoteAck > rb.baseOffset && remoteAck-rb.baseOffset <= uint64(rb.count) {
		skip := int(remoteAck - rb.baseOffset)
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

	delta := dispatchSeq - rb.baseOffset
	if delta >= uint64(rb.count) || maxLen <= 0 {
		return nil, dispatchSeq, nil
	}
	offsetInBuf := int(delta)

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

func (rb *reliableBuffer) validAck(ack uint64) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	// Subtract only after the lower bound check so an attacker-controlled
	// acknowledgement cannot wrap around and appear to be in range.
	return ack <= rb.baseOffset || ack-rb.baseOffset <= uint64(rb.count)
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
	delta := dispatchSeq - rb.baseOffset
	if delta >= uint64(rb.count) {
		return 0
	}
	return rb.count - int(delta)
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
	if rb.count != 0 || rb.closed || ctx.Err() != nil {
		return
	}
	stopCtx := context.AfterFunc(ctx, func() { rb.broadcast() })
	timer := time.AfterFunc(timeout, func() { rb.broadcast() })
	rb.cond.Wait()
	timer.Stop()
	stopCtx()
}

// waitDispatchable parks the caller until bytes exist beyond the given
// dispatch cursor (i.e. the peer has NOT yet been sent everything buffered),
// the context is cancelled, or the timeout elapses. Unlike waitLongPoll, data
// that is buffered-but-already-dispatched (sitting in flight, awaiting the
// peer's ack) does NOT wake the caller — that state drains via acks, and
// waking on it would busy-loop a streaming writer.
func (rb *reliableBuffer) waitDispatchable(ctx context.Context, timeout time.Duration, dispatchSeq uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.pendingBeyond(dispatchSeq) || rb.closed || ctx.Err() != nil {
		return
	}
	stopCtx := context.AfterFunc(ctx, func() { rb.broadcast() })
	timer := time.AfterFunc(timeout, func() { rb.broadcast() })
	rb.cond.Wait()
	timer.Stop()
	stopCtx()
}

// pendingBeyond reports whether bytes exist beyond dispatchSeq. Caller must
// hold rb.mu.
func (rb *reliableBuffer) pendingBeyond(dispatchSeq uint64) bool {
	if dispatchSeq < rb.baseOffset {
		dispatchSeq = rb.baseOffset
	}
	return dispatchSeq-rb.baseOffset < uint64(rb.count)
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

	logField       *zap.Logger
	closedFlag     atomic.Bool // set once Close() wins; safe to read without the lock
	closeRequested atomic.Bool // graceful stop: ship what is queued, then exit
	kicked         atomic.Bool // set by Kick: the downlink must NOT send a close marker, so the client re-establishes
	closedCh       chan struct{}
	closedOnce     sync.Once
	// lastActive must stay an atomic.Int64, never a plain int64: on 32-bit
	// targets (386/arm) a plain int64 deep inside this struct lands on a
	// 4-byte boundary, and atomic.LoadInt64/StoreInt64 on it traps with
	// "unaligned 64-bit atomic operation". atomic.Int64 carries the
	// compiler's align64 marker, so it is 8-byte aligned wherever placed.
	lastActive      atomic.Int64
	downDispatchSeq uint64     // server->client dispatch cursor
	downWindowMu    sync.Mutex // guards concurrent access to the dispatch cursor
	// downWriter is the exclusive owner of the downlink dispatch cursor. A
	// streaming downlink response holds it for the session's lifetime; poll
	// responses acquire it briefly and release. Acquiring evicts the previous
	// owner and rewinds the cursor to the peer's last acknowledged byte, so
	// nothing the old owner had in flight can be lost (the peer dedups
	// re-sent bytes by sequence number).
	downWriter  atomic.Pointer[downWriterTicket]
	downPeerAck atomic.Uint64 // peer's ack of our downlink stream (client-reported)
	uploads     atomic.Int32  // admitted bounded poll producers
	streamUp    atomic.Int32  // at most one retained stream frame per session
	streamReady chan struct{} // initial stream POST passed authentication/admission
	streamOnce  sync.Once

	// closeErr records why the session died, for XHTTPConn.Err(). Written
	// once before the close signal fires; read-only afterwards.
	closeErr atomic.Pointer[closeErrValue]
}

// closeErrValue boxes an error so it can live in an atomic.Pointer.
type closeErrValue struct{ err error }

// setCloseErr records the session's death reason (first writer wins).
func (c *meekVirtualConn) setCloseErr(err error) {
	c.closeErr.CompareAndSwap(nil, &closeErrValue{err: err})
}

// getCloseErr returns the recorded death reason, or nil for a clean close.
func (c *meekVirtualConn) getCloseErr() error {
	if v := c.closeErr.Load(); v != nil {
		return v.err
	}
	return nil
}

// downWriterTicket identifies one downlink writer. Pointer identity lets a
// returning writer detect that a newer one replaced it.
type downWriterTicket struct{ identity byte }

// AcquireDownWriter evicts any previous downlink writer and takes ownership.
// The cursor is rewound to the peer's acknowledged byte so bytes the evicted
// writer had dispatched-but-unacknowledged are re-sent by the new owner.
func (c *meekVirtualConn) AcquireDownWriter(t *downWriterTicket) {
	c.downWindowMu.Lock()
	if ack := c.downPeerAck.Load(); ack < c.downDispatchSeq {
		c.downDispatchSeq = ack
	}
	c.downWriter.Store(t)
	c.downWindowMu.Unlock()
	c.writeBuf.broadcast() // wake the evicted owner so it observes the loss
}

// ReleaseDownWriter gives ownership up if the caller still holds it.
func (c *meekVirtualConn) ReleaseDownWriter(t *downWriterTicket) {
	if c.downWriter.CompareAndSwap(t, nil) {
		c.writeBuf.broadcast()
	}
}

// holdsDownWriter reports whether t is still the current downlink owner.
func (c *meekVirtualConn) holdsDownWriter(t *downWriterTicket) bool {
	return c.downWriter.Load() == t
}

// downWriterActive reports whether any streaming owner holds the downlink.
func (c *meekVirtualConn) downWriterActive() bool {
	return c.downWriter.Load() != nil
}

func newMeekVirtualConn(sessionID string, local, remote net.Addr, lg *zap.Logger) *meekVirtualConn {
	c := &meekVirtualConn{
		sessionID:   sessionID,
		local:       local,
		remote:      remote,
		logField:    lg,
		closedCh:    make(chan struct{}),
		streamReady: make(chan struct{}),
		readCond:    sync.NewCond(&sync.Mutex{}),
		writeBuf:    newReliableBuffer(4 * 1024 * 1024), // 4MB max buffer
		oooBuf:      make(map[uint64][]byte),
	}
	c.lastActive.Store(time.Now().Unix())
	return c
}

func (c *meekVirtualConn) signalStreamReady() {
	c.streamOnce.Do(func() { close(c.streamReady) })
}

// closedSignal is a channel closed when the session is fully closed. Callers
// with long blocking operations (stream probes) select on it to abort.
func (c *meekVirtualConn) closedSignal() <-chan struct{} { return c.closedCh }

// log returns the session's logger, falling back to the package logger when
// the owner did not thread one in (tests, low-level construction).
func (c *meekVirtualConn) log() *zap.Logger {
	if c.logField != nil {
		return c.logField
	}
	return logger
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
		c.drainContiguous()
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
		// Fire the shutdown signal so long-blocking operations (stream
		// negotiation probes) abort instead of idling out their windows.
		c.closedOnce.Do(func() {
			if c.closedCh != nil {
				close(c.closedCh)
			}
		})
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
			c.log().Warn("[Session] downlink drain timed out, closing with data still queued", zap.String("session", c.sessionID))
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
	ack, _ := c.PutReadDataContext(context.Background(), seq, data)
	return ack
}

// PutReadDataContext bounds the lifetime of a request waiting for receive
// capacity. Cancellation releases its payload without closing the session;
// the peer can retransmit from the returned cumulative acknowledgement.
func (c *meekVirtualConn) PutReadDataContext(ctx context.Context, seq uint64, data []byte) (uint64, error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	if uint64(len(data)) > ^uint64(0)-seq || len(data) > maxReassemblyBytes {
		return c.nextReadSeq, fmt.Errorf("invalid receive sequence or payload size")
	}
	// Register a wakeup only on the slow path; normal ingestion needs no
	// timer, goroutine or cancellation allocation.
	var stop func() bool
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return c.nextReadSeq, err
		}
		if c.isClosed() {
			return c.nextReadSeq, io.ErrClosedPipe
		}
		if seq < c.nextReadSeq {
			skip := c.nextReadSeq - seq
			if skip >= uint64(len(data)) {
				return c.nextReadSeq, nil
			}
			data = data[int(skip):]
			seq = c.nextReadSeq
		}
		if len(data) == 0 {
			return c.nextReadSeq, nil
		}
		switch {
		case seq == c.nextReadSeq && c.readBuf.Len()+len(data) <= maxReassemblyBytes:
			c.readBuf.Write(data)
			c.nextReadSeq += uint64(len(data))
			c.drainContiguous()
			c.readCond.Broadcast()
			return c.nextReadSeq, nil
		case seq > c.nextReadSeq:
			if existing, dup := c.oooBuf[seq]; dup {
				if len(data) <= len(existing) {
					return c.nextReadSeq, nil
				}
				growth := len(data) - len(existing)
				if c.oooBytes+growth <= maxOutOfOrderBytes {
					extended := make([]byte, len(data))
					copy(extended, existing)
					copy(extended[len(existing):], data[len(existing):])
					c.oooBuf[seq] = extended
					c.oooBytes += growth
					return c.nextReadSeq, nil
				}
				// Keep the already bounded prefix. Once the missing gap arrives,
				// its cumulative ACK asks the sender for any remaining suffix.
				return c.nextReadSeq, nil
			}
			if len(c.oooBuf) < maxOutOfOrderChunks && c.oooBytes+len(data) <= maxOutOfOrderBytes {
				dataCopy := bytes.Clone(data)
				c.oooBuf[seq] = dataCopy
				c.oooBytes += len(dataCopy)
				return c.nextReadSeq, nil
			}
		}
		if stop == nil && ctx.Done() != nil {
			stop = context.AfterFunc(ctx, func() {
				c.readCond.L.Lock()
				c.readCond.Broadcast()
				c.readCond.L.Unlock()
			})
		}
		c.readCond.Wait()
	}
}

// drainContiguous flushes every cached chunk that now sits immediately after
// the read cursor. Caller must hold readCond.L.
func (c *meekVirtualConn) drainContiguous() {
	for {
		// An in-order chunk may cover all or part of previously cached data.
		// Remove fully covered entries and re-key a surviving suffix at the
		// current cursor; otherwise stale entries can consume the OOO budget
		// forever because their original key is now behind nextReadSeq.
		for seq, data := range c.oooBuf {
			if seq >= c.nextReadSeq {
				continue
			}
			delete(c.oooBuf, seq)
			c.oooBytes -= len(data)
			end := seq + uint64(len(data)) // insertion rejects overflow
			if end <= c.nextReadSeq {
				continue
			}
			suffix := data[int(c.nextReadSeq-seq):]
			if existing, ok := c.oooBuf[c.nextReadSeq]; ok {
				if len(existing) >= len(suffix) {
					continue
				}
				c.oooBytes -= len(existing)
			}
			c.oooBuf[c.nextReadSeq] = suffix
			c.oooBytes += len(suffix)
		}
		nextData, ok := c.oooBuf[c.nextReadSeq]
		if !ok {
			return
		}
		// Never wait while draining: readers must be able to consume the
		// prefix just appended. Read resumes draining when capacity returns.
		if c.isClosed() || c.readBuf.Len()+len(nextData) > maxReassemblyBytes {
			return
		}
		delete(c.oooBuf, c.nextReadSeq)
		c.oooBytes -= len(nextData)
		c.readBuf.Write(nextData)
		c.nextReadSeq += uint64(len(nextData))
	}
}

func (c *meekVirtualConn) updateActive() {
	c.lastActive.Store(time.Now().Unix())
}

func (c *meekVirtualConn) Close() error {
	c.closedOnce.Do(func() {
		if c.closedCh != nil {
			close(c.closedCh)
		}
	})
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
