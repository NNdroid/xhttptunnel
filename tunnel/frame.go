package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	maxUDPFrameSize = 65535
)

func ReadUDPFrameInto(r io.Reader, buf []byte) (int, error) {
	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if length > len(buf) {
		return 0, fmt.Errorf("buffer too small for UDP frame: length=%d, cap=%d", length, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:length]); err != nil {
		return 0, err
	}
	return length, nil
}

func WriteUDPFrame(w io.Writer, payload []byte) error {
	length := len(payload)
	if length > 65535 {
		return fmt.Errorf("UDP payload too large: %d > 65535", length)
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(length))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

type DumpConn struct {
	net.Conn
	Prefix string
}

func (c *DumpConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬇️ read %d bytes ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

func (c *DumpConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬆️ sent %d bytes ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

type DumpPacketConn struct {
	net.PacketConn
	Prefix string
}

func (c *DumpPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬇️ read from %s: %d bytes ---\n%s\n", c.Prefix, addr.String(), n, hex.Dump(b[:n]))
	}
	return n, addr, err
}

func (c *DumpPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬆️ sent to %s: %d bytes ---\n%s\n", c.Prefix, addr.String(), n, hex.Dump(b[:n]))
	}
	return n, err
}

// ==========================================
// XHTTP dynamic padding and EOF signaling frame
// ==========================================

type XHTTPConn struct {
	r          io.Reader
	w          io.Writer
	closer     func() error
	local      net.Addr
	remote     net.Addr
	targetAddr string
	network    string
	// vc is the underlying session, when this conn wraps one (nil in tests
	// that build the conn from raw pipes). It backs Done() and Err().
	vc               *meekVirtualConn
	mu               sync.Mutex
	readMu           sync.Mutex
	readPending      []byte
	readScratch      []byte
	headerRead       int
	headerParsed     bool
	paddingRemaining int
	payloadRemaining int
	nextPayload      int
	peerClosed       bool
	frameBuf         []byte
	hdrBuf           []byte
	payloadBuf       []byte
	padScratch       []byte
	closeCh          chan struct{}
	closedFlag       int32
}

func newXHTTPConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr, vc *meekVirtualConn) *XHTTPConn {
	return &XHTTPConn{
		r: r, w: w, closer: closer, local: local, remote: remote, vc: vc,
		// The frame and padding buffers grow on first use. An accepted session
		// can remain idle for minutes behind a CDN, so reserving a full chunk for
		// every connection is expensive at high concurrency.
		hdrBuf:  make([]byte, 6),
		closeCh: make(chan struct{}),
	}
}

// Done returns a channel closed when the underlying session begins closing —
// normally when the tunnelled application on the peer side ends the session,
// or on transport death. Nil when this conn does not wrap a session.
func (c *XHTTPConn) Done() <-chan struct{} {
	if c.vc != nil {
		return c.vc.closedSignal()
	}
	return nil
}

// Err returns why the session died, if a reason was recorded (nil means a
// clean close or that the conn is still open).
func (c *XHTTPConn) Err() error {
	if c.vc != nil {
		return c.vc.getCloseErr()
	}
	return nil
}

func (c *XHTTPConn) WriteCloseFrame() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	frame := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
	_, err := c.w.Write(frame)
	return err
}

// padLenFor implements the per-chunk padding policy: empty chunks dress up as
// small random keepalives, tiny chunks are padded into a common size band so
// short payloads stop being length-linkable, and bulk chunks get light cover.
func padLenFor(chunkSize int) int {
	var padLenInt int
	switch {
	case chunkSize == 0:
		padLenInt = 32 + mrand.Intn(128)
	case chunkSize < 512:
		padLenInt = (600 + mrand.Intn(600)) - chunkSize
		if padLenInt < 0 {
			padLenInt = mrand.Intn(256)
		}
	default:
		padLenInt = 16 + mrand.Intn(112)
	}
	return padLenInt
}

func (c *XHTTPConn) writeSingleFrame(chunk []byte) error {
	chunkSize := len(chunk)
	padLenInt := padLenFor(chunkSize)

	frameLen := 6 + padLenInt + chunkSize
	if frameLen > cap(c.frameBuf) {
		newCap := cap(c.frameBuf) * 2
		if newCap < frameLen {
			newCap = frameLen
		}
		c.frameBuf = make([]byte, frameLen, newCap)
	} else {
		c.frameBuf = c.frameBuf[:frameLen]
	}

	binary.BigEndian.PutUint32(c.frameBuf[0:4], uint32(chunkSize))
	binary.BigEndian.PutUint16(c.frameBuf[4:6], uint16(padLenInt))

	if padLenInt > 0 {
		if padLenInt > cap(c.padScratch) {
			c.padScratch = make([]byte, padLenInt)
		}
		// Fresh CSPRNG bytes every frame. A process-lifetime static pool would
		// let a traffic analyst spot the same padding bytes recurring across
		// many frames, which defeats the point of dynamic padding.
		if _, err := rand.Read(c.padScratch[:padLenInt]); err != nil {
			return err
		}
		copy(c.frameBuf[6:6+padLenInt], c.padScratch[:padLenInt])
	}
	if chunkSize > 0 {
		copy(c.frameBuf[6+padLenInt:], chunk)
	}

	_, err := c.w.Write(c.frameBuf)
	return err
}

// streamFrameBytes renders one chunk of the stream-mode wire format into a
// single buffer: a 16-byte metadata block (sender's stream sequence, ack of
// the peer's stream) followed by the standard 6-byte padded frame. One buffer
// means one Write per chunk on the wire.
func streamFrameBytes(seq, ack uint64, payload []byte) ([]byte, error) {
	return streamFrameBytesInto(nil, seq, ack, payload)
}

func streamFrameStorage(scratch []byte, seq, ack uint64, length, pad int) []byte {
	total := 22 + pad + length
	if cap(scratch) < total {
		scratch = make([]byte, total)
	}
	buf := scratch[:total]
	binary.BigEndian.PutUint64(buf[0:8], seq)
	binary.BigEndian.PutUint64(buf[8:16], ack)
	binary.BigEndian.PutUint32(buf[16:20], uint32(length))
	binary.BigEndian.PutUint16(buf[20:22], uint16(pad))
	return buf
}

func streamFrameBytesInto(scratch []byte, seq, ack uint64, payload []byte) ([]byte, error) {
	padLenInt := padLenFor(len(payload))
	buf := streamFrameStorage(scratch, seq, ack, len(payload), padLenInt)
	if padLenInt > 0 {
		if _, err := rand.Read(buf[22 : 22+padLenInt]); err != nil {
			return nil, err
		}
	}
	copy(buf[22+padLenInt:], payload)
	return buf, nil
}

func streamCloseFrameBytes(seq, ack uint64) ([]byte, error) {
	frame, err := streamFrameBytes(seq, ack, nil)
	if err == nil {
		binary.BigEndian.PutUint32(frame[16:20], ^uint32(0))
	}
	return frame, err
}

// streamFrame is one parsed stream-mode chunk.
type streamFrame struct {
	seq    uint64 // sender's stream sequence for this payload
	ack    uint64 // sender's ack of the receiver's stream
	closed bool   // payloadLen == 0xFFFFFFFF: session close marker
	data   []byte
}

// readStreamFrame parses one stream-mode chunk from r. Header guards mirror
// XHTTPConn.Read's defense in depth.
func readStreamFrame(r io.Reader) (streamFrame, error) {
	var scratch []byte
	return readStreamFrameInto(r, &scratch)
}

// The payload is borrowed until the next call. PutReadData copies accepted
// data into its bounded reassembly storage before that call occurs.
func readStreamFrameInto(r io.Reader, scratch *[]byte) (streamFrame, error) {
	var meta [22]byte
	if _, err := io.ReadFull(r, meta[:]); err != nil {
		return streamFrame{}, err
	}
	f := streamFrame{
		seq:    binary.BigEndian.Uint64(meta[0:8]),
		ack:    binary.BigEndian.Uint64(meta[8:16]),
		closed: binary.BigEndian.Uint32(meta[16:20]) == 0xFFFFFFFF,
	}
	padLen := int(binary.BigEndian.Uint16(meta[20:22]))
	if padLen > 65535 {
		return f, fmt.Errorf("corrupted stream frame: padLen=%d", padLen)
	}
	payloadLen := binary.BigEndian.Uint32(meta[16:20])
	if !f.closed && payloadLen > uint32(currentMaxFrameSize()*4) {
		return f, fmt.Errorf("corrupted stream frame: payloadLen=%d", payloadLen)
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return f, err
		}
	}
	if f.closed || payloadLen == 0 {
		return f, nil
	}
	if cap(*scratch) < int(payloadLen) {
		*scratch = make([]byte, payloadLen)
	}
	f.data = (*scratch)[:payloadLen]
	if _, err := io.ReadFull(r, f.data); err != nil {
		return f, err
	}
	return f, nil
}

func (c *XHTTPConn) Write(p []byte) (int, error) {
	if atomic.LoadInt32(&c.closedFlag) == 1 {
		return 0, io.ErrClosedPipe
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, c.writeSingleFrame(nil)
	}

	written := 0
	maxPayload := currentMaxFrameSize()
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

func (c *XHTTPConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.vc != nil {
		if err := c.vc.readDeadlineError(); err != nil {
			return 0, err
		}
	}
	for {
		if len(c.readPending) > 0 {
			n := copy(p, c.readPending)
			c.readPending = c.readPending[n:]
			return n, nil
		}
		if c.payloadRemaining > 0 {
			count := len(p)
			if count > c.payloadRemaining {
				count = c.payloadRemaining
			}
			// Preserve frame-sized batching while tracking partial progress:
			// tiny transport reads otherwise multiply TCP writes and H2/H3
			// flushes. A deadline returns its accepted prefix and can resume.
			n, err := io.ReadFull(c.r, p[:count])
			c.payloadRemaining -= n
			if err == nil && c.payloadRemaining > 0 {
				// Drain the rest of this frame before returning the prefix, as
				// the original reader did. Reuse dedicated storage rather than
				// allocating a leftover slice for every application Read.
				if cap(c.readScratch) < c.payloadRemaining {
					c.readScratch = make([]byte, c.payloadRemaining)
				}
				remaining, rerr := io.ReadFull(c.r, c.readScratch[:c.payloadRemaining])
				c.payloadRemaining -= remaining
				c.readPending = c.readScratch[:remaining]
				err = rerr
			}
			return n, err
		}
		for c.headerRead < 6 {
			n, err := c.r.Read(c.hdrBuf[c.headerRead:])
			c.headerRead += n
			if err != nil && c.headerRead < 6 {
				return 0, err
			}
			if n == 0 && err == nil {
				return 0, io.ErrNoProgress
			}
		}
		if !c.headerParsed {
			raw := binary.BigEndian.Uint32(c.hdrBuf[:4])
			c.paddingRemaining = int(binary.BigEndian.Uint16(c.hdrBuf[4:6]))
			c.peerClosed = raw == ^uint32(0)
			if !c.peerClosed && raw > uint32(currentMaxFrameSize()*4) {
				return 0, fmt.Errorf("corrupted frame header: payloadLen=%d", raw)
			}
			if !c.peerClosed {
				c.nextPayload = int(raw)
			}
			c.headerParsed = true
		}
		for c.paddingRemaining > 0 {
			if len(c.payloadBuf) == 0 {
				c.payloadBuf = make([]byte, 1024)
			}
			count := c.paddingRemaining
			if count > len(c.payloadBuf) {
				count = len(c.payloadBuf)
			}
			n, err := c.r.Read(c.payloadBuf[:count])
			c.paddingRemaining -= n
			if err != nil && c.paddingRemaining > 0 {
				return 0, err
			}
			if n == 0 && err == nil {
				return 0, io.ErrNoProgress
			}
		}
		if c.peerClosed {
			return 0, io.EOF
		}
		c.payloadRemaining = c.nextPayload
		c.nextPayload = 0
		c.headerRead = 0
		c.headerParsed = false
	}
}

func (c *XHTTPConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1) {
		close(c.closeCh)
		return c.closer()
	}
	return nil
}

// TargetAddr and Network report the forwarding target the client requested
// for this session. They are only meaningful on the server side.
func (c *XHTTPConn) TargetAddr() string { return c.targetAddr }
func (c *XHTTPConn) Network() string    { return c.network }

func (c *XHTTPConn) LocalAddr() net.Addr  { return c.local }
func (c *XHTTPConn) RemoteAddr() net.Addr { return c.remote }
func (c *XHTTPConn) SetDeadline(t time.Time) error {
	if c.vc == nil {
		return errors.ErrUnsupported
	}
	return c.vc.SetDeadline(t)
}
func (c *XHTTPConn) SetReadDeadline(t time.Time) error {
	if c.vc == nil {
		return errors.ErrUnsupported
	}
	return c.vc.SetReadDeadline(t)
}
func (c *XHTTPConn) SetWriteDeadline(t time.Time) error {
	if c.vc == nil {
		return errors.ErrUnsupported
	}
	return c.vc.SetWriteDeadline(t)
}
