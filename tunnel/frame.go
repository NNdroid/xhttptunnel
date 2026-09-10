package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

type DumpPacketConn struct {
	net.PacketConn
	Prefix string
}

func (c *DumpPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬇️ 从 %s 读取 %d 字节 ---\n%s\n", c.Prefix, addr.String(), n, hex.Dump(b[:n]))
	}
	return n, addr, err
}

func (c *DumpPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if n > 0 {
		fmt.Printf("\n--- [%s] ⬆️ 发送到 %s %d 字节 ---\n%s\n", c.Prefix, addr.String(), n, hex.Dump(b[:n]))
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
	vc         *meekVirtualConn
	mu         sync.Mutex
	readBuf    []byte
	frameBuf   []byte
	hdrBuf     []byte
	payloadBuf []byte
	padScratch []byte
	closeCh    chan struct{}
	closedFlag int32
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
	padLenInt := padLenFor(len(payload))
	total := 16 + 6 + padLenInt + len(payload)
	buf := make([]byte, total)
	binary.BigEndian.PutUint64(buf[0:8], seq)
	binary.BigEndian.PutUint64(buf[8:16], ack)
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(payload)))
	binary.BigEndian.PutUint16(buf[20:22], uint16(padLenInt))
	if padLenInt > 0 {
		if _, err := rand.Read(buf[22 : 22+padLenInt]); err != nil {
			return nil, err
		}
	}
	copy(buf[22+padLenInt:], payload)
	return buf, nil
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
	payloadLen := binary.BigEndian.Uint32(meta[16:20]) & 0x7FFFFFFF
	if payloadLen > uint32(currentMaxFrameSize()*4) {
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
	f.data = make([]byte, payloadLen)
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
	if len(c.readBuf) > 0 {
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

		// Defense in depth: cap per-frame padding and payload size to prevent malicious OOM
		if padLen > 65535 || (rawPayloadLen != 0xFFFFFFFF && rawPayloadLen > uint32(currentMaxFrameSize()*4)) {
			return 0, fmt.Errorf("corrupted frame header: payloadLen=%d, padLen=%d", rawPayloadLen, padLen)
		}

		if padLen > 0 {
			if padLen > cap(c.payloadBuf) {
				c.payloadBuf = make([]byte, padLen)
			}
			if _, err := io.ReadFull(c.r, c.payloadBuf[:padLen]); err != nil {
				return 0, err
			}
		}

		if rawPayloadLen == uint32(0xFFFFFFFF) {
			return 0, io.EOF
		}
		if rawPayloadLen == 0 {
			continue
		}

		payloadLen := int(rawPayloadLen)
		readIntoP := payloadLen
		if readIntoP > len(p) {
			readIntoP = len(p)
		}
		if _, err := io.ReadFull(c.r, p[:readIntoP]); err != nil {
			return 0, err
		}

		leftover := payloadLen - readIntoP
		if leftover > 0 {
			// The leftover bytes must be stored in a dedicated slice; never reuse
			// c.payloadBuf here, otherwise reading the next frame's padding
			// (line 253) would overwrite this unread payload data!
			leftoverBuf := make([]byte, leftover)
			if _, err := io.ReadFull(c.r, leftoverBuf); err != nil {
				return readIntoP, err
			}
			c.readBuf = leftoverBuf
		}
		return readIntoP, nil
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

func (c *XHTTPConn) LocalAddr() net.Addr                { return c.local }
func (c *XHTTPConn) RemoteAddr() net.Addr               { return c.remote }
func (c *XHTTPConn) SetDeadline(t time.Time) error      { return nil }
func (c *XHTTPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *XHTTPConn) SetWriteDeadline(t time.Time) error { return nil }
