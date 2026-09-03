package main

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

func readUDPFrameInto(r io.Reader, buf []byte) (int, error) {
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

func writeUDPFrame(w io.Writer, payload []byte) error {
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
	padScratch []byte
	closeCh    chan struct{}
	closedFlag int32
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	return &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		// The frame and padding buffers grow on first use. An accepted session
		// can remain idle for minutes behind a CDN, so reserving a full chunk for
		// every connection is expensive at high concurrency.
		hdrBuf:  make([]byte, 6),
		closeCh: make(chan struct{}),
	}
}

func (c *xhttpFramedConn) WriteCloseFrame() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	frame := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
	_, err := c.w.Write(frame)
	return err
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

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	if atomic.LoadInt32(&c.closedFlag) == 1 {
		return 0, io.ErrClosedPipe
	}
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
		if padLen > 65535 || (rawPayloadLen != 0xFFFFFFFF && rawPayloadLen > uint32(maxframeSize*4)) {
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

func (c *xhttpFramedConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1) {
		close(c.closeCh)
		c.readBuf = nil
		return c.closer()
	}
	return nil
}

func (c *xhttpFramedConn) LocalAddr() net.Addr                { return c.local }
func (c *xhttpFramedConn) RemoteAddr() net.Addr               { return c.remote }
func (c *xhttpFramedConn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpFramedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpFramedConn) SetWriteDeadline(t time.Time) error { return nil }
