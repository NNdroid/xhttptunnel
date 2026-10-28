package tunnel

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestStreamEnvelopeAddsHeaderOnly pins where the pad sits on the streaming
// transport, because the layering is easy to misread and both "fixes" for it
// are wrong.
//
// The session conn frames every write before it reaches the ring, so by the
// time getStreamFrame copies ring bytes into an envelope it is wrapping an
// already padded frame. The envelope therefore adds its 22-byte header and no
// pad of its own: one pad per wire frame, not two. Removing the inner pad to
// save window would be worse than it looks — a session can be downgraded to
// long polling mid-life (the poll GET in the server handler takes the downlink
// cursor from a live streaming writer), and those same ring frames are what a
// poll body carries. Unpadded frames would then ship exact sizes in precisely
// the CDN-buffered case the rule exists for.
func TestStreamEnvelopeAddsHeaderOnly(t *testing.T) {
	withPadding(t, "400-600")

	const payloadLen = 20
	vc := newMeekVirtualConn("stream-pad", nil, nil, nil)
	conn := newXHTTPConn(vc, vc, nil, nil, nil, vc)
	if _, err := conn.Write(bytes.Repeat([]byte{0x41}, payloadLen)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := vc.writeBuf.Len(); got < 406 || got > 606 {
		t.Fatalf("the ring holds %d bytes for a %d-byte write, want one padded frame (406..606)", got, payloadLen)
	}

	frame, seq, err := vc.writeBuf.getStreamFrame(0, 0, 0, currentMaxSendBufSize(), nil)
	if err != nil {
		t.Fatalf("getStreamFrame: %v", err)
	}
	if seq != 0 {
		t.Fatalf("frame starts at seq %d, want 0", seq)
	}
	if len(frame) < 22+6 {
		t.Fatalf("envelope is %d bytes, too short for its header plus a frame header", len(frame))
	}

	innerLen := int(binary.BigEndian.Uint32(frame[16:20]))
	outerPad := int(binary.BigEndian.Uint16(frame[20:22]))
	if outerPad != 0 {
		t.Fatalf("the envelope padded an already padded frame by %d bytes; the pad must be applied once", outerPad)
	}
	if got, want := len(frame), 22+innerLen; got != want {
		t.Fatalf("wire frame is %d bytes, want the 22-byte header plus %d ring bytes", got, innerLen)
	}

	// The wrapped bytes must be one complete data frame in the band, with the
	// application payload intact behind its pad.
	if innerLen < 406 || innerLen > 606 {
		t.Fatalf("inner frame is %d bytes, want 406..606", innerLen)
	}
	if got := int(binary.BigEndian.Uint32(frame[22:26])); got != payloadLen {
		t.Fatalf("inner frame payload = %d, want %d", got, payloadLen)
	}
	innerPad := int(binary.BigEndian.Uint16(frame[26:28]))
	if got := 6 + payloadLen + innerPad; got != innerLen {
		t.Fatalf("inner frame says 6+%d+%d = %d bytes but carries %d", payloadLen, innerPad, got, innerLen)
	}
	for i := 0; i < payloadLen; i++ {
		if frame[28+innerPad+i] != 0x41 {
			t.Fatalf("payload byte %d is %#x, want 0x41", i, frame[28+innerPad+i])
		}
	}

	// The 22-byte header is the whole difference between the band and the wire,
	// which is why README quotes 428..628 for a small streaming write.
	if len(frame) < 428 || len(frame) > 628 {
		t.Fatalf("wire frame is %d bytes, want 428..628 (band plus the envelope header)", len(frame))
	}
}
