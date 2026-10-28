package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/url"
	"testing"
	"time"
)

// TestStreamEnvelopeAddsHeaderOnly pins the pre-negotiation shape, because the
// layering is easy to misread and both "fixes" for it are wrong.
//
// This is what a pair that never exchanged CapPadBody produces: the frame layer
// pads (a frame's own pad field is understood by every peer) and the chunk is
// then past the band's threshold, so the envelope adds its 22-byte header and no
// pad — a 422..622-byte object, which is a frame taller than the band.
//
// The inner pad is load-bearing here and cannot simply be dropped to save
// window: a session can be downgraded to long polling mid-life (the poll GET in
// the server handler takes the downlink cursor from a live streaming writer),
// and those same ring frames are what a poll body then carries. Unpadded frames
// would ship exact sizes in precisely the CDN-buffered case the rule exists for.
// That is why the negotiated shape moves padding to the transport instead of
// removing it — see TestStreamEnvelopeCarriesThePadWhenNegotiated.
func TestStreamEnvelopeAddsHeaderOnly(t *testing.T) {
	withPadding(t, "400-600")

	const payloadLen = 20
	vc := newMeekVirtualConn("stream-pad", nil, nil, nil)
	conn := newXHTTPConn(vc, vc, nil, nil, nil, vc)
	if _, err := conn.Write(bytes.Repeat([]byte{0x41}, payloadLen)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := vc.writeBuf.Len(); got < 400 || got > 600 {
		t.Fatalf("the ring holds %d bytes for a %d-byte write, want one padded frame (400..600)", got, payloadLen)
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
	if innerLen < 400 || innerLen > 600 {
		t.Fatalf("inner frame is %d bytes, want 400..600", innerLen)
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

	// The 22-byte header is the whole difference between the band and the wire
	// here, which is the 422..622 this test exists to describe.
	if len(frame) < 422 || len(frame) > 622 {
		t.Fatalf("wire frame is %d bytes, want 422..622 (band plus the envelope header)", len(frame))
	}
}

// TestStreamEnvelopeCarriesThePadWhenNegotiated pins the negotiated shape, the
// one both ends reach after exchanging CapPadBody.
//
// The frame layer leaves the ring bare, so the send window carries payload
// instead of padding and the envelope carries the only pad — and it counts its
// own 22-byte header when choosing it. A 20-byte write therefore leaves exactly
// one 400..600-byte object, rather than the 422..622 of the compatible shape,
// and an observer cannot tell a streamed session from a polled one by size.
func TestStreamEnvelopeCarriesThePadWhenNegotiated(t *testing.T) {
	withPadding(t, "400-600")

	const payloadLen = 20
	vc := newMeekVirtualConn("stream-pad-negotiated", nil, nil, nil)
	vc.padInTransport.Store(true)
	conn := newXHTTPConn(vc, vc, nil, nil, nil, vc)
	if _, err := conn.Write(bytes.Repeat([]byte{0x41}, payloadLen)); err != nil {
		t.Fatalf("write: %v", err)
	}
	bare := frameHeaderSize + payloadLen
	if got := vc.writeBuf.Len(); got != bare {
		t.Fatalf("the ring holds %d bytes for a %d-byte write, want one bare %d-byte frame", got, payloadLen, bare)
	}

	frame, seq, err := vc.writeBuf.getStreamFrame(0, 0, 0, currentMaxSendBufSize(), nil)
	if err != nil {
		t.Fatalf("getStreamFrame: %v", err)
	}
	if seq != 0 {
		t.Fatalf("frame starts at seq %d, want 0", seq)
	}
	if total := len(frame); total < 400 || total > 600 {
		t.Fatalf("wire object is %d bytes, want 400..600; the envelope pad has to count its own header", total)
	}

	innerLen := int(binary.BigEndian.Uint32(frame[16:20]))
	outerPad := int(binary.BigEndian.Uint16(frame[20:22]))
	if innerLen != bare {
		t.Fatalf("envelope carries %d ring bytes, want the bare frame (%d)", innerLen, bare)
	}
	if got, want := len(frame), streamEnvelopeHeader+outerPad+innerLen; got != want {
		t.Fatalf("wire object is %d bytes, header says %d + %d + %d", got, streamEnvelopeHeader, outerPad, innerLen)
	}
	inner := streamEnvelopeHeader + outerPad
	if innerPad := int(binary.BigEndian.Uint16(frame[inner+4 : inner+6])); innerPad != 0 {
		t.Fatalf("inner frame pads by %d bytes on top of the envelope; the pad must be applied once", innerPad)
	}
	if got := int(binary.BigEndian.Uint32(frame[inner : inner+4])); got != payloadLen {
		t.Fatalf("inner frame payload length = %d, want %d", got, payloadLen)
	}
	for i := 0; i < payloadLen; i++ {
		if got := frame[inner+frameHeaderSize+i]; got != 0x41 {
			t.Fatalf("payload byte %d is %#x, want 0x41", i, got)
		}
	}

	// The reader strips the envelope pad and hands back the frame unchanged.
	f, err := readStreamFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readStreamFrame: %v", err)
	}
	if len(f.data) != bare {
		t.Fatalf("reader gave back %d bytes, want the %d-byte frame", len(f.data), bare)
	}
	if got := int(binary.BigEndian.Uint32(f.data[0:4])); got != payloadLen {
		t.Fatalf("inner payload length = %d, want %d", got, payloadLen)
	}
}

// TestPaddingHandsOffToTheTransportOverAStreamSession checks the negotiation
// end to end rather than at the buffer: a streamed session talking to an origin
// that speaks CapPadBody must stop padding at the frame layer and let the
// envelope own the pad. Without the handoff the frame pad shapes the wire and
// every streamed object sits 22 bytes above the band, which is the shape this
// whole layer exists to avoid.
func TestPaddingHandsOffToTheTransportOverAStreamSession(t *testing.T) {
	withPadding(t, "400-600")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pad-secret", "", "", "")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	serverURL, err := url.Parse("http://" + origin.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("parse origin URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password:   "pad-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "stream",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial in forced stream mode: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte{'s'}, 20)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readFullBefore(conn, len(payload), 20*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted through the streamed session")
	}

	xc, ok := conn.(*XHTTPConn)
	if !ok {
		t.Fatalf("dial returned %T, want *XHTTPConn", conn)
	}
	if xc.vc == nil || !xc.vc.padInTransport.Load() {
		t.Fatal("the session never handed padding to the transport: the origin's CapPadBody echo was not acted on")
	}
}
