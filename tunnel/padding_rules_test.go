package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
)

// complexPaddingRules are whole rules the parser must accept, each with the
// band table it has to compile to. They exist because the single-band default
// exercises almost none of the parser: the interesting cases are a threshold
// that differs from the band's own lower bound, several bands of very different
// widths, and the extremes of the size limits.
var complexPaddingRules = []struct {
	name  string
	spec  string
	bands []paddingBand
}{
	{
		name: "control band plus main band",
		spec: "1:120-200,400:400-600",
		bands: []paddingBand{
			{below: 1, min: 120, max: 200},
			{below: 400, min: 400, max: 600},
		},
	},
	{
		name: "three bands, irregular widths",
		spec: "1:120-200,64:300-360,400:400-600",
		bands: []paddingBand{
			{below: 1, min: 120, max: 200},
			{below: 64, min: 300, max: 360},
			{below: 400, min: 400, max: 600},
		},
	},
	{
		name: "band far above its threshold",
		// Everything under 100 bytes is padded to 600..700, so 100..599-byte
		// payloads end up shorter than padded 99-byte ones. Odd, but the rule
		// is well formed and the ordering is not something to forbid.
		spec:  "100:600-700",
		bands: []paddingBand{{below: 100, min: 600, max: 700}},
	},
	{
		name: "shorthand threshold equals lower bound",
		spec: "40-60",
		bands: []paddingBand{
			{below: 40, min: 40, max: 60},
		},
	},
	{
		name: "band at the floor of the negative-pad rule",
		// min == below-1 is the smallest lower bound a threshold admits:
		// a payload of below-1 bytes may already sit at the band's floor.
		spec:  "400:399-600",
		bands: []paddingBand{{below: 400, min: 399, max: 600}},
	},
	{
		name: "single-size bands",
		spec: "1:64-64,2:128-128,3:512-512",
		bands: []paddingBand{
			{below: 1, min: 64, max: 64},
			{below: 2, min: 128, max: 128},
			{below: 3, min: 512, max: 512},
		},
	},
	{
		name: "whitespace and case",
		spec: " 1 : 120 - 200 ,\t400 : 400 - 600 ",
		bands: []paddingBand{
			{below: 1, min: 120, max: 200},
			{below: 400, min: 400, max: 600},
		},
	},
	{
		name: "ceiling of the pad field",
		spec: "65535:65535-65535",
		bands: []paddingBand{
			{below: 65535, min: 65535, max: 65535},
		},
	},
	{
		name: "spread across the whole range",
		spec: "1:120-200,1000:1024-2048,65535:65535-65535",
		bands: []paddingBand{
			{below: 1, min: 120, max: 200},
			{below: 1000, min: 1024, max: 2048},
			{below: 65535, min: 65535, max: 65535},
		},
	},
}

func TestPaddingComplexSpecsParse(t *testing.T) {
	for _, tc := range complexPaddingRules {
		p, err := parsePaddingSpec(tc.spec)
		if err != nil {
			t.Errorf("%s: parsePaddingSpec(%q): %v", tc.name, tc.spec, err)
			continue
		}
		if len(p.bands) != len(tc.bands) {
			t.Errorf("%s: %q compiled to %d bands, want %d", tc.name, tc.spec, len(p.bands), len(tc.bands))
			continue
		}
		for i := range tc.bands {
			if p.bands[i] != tc.bands[i] {
				t.Errorf("%s: band %d = %+v, want %+v", tc.name, i, p.bands[i], tc.bands[i])
			}
		}
		// The log line is built from the compiled bands, so it must spell out
		// every threshold explicitly whatever shorthand the operator wrote.
		want := ""
		for i, b := range tc.bands {
			if i > 0 {
				want += ","
			}
			want += fmt.Sprintf("%d:%d-%d", b.below, b.min, b.max)
		}
		if p.spec != want {
			t.Errorf("%s: %q normalised to %q, want %q", tc.name, tc.spec, p.spec, want)
		}
	}
}

// TestPaddingComplexSpecsReject collects the shapes a hand-written rule can get
// wrong. Each one must be refused at startup with a message that names the
// problem, because a silently accepted bad rule corrupts frames rather than
// merely shaping them differently.
func TestPaddingComplexSpecsReject(t *testing.T) {
	cases := map[string]string{
		// Band ordering.
		"1:120-200,64:300-360,64:400-600": "must be greater than the previous band",
		"100:200-300,50:400-500":          "must be greater than the previous band",
		"400:400-600,200:200-300":         "must be greater than the previous band",
		// Negative pad: the band's own longest payload already exceeds its target.
		"400:398-600":        "would already exceed the target",
		"1:10-20,100:98-200": "would already exceed the target",
		// Bounds.
		"0:400-600":                   "threshold must be at least 1",
		"0-600":                       "lower bound must be at least 1",
		"1:0-100":                     "lower bound must be at least 1",
		"400-200":                     "inverted range",
		"65536:65536-65536":           "exceeds",
		"1:120-200,65536:65536-65536": "exceeds",
		// Shape.
		"400":              "is not MIN-MAX",
		"400-":             "empty size",
		"-600":             "empty size",
		"400-600-700":      "is not a byte count",
		"abc-600":          "is not a byte count",
		"400:-600":         "empty size",
		"400:600":          "is not MIN-MAX",
		"400-600,,600-800": "empty band",
		"400-600,":         "empty band",
		// strconv.Atoi would take these as numbers; the digit check must not.
		"+400-600": "is not a byte count",
		"400-+600": "is not a byte count",
	}
	for spec, want := range cases {
		err := ValidatePadding(spec)
		if err == nil {
			t.Errorf("ValidatePadding(%q) accepted an invalid rule", spec)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidatePadding(%q) = %q, want a message containing %q", spec, err, want)
		}
	}
}

// TestPaddingMaxBandsBoundary pins the limit from both sides: eight bands are a
// legitimate rule, nine are a typo that would turn the lookup into a search.
func TestPaddingMaxBandsBoundary(t *testing.T) {
	eight := make([]string, 0, 8)
	nine := make([]string, 0, 9)
	for i := 1; i <= 9; i++ {
		band := fmt.Sprintf("%d:%d-%d", i, i*10, i*10+5)
		if i <= 8 {
			eight = append(eight, band)
		}
		nine = append(nine, band)
	}
	if err := ValidatePadding(strings.Join(eight, ",")); err != nil {
		t.Errorf("eight bands were rejected: %v", err)
	}
	if err := ValidatePadding(strings.Join(nine, ",")); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("nine bands = %v, want an 'at most' error", err)
	}
}

// bandForPayload is the matching rule the test asserts against, written out
// separately from padLen so a change in the implementation cannot satisfy it by
// construction: the first band whose threshold is above the payload wins.
func bandForPayload(bands []paddingBand, n int) (paddingBand, bool) {
	for _, b := range bands {
		if n < b.below {
			return b, true
		}
	}
	return paddingBand{}, false
}

// payloadsForBand picks payload sizes inside one band's payload range
// [previous threshold, this threshold).
func payloadsForBand(prevBelow, below int) []int {
	if below <= prevBelow {
		return nil
	}
	out := []int{prevBelow, below - 1}
	if mid := (prevBelow + below - 1) / 2; mid != prevBelow && mid != below-1 {
		out = append(out, mid)
	}
	if below-prevBelow > 10 {
		out = append(out, prevBelow+3, below-4)
	}
	return out
}

// TestPaddingComplexRulesPickTheRightBand runs each rule over the payloads every
// band claims and checks the totals it actually produces: the right band, never
// below its floor, and spread over its range rather than pinned to one value.
func TestPaddingComplexRulesPickTheRightBand(t *testing.T) {
	for _, tc := range complexPaddingRules {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parsePaddingSpec(tc.spec)
			if err != nil {
				t.Fatalf("parsePaddingSpec(%q): %v", tc.spec, err)
			}

			prev := 0
			for _, b := range p.bands {
				for _, n := range payloadsForBand(prev, b.below) {
					seen := map[int]bool{}
					for i := 0; i < 400; i++ {
						pad := p.padLen(n)
						if pad < 0 {
							t.Fatalf("payload %d padded by %d", n, pad)
						}
						total := n + pad
						if total < b.min || total > b.max {
							t.Fatalf("payload %d landed at %d, outside band [%d,%d]", n, total, b.min, b.max)
						}
						seen[total] = true
					}
					// A band that always produced the same total would be a
					// one-value signature, not a distribution. Small bands are
					// exempt from the ratio, not from the spread itself.
					if width := b.max - b.min + 1; width > 1 {
						want := width / 2
						if want > 200 {
							want = 200
						}
						if len(seen) < want {
							t.Errorf("payload %d reached only %d of %d totals in [%d,%d]", n, len(seen), width, b.min, b.max)
						}
					}
				}
				prev = b.below
			}

			// Everything at or above the last threshold travels bare.
			for _, n := range []int{prev, prev + 1, prev * 2, 256000} {
				if pad := p.padLen(n); pad != 0 {
					t.Errorf("payload %d is past the last threshold but was padded by %d", n, pad)
				}
			}
		})
	}
}

// TestPaddingComplexRulesOnTheWire is the behavioural half: the inner frame the
// tunnel actually writes must match its own header, land in the band the rule
// assigns, and still deliver the payload byte for byte.
func TestPaddingComplexRulesOnTheWire(t *testing.T) {
	const spec = "1:120-200,64:300-360,400:400-600"
	bands := []paddingBand{
		{below: 1, min: 120, max: 200},
		{below: 64, min: 300, max: 360},
		{below: 400, min: 400, max: 600},
	}
	withPadding(t, spec)

	payloads := []struct {
		n      int
		padded bool
		band   paddingBand
	}{
		{0, true, bands[0]},
		{1, true, bands[1]},
		{63, true, bands[1]},
		{64, true, bands[2]},
		{399, true, bands[2]},
		{400, false, paddingBand{}},
		{1024, false, paddingBand{}},
	}

	for _, tc := range payloads {
		payload := bytes.Repeat([]byte{byte('a' + tc.n%26)}, tc.n)
		var buf bytes.Buffer
		sender := newXHTTPConn(&buf, &buf, func() error { return nil }, nil, nil, nil)
		if err := sender.writeSingleFrame(payload); err != nil {
			t.Fatalf("payload %d: writeSingleFrame: %v", tc.n, err)
		}
		raw := buf.Bytes()

		length := int(binary.BigEndian.Uint32(raw[0:4]))
		pad := int(binary.BigEndian.Uint16(raw[4:6]))
		if length != tc.n {
			t.Fatalf("payload %d: header length = %d", tc.n, length)
		}
		if len(raw) != 6+pad+length {
			t.Fatalf("payload %d: frame is %d bytes but the header declares %d pad + %d payload", tc.n, len(raw), pad, length)
		}
		if tc.padded {
			if total := length + pad; total < tc.band.min || total > tc.band.max {
				t.Fatalf("payload %d landed at %d, outside its band [%d,%d]", tc.n, total, tc.band.min, tc.band.max)
			}
		} else if pad != 0 {
			t.Fatalf("payload %d is past the last threshold but the frame carries %d pad bytes", tc.n, pad)
		}

		// The pad is transparent to the reader whatever the band.
		reader := newXHTTPConn(bytes.NewReader(raw), io.Discard, func() error { return nil }, nil, nil, nil)
		got := make([]byte, tc.n)
		if tc.n > 0 {
			if _, err := io.ReadFull(reader, got); err != nil {
				t.Fatalf("payload %d: read back: %v", tc.n, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload %d corrupted by padding", tc.n)
			}
		}
	}
}

// TestPaddingComplexRulesOnTheStreamWire covers the other framing: the 22-byte
// streaming envelope shares the policy, including the close marker whose length
// field is the marker itself.
func TestPaddingComplexRulesOnTheStreamWire(t *testing.T) {
	bands := []paddingBand{
		{below: 1, min: 120, max: 200},
		{below: 64, min: 300, max: 360},
		{below: 400, min: 400, max: 600},
	}
	withPadding(t, "1:120-200,64:300-360,400:400-600")

	for _, n := range []int{0, 1, 63, 64, 399, 400, 1024} {
		payload := bytes.Repeat([]byte{'z'}, n)
		frame, err := streamFrameBytes(7, 11, payload)
		if err != nil {
			t.Fatalf("payload %d: streamFrameBytes: %v", n, err)
		}
		length := int(binary.BigEndian.Uint32(frame[16:20]))
		pad := int(binary.BigEndian.Uint16(frame[20:22]))
		if length != n {
			t.Fatalf("payload %d: envelope length = %d", n, length)
		}
		if len(frame) != 22+pad+length {
			t.Fatalf("payload %d: envelope is %d bytes, header says %d pad + %d payload", n, len(frame), pad, length)
		}
		if b, padded := bandForPayload(bands, n); padded {
			if total := length + pad; total < b.min || total > b.max {
				t.Fatalf("payload %d landed at %d, outside its band [%d,%d]", n, total, b.min, b.max)
			}
		} else if pad != 0 {
			t.Fatalf("payload %d is past the last threshold but carries %d pad bytes", n, pad)
		}

		got, err := readStreamFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("payload %d: readStreamFrame: %v", n, err)
		}
		if got.seq != 7 || got.ack != 11 {
			t.Fatalf("payload %d: envelope metadata %d/%d, want 7/11", n, got.seq, got.ack)
		}
		if !bytes.Equal(got.data, payload) {
			t.Fatalf("payload %d corrupted by padding", n)
		}
	}

	// The close marker is an empty payload, so it takes the control band.
	marker, err := streamCloseFrameBytes(0, 0)
	if err != nil {
		t.Fatalf("streamCloseFrameBytes: %v", err)
	}
	if total := len(marker) - 22; total < bands[0].min || total > bands[0].max {
		t.Fatalf("close marker is %d bytes of payload+pad, outside the control band [%d,%d]", total, bands[0].min, bands[0].max)
	}
	f, err := readStreamFrame(bytes.NewReader(marker))
	if err != nil {
		t.Fatalf("readStreamFrame(close): %v", err)
	}
	if !f.closed {
		t.Fatal("the padded close marker lost its marker")
	}
}

// TestPaddingPadFieldBoundary pins the two-byte field the pad length travels in.
// The largest legal band must survive the round trip byte for byte, and one byte
// more must be refused at parse time. An earlier limit of 90000 let
// "90000:90000-90000" through: the header narrowed the pad to 24456, the reader
// stripped that many bytes, and the application was handed padding as payload.
func TestPaddingPadFieldBoundary(t *testing.T) {
	withPadding(t, "65535:65535-65535")

	payload := bytes.Repeat([]byte("k"), 8)
	var buf bytes.Buffer
	sender := newXHTTPConn(&buf, &buf, func() error { return nil }, nil, nil, nil)
	if err := sender.writeSingleFrame(payload); err != nil {
		t.Fatalf("writeSingleFrame: %v", err)
	}
	raw := buf.Bytes()
	if pad := int(binary.BigEndian.Uint16(raw[4:6])); pad != 65535-len(payload) {
		t.Fatalf("pad field = %d, want %d; the value was narrowed on the wire", pad, 65535-len(payload))
	}
	reader := newXHTTPConn(bytes.NewReader(raw), io.Discard, func() error { return nil }, nil, nil, nil)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("padding leaked into the payload: %q", got)
	}

	// The streaming envelope carries the same field and must honour the same cap.
	frame, err := streamFrameBytes(1, 2, payload)
	if err != nil {
		t.Fatalf("streamFrameBytes: %v", err)
	}
	if pad := int(binary.BigEndian.Uint16(frame[20:22])); pad != 65535-len(payload) {
		t.Fatalf("stream pad field = %d, want %d", pad, 65535-len(payload))
	}
	f, err := readStreamFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readStreamFrame: %v", err)
	}
	if !bytes.Equal(f.data, payload) {
		t.Fatalf("stream payload corrupted: %q", f.data)
	}

	if err := ValidatePadding("65536:65536-65536"); err == nil {
		t.Fatal("a band wider than the header's pad field was accepted")
	}
}

// TestPaddingRulesOverARealSession is the end-to-end half of the complex-rule
// coverage: the rule has to hold through the reliable window, the poll request
// body and the server's reassembly, not just inside a single frame buffer.
func TestPaddingRulesOverARealSession(t *testing.T) {
	t.Run("control and main bands", func(t *testing.T) {
		runPaddedSession(t, "1:120-200,64:300-360,400:400-600", []int{1, 20, 63, 64, 399, 400, 4096, 60000})
	})
	t.Run("pad field ceiling", func(t *testing.T) {
		// Every write becomes a ~64KB frame: this is the shape a rule that
		// covers bulk traffic produces, and it exercises the scratch headroom
		// and the receive-window accounting at the largest legal pad.
		runPaddedSession(t, "65535:65535-65535", []int{1, 4, 40})
	})
}

func runPaddedSession(t *testing.T, spec string, sizes []int) {
	t.Helper()
	withPadding(t, spec)

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
		StreamMode: "poll",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial with padding %q: %v", spec, err)
	}
	defer conn.Close()

	for _, size := range sizes {
		payload := bytes.Repeat([]byte{byte('a' + size%26)}, size)
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("padding %q, size %d: write: %v", spec, size, err)
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("padding %q, size %d: read: %v", spec, size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("padding %q, size %d: payload corrupted through the tunnel", spec, size)
		}
	}
}

// innerFrame is one 6-byte-header frame as it appears on the wire.
type innerFrame struct {
	payload int
	pad     int
	total   int
}

// splitInnerFrames walks a byte stream the way an XHTTPConn reader would,
// returning one entry per frame it finds.
func splitInnerFrames(t *testing.T, wire []byte) []innerFrame {
	t.Helper()
	var frames []innerFrame
	for off := 0; off < len(wire); {
		if off+6 > len(wire) {
			t.Fatalf("truncated frame header at offset %d of %d", off, len(wire))
		}
		payload := int(binary.BigEndian.Uint32(wire[off : off+4]))
		pad := int(binary.BigEndian.Uint16(wire[off+4 : off+6]))
		total := 6 + payload + pad
		if off+total > len(wire) {
			t.Fatalf("frame at offset %d runs past the buffer: total=%d remaining=%d", off, total, len(wire)-off)
		}
		frames = append(frames, innerFrame{payload: payload, pad: pad, total: total})
		off += total
	}
	return frames
}

// TestUDPFrameJoinsLengthAndPayload pins the framing of WriteUDPFrame. The
// tunnel renders one padded frame per Write, so emitting the two-byte length
// separately from the payload used to produce two frames per datagram: a
// 30-byte datagram cost 1038 bytes instead of ~500, and every datagram appeared
// as a pair of 400..600-byte frames — paying twice for the padding while
// handing an observer a shape of its own to key on.
func TestUDPFrameJoinsLengthAndPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 30)
	for _, tc := range []struct {
		name     string
		spec     string
		min, max int
	}{
		{name: "default rule", spec: "400-600", min: 406, max: 606},
		{name: "padding off", spec: "off", min: 38, max: 38},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshotPadding(t)
			if err := SetPadding(tc.spec); err != nil {
				t.Fatalf("set padding %q: %v", tc.spec, err)
			}

			var wire bytes.Buffer
			conn := newXHTTPConn(nil, &wire, nil, nil, nil, nil)
			if err := WriteUDPFrame(conn, payload); err != nil {
				t.Fatalf("write datagram: %v", err)
			}

			frames := splitInnerFrames(t, wire.Bytes())
			if len(frames) != 1 {
				t.Fatalf("a %d-byte datagram took %d frames (%+v), want 1", len(payload), len(frames), frames)
			}
			if frames[0].payload != 2+len(payload) {
				t.Fatalf("frame payload = %d, want the length prefix and the datagram together (%d)", frames[0].payload, 2+len(payload))
			}
			if frames[0].total < tc.min || frames[0].total > tc.max {
				t.Fatalf("frame total = %d, want %d..%d", frames[0].total, tc.min, tc.max)
			}

			// The reader must still strip the pad and hand back the datagram.
			reader := newXHTTPConn(bytes.NewReader(wire.Bytes()), nil, nil, nil, nil, nil)
			got := make([]byte, maxUDPFrameSize)
			n, err := ReadUDPFrameInto(reader, got)
			if err != nil {
				t.Fatalf("read datagram back: %v", err)
			}
			if !bytes.Equal(got[:n], payload) {
				t.Fatalf("datagram corrupted through the frame: got %d bytes, want %d", n, len(payload))
			}
		})
	}
}
