package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// withPadding installs a rule for the duration of the test. Padding is
// process-wide state, so every test that touches it must restore it or it
// silently reshapes the frames of everything that runs afterwards.
func withPadding(t *testing.T, spec string) {
	t.Helper()
	prev := PaddingSpec()
	if err := SetPadding(spec); err != nil {
		t.Fatalf("SetPadding(%q): %v", spec, err)
	}
	t.Cleanup(func() {
		if err := SetPadding(prev); err != nil {
			t.Fatalf("restore padding %q: %v", prev, err)
		}
	})
}

func TestPaddingSpecParsesBands(t *testing.T) {
	cases := []struct {
		spec  string
		bands []paddingBand
		label string
	}{
		{"400-600", []paddingBand{{below: 400, min: 400, max: 600}}, "400:400-600"},
		{" 400 - 600 ", []paddingBand{{below: 400, min: 400, max: 600}}, "400:400-600"},
		{"512:600-1199", []paddingBand{{below: 512, min: 600, max: 1199}}, "512:600-1199"},
		{"1:120-200,400:400-600", []paddingBand{
			{below: 1, min: 120, max: 200},
			{below: 400, min: 400, max: 600},
		}, "1:120-200,400:400-600"},
		// A single-size band is legal: every short payload is padded to
		// exactly that length. Useless for privacy, but valid.
		{"400-400", []paddingBand{{below: 400, min: 400, max: 400}}, "400:400-400"},
	}
	for _, tc := range cases {
		p, err := parsePaddingSpec(tc.spec)
		if err != nil {
			t.Errorf("parsePaddingSpec(%q): %v", tc.spec, err)
			continue
		}
		if len(p.bands) != len(tc.bands) {
			t.Errorf("%q compiled to %d bands, want %d", tc.spec, len(p.bands), len(tc.bands))
			continue
		}
		for i := range tc.bands {
			if p.bands[i] != tc.bands[i] {
				t.Errorf("%q band %d = %+v, want %+v", tc.spec, i, p.bands[i], tc.bands[i])
			}
		}
		if p.spec != tc.label {
			t.Errorf("%q normalised to %q, want %q", tc.spec, p.spec, tc.label)
		}
	}
}

func TestPaddingSpecKeywords(t *testing.T) {
	for _, spec := range []string{"", "auto", "AUTO", "default", "  "} {
		p, err := parsePaddingSpec(spec)
		if err != nil {
			t.Fatalf("parsePaddingSpec(%q): %v", spec, err)
		}
		if p.spec != "400:400-600" {
			t.Errorf("%q resolved to %q, want the built-in 400:400-600", spec, p.spec)
		}
	}
	for _, spec := range []string{"off", "OFF", " none "} {
		p, err := parsePaddingSpec(spec)
		if err != nil {
			t.Fatalf("parsePaddingSpec(%q): %v", spec, err)
		}
		if p.spec != "off" || len(p.bands) != 0 {
			t.Errorf("%q resolved to %q with %d bands, want off", spec, p.spec, len(p.bands))
		}
	}
}

// TestPaddingSpecRejects covers the specs a typo can produce. The
// threshold-1 rule matters most: without it a band's largest payload already
// exceeds the target, the pad goes negative, and the frame buffer is sliced
// backwards on the very next write.
func TestPaddingSpecRejects(t *testing.T) {
	cases := map[string]string{
		"400":                         "not MIN-MAX",
		"400-":                        "unreadable upper bound",
		"-600":                        "unreadable lower bound",
		"+400-600":                    "not a byte count",
		"0-600":                       "at least 1",
		"600-400":                     "inverted",
		"0:400-600":                   "threshold must be at least 1",
		"400:200-600":                 "pad would go negative",
		"400-600,300:400-600":         "must be greater than the previous band",
		"400-600,400-600":             "must be greater than the previous band",
		"400-600,,600-800":            "empty band",
		"400-200000":                  "exceeds",
		strings.Repeat("400-600,", 9): "at most",
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

// TestPaddingNeverNegative is the safety property behind every frame write: a
// validated rule can only ever report a non-negative pad. A negative value would
// slice frame[22+pad:] backwards and panic inside the send path.
func TestPaddingNeverNegative(t *testing.T) {
	for _, spec := range []string{"400-600", "1:120-200,400:400-600", "512:600-1199", "off"} {
		p, err := parsePaddingSpec(spec)
		if err != nil {
			t.Fatalf("parsePaddingSpec(%q): %v", spec, err)
		}
		for n := 0; n <= 5000; n++ {
			if pad := p.padLen(n); pad < 0 {
				t.Fatalf("spec %q: padLen(%d) = %d", spec, n, pad)
			}
		}
	}
}

func TestPaddingDefaultShape(t *testing.T) {
	withPadding(t, "")

	for _, n := range []int{0, 1, 20, 100, 399} {
		seen := map[int]bool{}
		for i := 0; i < 4000; i++ {
			pad := padLenFor(n)
			wire := n + pad + 6
			if wire < 400+6 || wire > 600+6 {
				t.Fatalf("payload %d produced a %d-byte frame, outside 406..606", n, wire)
			}
			seen[pad+n] = true
		}
		if len(seen) < 150 {
			t.Errorf("payload %d only reached %d distinct targets, the band should be spread across 400..600", n, len(seen))
		}
	}

	// At and above the band the payload travels as-is: that is the whole point
	// of the threshold, and it is what keeps bulk transfer cheap.
	for _, n := range []int{400, 480, 600, 601, 1024, 256000} {
		if pad := padLenFor(n); pad != 0 {
			t.Errorf("payload %d was padded by %d, want 0", n, pad)
		}
	}
}

// TestPaddingBandOverlap pins the property the default shape is chosen for: the
// unpadded range starts exactly where the band does, so a small padded payload
// and a medium bare payload can leave the same number of bytes on the wire.
func TestPaddingBandOverlap(t *testing.T) {
	withPadding(t, "")

	padded := map[int]bool{}
	for i := 0; i < 4000; i++ {
		padded[padLenFor(0)+6] = true
		padded[padLenFor(399)+399+6] = true
	}
	for n := 400; n <= 600; n++ {
		if !padded[n+6] {
			t.Errorf("a bare %d-byte payload (%d on the wire) is outside the padded band's range", n, n+6)
		}
	}
}

func TestPaddingBandsSelectByThreshold(t *testing.T) {
	withPadding(t, "1:120-200,400:400-600")

	for i := 0; i < 2000; i++ {
		// An empty chunk is a keepalive; it takes the first band.
		if pad := padLenFor(0); pad < 120 || pad > 200 {
			t.Fatalf("empty chunk padded by %d, want 120..200", pad)
		}
		// One byte already falls into the second band.
		if pad := padLenFor(1); pad < 399 || pad > 599 {
			t.Fatalf("1-byte chunk padded by %d, want 399..599", pad)
		}
		if pad := padLenFor(399); pad < 1 || pad > 201 {
			t.Fatalf("399-byte chunk padded by %d, want 1..201", pad)
		}
	}
	if pad := padLenFor(400); pad != 0 {
		t.Fatalf("a 400-byte chunk was padded by %d, want 0", pad)
	}
}

func TestPaddingOff(t *testing.T) {
	withPadding(t, "off")
	for _, n := range []int{0, 1, 400, 1024} {
		if pad := padLenFor(n); pad != 0 {
			t.Errorf("padLen(%d) = %d with padding off", n, pad)
		}
	}

	var buf bytes.Buffer
	c := newXHTTPConn(&buf, &buf, func() error { return nil }, nil, nil, nil)
	if err := c.writeSingleFrame([]byte("hi")); err != nil {
		t.Fatalf("writeSingleFrame: %v", err)
	}
	if got := buf.Len(); got != 6+2 {
		t.Errorf("unpadded frame is %d bytes, want 8", got)
	}
}

// TestFramePaddingRoundTrip proves the pad is transparent: the payload comes
// back byte-identical whatever the rule appends.
func TestFramePaddingRoundTrip(t *testing.T) {
	withPadding(t, "")

	var buf bytes.Buffer
	sender := newXHTTPConn(&buf, &buf, func() error { return nil }, nil, nil, nil)
	payload := bytes.Repeat([]byte("ssh-keepalive"), 3) // 39 bytes, inside the band
	if err := sender.writeSingleFrame(payload); err != nil {
		t.Fatalf("writeSingleFrame: %v", err)
	}
	if buf.Len() < 400+6 || buf.Len() > 600+6 {
		t.Fatalf("frame is %d bytes, outside the padded band", buf.Len())
	}

	reader := newXHTTPConn(&buf, io.Discard, func() error { return nil }, nil, nil, nil)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted by padding: %q", got)
	}
}

// TestCloseFrameIsPadded covers the marker the old code wrote as a bare six
// bytes: the only object of that size on the wire, and therefore an exact
// fingerprint of "a tunnel just closed".
func TestCloseFrameIsPadded(t *testing.T) {
	withPadding(t, "")

	var buf bytes.Buffer
	sender := newXHTTPConn(&buf, &buf, func() error { return nil }, nil, nil, nil)
	if err := sender.WriteCloseFrame(); err != nil {
		t.Fatalf("WriteCloseFrame: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) < 400+6 || len(raw) > 600+6 {
		t.Fatalf("close frame is %d bytes, outside the padded band", len(raw))
	}
	if got := binary.BigEndian.Uint32(raw[0:4]); got != ^uint32(0) {
		t.Fatalf("close frame length field = %#x, want the close marker", got)
	}
	if pad := int(binary.BigEndian.Uint16(raw[4:6])); len(raw) != 6+pad {
		t.Fatalf("close frame is %d bytes but declares %d of padding", len(raw), pad)
	}

	// A reader must still see the marker: it drains the pad first.
	reader := newXHTTPConn(bytes.NewReader(raw), io.Discard, func() error { return nil }, nil, nil, nil)
	if _, err := reader.Read(make([]byte, 8)); err != io.EOF {
		t.Fatalf("reading a padded close frame returned %v, want io.EOF", err)
	}
}

// TestStreamCloseFrameIsPadded checks the streaming variant, which builds its
// marker through the same policy.
func TestStreamCloseFrameIsPadded(t *testing.T) {
	withPadding(t, "")

	frame, err := streamCloseFrameBytes(0, 0)
	if err != nil {
		t.Fatalf("streamCloseFrameBytes: %v", err)
	}
	if len(frame) < 400+22 || len(frame) > 600+22 {
		t.Fatalf("stream close frame is %d bytes, outside the padded band", len(frame))
	}
	f, err := readStreamFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readStreamFrame: %v", err)
	}
	if !f.closed {
		t.Fatal("the padded stream close frame lost its marker")
	}
}
