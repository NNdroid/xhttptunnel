package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordedBody is one body a forwarding proxy saw, in one direction.
type recordedBody struct {
	method  string
	status  int
	body    []byte
	pad     int
	isReply bool
}

// bodyRecorder forwards to an origin and keeps a copy of every body it sees.
// It buffers instead of streaming, which is safe for what it is used on: poll
// bodies are Content-Length bounded and complete before the handler runs.
type bodyRecorder struct {
	server *httptest.Server
	origin *url.URL

	// stripCaps makes the proxy drop the capability header from responses, the
	// way a middlebox that does not understand it would. The bodies pass
	// through untouched.
	stripCaps atomic.Bool
	// stripRequestCaps does the same to requests, one direction only: the
	// origin never learns the client can read a padded body, so it must not
	// answer as if it had. The bodies pass through untouched, which is the
	// dangerous half of the case — the capability can be lost while the bytes
	// that depend on it are not.
	stripRequestCaps atomic.Bool
	// psk lets the recorder read the masked pad length, the way its owner
	// does and the way an observer cannot.
	psk string

	mu     sync.Mutex
	bodies []recordedBody
}

// padSecret is the PSK the padding scenarios share. The recorder holds it so it
// can read the pad length off the wire the way its owner does: the count
// travels masked, which is the point, so a hop or an observer cannot read it.
const padSecret = "pad-secret"

// unmaskPadLen recovers the pad length a request or response travelled with.
// With no key it is the plaintext value, which is what a peer that never
// negotiated a PSK sends.
func unmaskPadLen(psk, nonce, direction, wire string) int {
	if wire == "" {
		return 0
	}
	n, err := strconv.Atoi(wire)
	if err != nil {
		return 0
	}
	if psk == "" || nonce == "" {
		return n
	}
	return int(maskU16(n, maskFor(direction, psk, nonce), 16))
}

func newBodyRecorder(t *testing.T, originURL *url.URL) *bodyRecorder {
	t.Helper()
	rec := &bodyRecorder{origin: originURL, psk: padSecret}
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "proxy read failed", http.StatusBadGateway)
			return
		}
		r.Body.Close()
		reqNonce := r.Header.Get(AuthNonceHeader)
		if len(sent) > 0 {
			// The pad's length travels masked, so it is read the way its
			// owner reads it and not the way an observer would: the recorder
			// holds the key, which is the only thing that makes the header
			// say anything at all.
			pad := unmaskPadLen(rec.psk, r.Header.Get(AuthNonceHeader), reqMaskDomain, r.Header.Get(PadHeader))
			rec.record(recordedBody{method: r.Method, body: sent, pad: pad})
		}

		if rec.stripRequestCaps.Load() {
			r.Header.Del(CapsHeader)
		}

		r.RequestURI = ""
		r.URL.Scheme = rec.origin.Scheme
		r.URL.Host = rec.origin.Host
		r.Host = rec.origin.Host
		// NoBody for an empty body, so the forwarded request still travels
		// with a Content-Length it can name: a tunnel request signed over an
		// unstated length is refused, and the hop in the middle is not where
		// that rule should bite.
		if len(sent) == 0 {
			r.Body = http.NoBody
		} else {
			r.Body = io.NopCloser(bytes.NewReader(sent))
		}
		r.GetBody = nil
		r.ContentLength = int64(len(sent))

		resp, err := transport.RoundTrip(r)
		if err != nil {
			http.Error(w, "proxy origin unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "proxy read failed", http.StatusBadGateway)
			return
		}
		if len(got) > 0 {
			respPad := unmaskPadLen(rec.psk, reqNonce, respMaskDomain, resp.Header.Get(PadHeader))
			rec.record(recordedBody{status: resp.StatusCode, body: got, pad: respPad, isReply: true})
		}
		for k, vv := range resp.Header {
			switch http.CanonicalHeaderKey(k) {
			case "Content-Length":
				continue
			case http.CanonicalHeaderKey(CapsHeader):
				if rec.stripCaps.Load() {
					continue
				}
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(got)))
		w.WriteHeader(resp.StatusCode)
		w.Write(got)
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

func (r *bodyRecorder) record(b recordedBody) {
	r.mu.Lock()
	r.bodies = append(r.bodies, b)
	r.mu.Unlock()
}

// mark returns a position in the recorded stream, so a test can ask what
// happened after a particular moment rather than searching the whole run.
func (r *bodyRecorder) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// recordedSince returns everything recorded at or after a mark.
func (r *bodyRecorder) recordedSince(mark int) []recordedBody {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mark > len(r.bodies) {
		mark = len(r.bodies)
	}
	out := make([]recordedBody, len(r.bodies)-mark)
	copy(out, r.bodies[mark:])
	return out
}

func (r *bodyRecorder) snapshot() (sent, replies []recordedBody) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.bodies {
		if b.isReply {
			replies = append(replies, b)
			continue
		}
		sent = append(sent, b)
	}
	return sent, replies
}

// TestPollBodiesArePaddedOnTheWire covers both halves of poll-body padding, as
// an intermediary sees them.
//
// A poll body is a run of session frames, so the compatible shape — what a
// mixed-version pair produces — is a run of frames the frame layer padded. That
// is the only pad an old peer understands.
//
// Once the client has seen the server echo CapPadBody, padding moves out of the
// frame and onto the body: the frames in the ring go out bare (six-byte headers,
// so the send window carries payload instead of padding) and the body grows a
// leading pad announced by X-Pad, whose total still lands inside the band. The
// assertion that matters is that the two never stack — a body with an X-Pad must
// contain only unpadded frames.
func TestPollBodiesArePaddedOnTheWire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snapshotPadding(t)
	if err := SetPadding("400-600"); err != nil {
		t.Fatal(err)
	}

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pad-secret", "", "", "")
	if err != nil {
		t.Fatalf("start origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	originURL, err := url.Parse("http://" + origin.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("parse origin URL: %v", err)
	}
	rec := newBodyRecorder(t, originURL)

	serverURL, err := url.Parse(rec.server.URL + "/stream")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password:   "pad-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte{0x77}, 20)
	for i := 0; i < 4; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got, err := readFullBefore(conn, len(payload), 20*time.Second)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round %d: payload corrupted through the poll body", i)
		}
	}

	sent, replies := rec.snapshot()
	if len(sent) == 0 {
		t.Fatal("the proxy saw no request bodies")
	}
	if len(replies) == 0 {
		t.Fatal("the proxy saw no response bodies")
	}

	// Each body has to be either a run of frames the frame rule already shaped,
	// or a padded body whose frames are bare. Never both on the same object.
	sawBodyPad := false
	check := func(dir string, b recordedBody) {
		t.Helper()
		body := b.body
		if b.pad > 0 {
			sawBodyPad = true
			if b.pad > len(body) {
				t.Fatalf("%s: declared pad %d exceeds the %d-byte body", dir, b.pad, len(body))
			}
			if total := len(body); total < 400 || total > 600 {
				t.Fatalf("%s: padded body is %d bytes, want 400..600", dir, total)
			}
			body = body[b.pad:]
		}
		for i, f := range splitInnerFrames(t, body) {
			if f.payload != len(payload) {
				t.Fatalf("%s frame %d: payloadLen=%d, want %d — the body is not a run of data frames", dir, i, f.payload, len(payload))
			}
			switch {
			case b.pad > 0 && f.pad != 0:
				t.Fatalf("%s frame %d: frame pad of %d sits on top of a padded body; the pad must be applied once", dir, i, f.pad)
			case b.pad == 0 && (f.total < 400 || f.total > 600):
				t.Fatalf("%s frame %d: total=%d (pad=%d), want 400..600 when the frame layer owns the pad", dir, i, f.total, f.pad)
			}
		}
	}
	for _, b := range sent {
		check("poll POST", b)
	}
	for _, b := range replies {
		check("poll response", b)
	}
	if !sawBodyPad {
		t.Fatal("no body carried X-Pad: the capability never took effect, so padding stayed in the frame layer and every body is a frame taller than the band")
	}
}

// TestPollPaddingFollowsThePeerRatherThanLatching pins the lifetime of the
// capability. Padding a request body is only safe while the peer that will read
// it honours X-Pad, and a session outlives any one response: a fleet mid-upgrade
// mixes builds, so an echo from one node says nothing about the next. Latching
// on the first echo would keep prefixing bodies after the peer stopped
// advertising, and those bytes land in the origin's reassembly as payload —
// silent corruption, not a shape change.
//
// The proxy here drops the capability from responses while leaving the bodies
// and their X-Pad alone. The client has to notice and go back to padding in the
// frame, which every peer can read.
func TestPollPaddingFollowsThePeerRatherThanLatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snapshotPadding(t)
	if err := SetPadding("400-600"); err != nil {
		t.Fatal(err)
	}

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pad-secret", "", "", "")
	if err != nil {
		t.Fatalf("start origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	originURL, err := url.Parse("http://" + origin.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("parse origin URL: %v", err)
	}
	rec := newBodyRecorder(t, originURL)

	serverURL, err := url.Parse(rec.server.URL + "/stream")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password:   "pad-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte{0x33}, 20)
	round := func(tag string) {
		t.Helper()
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("%s: write: %v", tag, err)
		}
		got, err := readFullBefore(conn, len(payload), 20*time.Second)
		if err != nil {
			t.Fatalf("%s: read: %v", tag, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: payload corrupted", tag)
		}
	}

	// Settle the negotiation: two rounds are enough for the client to have seen
	// the echo and switched its bodies over.
	for i := 0; i < 2; i++ {
		round("negotiated")
	}

	rec.stripCaps.Store(true)
	mark := rec.mark()
	for i := 0; i < 4; i++ {
		round("after the strip")
	}

	// The bodies already in flight when the capability disappeared were built
	// before the answer arrived — some from frames written while the frame layer
	// was still leaving the pad to the transport — so a couple of them are
	// expected to carry the old shape. What must not happen is staying there:
	// every body built after the client has seen an answer without the
	// capability has to carry its pad in the frame again.
	//
	// The two shapes are measured differently on purpose: a padded body is the
	// wire object, so the band applies to len(body); a bare body is a run of
	// frames the frame layer padded, so the band applies to each frame.
	const inFlight = 2
	var requests, fromTransport, fromFrame int
	for _, b := range rec.recordedSince(mark) {
		if b.isReply {
			continue
		}
		requests++
		body := b.body
		if b.pad > 0 {
			body = body[b.pad:]
			if total := len(b.body); total < 400 || total > 600 {
				t.Fatalf("padded body is %d bytes, want 400..600", total)
			}
		}
		if b.pad == len(b.body) {
			// An idle poll: all pad, no frames. Its pad is still the
			// transport's, so it belongs to the shape being counted here even
			// though there is nothing inside it to measure.
			fromTransport++
			continue
		}
		frames := splitInnerFrames(t, body)
		if len(frames) == 0 {
			t.Fatalf("body %d holds no frame: len=%d pad=%d", requests, len(b.body), b.pad)
		}
		framePadded := true
		for _, f := range frames {
			if f.pad == 0 {
				framePadded = false
			}
		}
		if framePadded {
			fromFrame++
			for _, f := range frames {
				if f.total < 400 || f.total > 600 {
					t.Fatalf("frame total %d, want 400..600 when the frame layer owns the pad", f.total)
				}
			}
		} else {
			fromTransport++
		}
	}
	if requests < 4 {
		t.Fatalf("only %d request bodies after the strip, need enough to see the decision change", requests)
	}
	if fromTransport > inFlight {
		t.Fatalf("%d of %d bodies after the strip still carried the transport's shape: the client latched on the first echo instead of following the peer", fromTransport, requests)
	}
	if fromFrame < 2 {
		t.Fatalf("only %d of %d bodies went back to frame-level padding after the capability disappeared", fromFrame, requests)
	}
}

// TestPollPaddingFailsClosedWhenTheRequestHeaderIsStripped pins the other half
// of the negotiation: the capability has to survive the path before either side
// acts on it.
//
// The proxy here drops the header from requests only. The origin therefore never
// learns the client can read a padded body, and must not answer as if it had. If
// it announced pad-body anyway, the client would take that answer as licence to
// prefix its bodies with an X-Pad — on the strength of an answer to a request
// the origin never saw. Data would still line up while the X-Pad itself survives,
// and the moment a middlebox drops that too, the prefix is reassembled as
// payload. Failing the handshake closed leaves both ends on the frame shape,
// which no middlebox can turn into corruption.
func TestPollPaddingFailsClosedWhenTheRequestHeaderIsStripped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snapshotPadding(t)
	if err := SetPadding("400-600"); err != nil {
		t.Fatal(err)
	}

	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	origin, err := ListenXHTTP(ctx, "127.0.0.1:0", "/stream", "pad-secret", "", "", "")
	if err != nil {
		t.Fatalf("start origin: %v", err)
	}
	defer origin.Close()
	serveAcceptedTCPEcho(t, ctx, origin)

	originURL, err := url.Parse("http://" + origin.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("parse origin URL: %v", err)
	}
	rec := newBodyRecorder(t, originURL)
	// Stripped from the first request, so there is never a window in which the
	// ends agree and then forget.
	rec.stripRequestCaps.Store(true)

	serverURL, err := url.Parse(rec.server.URL + "/stream")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Password:   "pad-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll",
	}, echoAddr, "tcp")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte{0x5a}, 20)
	for i := 0; i < 4; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("round %d: write: %v", i, err)
		}
		got, err := readFullBefore(conn, len(payload), 20*time.Second)
		if err != nil {
			t.Fatalf("round %d: read: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round %d: payload corrupted", i)
		}
	}

	sent, replies := rec.snapshot()
	if len(sent) < 2 {
		t.Fatalf("the proxy saw %d request bodies, need several rounds of them", len(sent))
	}
	for i, b := range sent {
		if b.pad != 0 {
			t.Fatalf("request body %d declares X-Pad=%d although the origin never received the announcement; the handshake has to fail closed", i, b.pad)
		}
		frames := splitInnerFrames(t, b.body)
		if len(frames) == 0 {
			t.Fatalf("request body %d holds no frame", i)
		}
		for j, f := range frames {
			if f.pad == 0 || f.total < 400 || f.total > 600 {
				t.Fatalf("request body %d frame %d: total=%d pad=%d, want the frame layer's 400..600 when the transport pad is not in force", i, j, f.total, f.pad)
			}
		}
	}
	for i, b := range replies {
		if b.pad != 0 {
			t.Fatalf("response body %d declares X-Pad=%d although this client never announced pad-body", i, b.pad)
		}
	}
}
