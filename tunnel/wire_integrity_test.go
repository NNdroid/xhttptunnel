package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// wireProxy is a forwarding hop a test can arm. It passes requests and
// responses through untouched until it is told otherwise, at which point it
// starts editing the bytes in flight — which is the case a CDN represents. A
// hop that forwards correctly is not where the wire format is tested.
type wireProxy struct {
	server *httptest.Server
	origin *url.URL

	mu sync.Mutex
	// editRequest / editResponse rewrite the bytes of one direction. Nil
	// means pass through.
	editRequest  func(b []byte) []byte
	editResponse func(b []byte) []byte
	// editRequestHeaders rewrites the headers a request travels under.
	editRequestHeaders func(h http.Header)
	// editResponseHeaders rewrites the headers a response travels under.
	editResponseHeaders func(h http.Header)
	// lastRequest is the biggest request body seen, for a positive control.
	lastRequest []byte
	statuses    []int
	// padHeaders are the pad lengths as they travelled: masked, so an
	// observer holding them holds nothing, and this is what pins that.
	padHeaders []string
	methods    []string
}

func newWireProxy(t *testing.T, originURL *url.URL) *wireProxy {
	t.Helper()
	p := &wireProxy{origin: originURL}
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(PadHeader); v != "" {
			p.mu.Lock()
			p.padHeaders = append(p.padHeaders, v)
			p.mu.Unlock()
		}

		p.mu.Lock()
		method := r.Method
		reqEdit := p.editRequest
		reqHeaderEdit := p.editRequestHeaders
		p.mu.Unlock()

		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			http.Error(w, "proxy read failed", http.StatusBadGateway)
			return
		}
		if reqEdit != nil {
			body = reqEdit(body)
		}
		if reqHeaderEdit != nil {
			reqHeaderEdit(r.Header)
		}

		p.mu.Lock()
		p.methods = append(p.methods, method)
		if len(body) > len(p.lastRequest) {
			p.lastRequest = append([]byte(nil), body...)
		}
		p.mu.Unlock()

		r.RequestURI = ""
		r.URL.Scheme = p.origin.Scheme
		r.URL.Host = p.origin.Host
		r.Host = p.origin.Host
		if len(body) == 0 {
			r.Body = http.NoBody
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		r.GetBody = nil
		r.ContentLength = int64(len(body))

		resp, err := transport.RoundTrip(r)
		if err != nil {
			http.Error(w, "proxy origin unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if v := resp.Header.Get(PadHeader); v != "" {
			p.mu.Lock()
			p.padHeaders = append(p.padHeaders, v)
			p.mu.Unlock()
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "proxy read failed", http.StatusBadGateway)
			return
		}
		p.mu.Lock()
		respEdit := p.editResponse
		respHeaderEdit := p.editResponseHeaders
		p.statuses = append(p.statuses, resp.StatusCode)
		p.mu.Unlock()
		if respEdit != nil {
			got = respEdit(got)
		}
		if respHeaderEdit != nil {
			respHeaderEdit(resp.Header)
		}

		for k, vv := range resp.Header {
			if http.CanonicalHeaderKey(k) == "Content-Length" {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(got)))
		w.WriteHeader(resp.StatusCode)
		w.Write(got)
	}))
	t.Cleanup(p.server.Close)
	return p
}

// flipLast rewrites one byte of a body without changing its length, which is
// the least a middlebox can do to a payload it can parse.
func flipLast(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 0x01
	return out
}

// newWireServer starts an echo server that records the session events it
// emits, so a test can assert on what the server noticed rather than on what
// the client happened to do about it.
func newWireServer(t *testing.T, ctx context.Context, events chan SessionEvent) *url.URL {
	t.Helper()
	const secret = "wire-secret"
	srv, err := NewServer(ServerConfig{
		Listen: "tcp://127.0.0.1:0",
		Path:   "/stream",
		PSK:    secret,
		EventHandler: func(ev SessionEvent) {
			select {
			case events <- ev:
			default:
			}
		},
		Handler: func(conn *XHTTPConn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("server did not bind in time")
	}
	u, _ := url.Parse("http://" + srv.Addr().String() + "/stream")
	return u
}

// wireDial opens a tunnel through a proxy that fronts an origin.
func wireDial(t *testing.T, ctx context.Context, p *wireProxy) net.Conn {
	t.Helper()
	u, err := url.Parse(p.server.URL + "/stream")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := DialXHTTP(ctx, u, &DialConfig{
		Password:   "wire-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll",
	}, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// waitForEvent pulls events until the wanted kind arrives or the deadline
// passes.
func waitForEvent(t *testing.T, events chan SessionEvent, kind string, d time.Duration) SessionEvent {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-events:
			if ev.Kind() == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %q event within %v", kind, d)
			return nil
		}
	}
}

// TestPollPadLengthTravelsMasked pins the shape the pad length has on the
// wire. It used to be a plaintext byte count, which turned a padded body into
// an exact statement of the payload inside it: Content-Length less X-Pad is
// the payload, to anyone reading the wire. It now travels under the same
// per-request keystream as the counters, so what an observer can read says
// nothing, and what a hop can alter is verified against the signature.
func TestPollPadLengthTravelsMasked(t *testing.T) {
	const secret = "pad-mask-secret"
	const plain = 512
	distinct := map[string]bool{}
	for i := 0; i < 64; i++ {
		nonce, err := newAuthNonce()
		if err != nil {
			t.Fatalf("newAuthNonce: %v", err)
		}
		wire := strconv.Itoa(int(maskU16(plain, maskFor(reqMaskDomain, secret, nonce), 16)))
		if wire == strconv.Itoa(plain) {
			t.Fatalf("draw %d left the pad length in the clear", i)
		}
		distinct[wire] = true
	}
	// One pad length, many wire values. The observer sees the nonce and the
	// value together, and there is no dictionary to build from it.
	if len(distinct) < 8 {
		t.Fatalf("64 draws of one pad length produced %d wire values: they are not being masked", len(distinct))
	}

	// And it still round-trips for the holder of the key.
	nonce, err := newAuthNonce()
	if err != nil {
		t.Fatalf("newAuthNonce: %v", err)
	}
	m := maskFor(reqMaskDomain, secret, nonce)
	_, _, got, err := decodeCounters(m, counters{pad: strconv.Itoa(int(maskU16(plain, m, 16)))})
	if err != nil {
		t.Fatalf("decodeCounters: %v", err)
	}
	if got != plain {
		t.Fatalf("recovered pad length %d, want %d", got, plain)
	}
}

// TestPollPadReaderDropsExactlyThePad is the reading half: the length is a
// known one, so the reader drops that many bytes and no more, and a length the
// body cannot carry is refused rather than read as far as it goes.
func TestPollPadReaderDropsExactlyThePad(t *testing.T) {
	snapshotPadding(t)
	if err := SetPadding("400-600"); err != nil {
		t.Fatal(err)
	}

	frames := make([]byte, 6+20)
	binary.BigEndian.PutUint32(frames[0:4], 20)
	binary.BigEndian.PutUint16(frames[4:6], 0)
	copy(frames[6:], bytes.Repeat([]byte{0x5a}, 20))

	padded, pad, err := padPollBody(frames)
	if err != nil {
		t.Fatalf("padPollBody: %v", err)
	}
	if total := len(padded); total < 400 || total > 600 {
		t.Fatalf("padded body is %d bytes, want 400..600", total)
	}
	if pad < 2 {
		t.Fatalf("pad is %d bytes, want at least 2", pad)
	}

	t.Run("buffered", func(t *testing.T) {
		got, err := splitPollBody(padded, pad)
		if err != nil {
			t.Fatalf("splitPollBody: %v", err)
		}
		if !bytes.Equal(got, frames) {
			t.Fatalf("kept %d bytes after the pad, want the %d frame bytes", len(got), len(frames))
		}
	})

	t.Run("streamed", func(t *testing.T) {
		r, err := skipPollPad(bytes.NewReader(padded), pad)
		if err != nil {
			t.Fatalf("skipPollPad: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, frames) {
			t.Fatalf("read %d bytes, want the %d frame bytes", len(got), len(frames))
		}
	})

	t.Run("longer than the body", func(t *testing.T) {
		if _, err := splitPollBody(padded, len(padded)+1); err == nil {
			t.Fatal("a pad longer than the body was accepted")
		}
	})

	t.Run("longer than its field", func(t *testing.T) {
		// A length the 2-byte pad field cannot hold. It is refused here
		// rather than being folded into a smaller number of skipped bytes.
		if _, err := splitPollBody(padded, maxPaddingTotal+1); err == nil {
			t.Fatal("a pad longer than the field width was accepted")
		}
		if _, err := skipPollPad(bytes.NewReader(padded), maxPaddingTotal+1); err == nil {
			t.Fatal("a pad longer than the field width was skipped")
		}
	})
}

// TestSignedRequestWithRewrittenBodyIsRefused pins the uplink half of the
// body signature: a hop that changes a byte the sender signed is refused, and
// the refusal is visible to the operator instead of reaching the application
// as a corrupt stream.
func TestSignedRequestWithRewrittenBodyIsRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	p := newWireProxy(t, newWireServer(t, ctx, events))
	conn := wireDial(t, ctx, p)
	defer conn.Close()

	// Arm the hop only after the session is up, so the failure is about the
	// bytes and not about the handshake.
	p.mu.Lock()
	p.editRequest = flipLast
	p.mu.Unlock()

	if _, err := conn.Write(bytes.Repeat([]byte{0x5a}, 64)); err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := waitForEvent(t, events, BodyTampered{}.Kind(), 10*time.Second)
	bt, ok := ev.(BodyTampered)
	if !ok {
		t.Fatalf("event is %T, want BodyTampered", ev)
	}
	if bt.Bytes == 0 {
		t.Fatal("the tampered request carried no body, so this proved nothing")
	}

	// And the origin said no rather than reassembling the bytes. The hop
	// records a status only once it has drained the response behind it,
	// which is after the origin has already emitted the event this woke on —
	// so the refusal is waited for rather than read at once.
	if !eventually(5*time.Second, func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, s := range p.statuses {
			if s == http.StatusBadRequest {
				return true
			}
		}
		return false
	}) {
		p.mu.Lock()
		statuses := append([]int(nil), p.statuses...)
		p.mu.Unlock()
		t.Fatalf("the origin never refused: statuses %v", statuses)
	}
}

// eventually polls until want holds or the deadline passes.
func eventually(d time.Duration, want func() bool) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); {
		if want() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestSignedResponseWithRewrittenBodyKillsTheTunnel is the downlink half. A
// tunnelled application receives this direction, so a hop that rewrites it is
// rewriting what the application reads. The session has to end instead.
func TestSignedResponseWithRewrittenBodyKillsTheTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	p := newWireProxy(t, newWireServer(t, ctx, events))
	conn := wireDial(t, ctx, p)
	defer conn.Close()

	payload := bytes.Repeat([]byte{0x5a}, 64)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readFullBefore(conn, len(payload), 10*time.Second); err != nil {
		t.Fatalf("a clean round trip before the hop is armed: %v", err)
	}

	p.mu.Lock()
	p.editResponse = flipLast
	p.mu.Unlock()

	if _, err := conn.Write(bytes.Repeat([]byte{0x77}, 64)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The rewritten response must not reach the application as data. Either
	// the session ends or the read keeps failing: both are the correct
	// answer, and a whole payload arriving is not.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(make([]byte, 64))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n > 0 {
			t.Fatal("a response the hop rewrote was delivered as data")
		}
	}
	t.Fatal("the tunnel kept serving data after its responses were rewritten")
}

// TestSignedCountersCannotBeRewritten pins that the counters are inside the
// trust boundary. They say where a body sits in the stream, so a hop that
// moved them used to be able to shift the ring's idea of what it had — and
// the request still authenticated, because they were not signed.
func TestSignedCountersCannotBeRewritten(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	p := newWireProxy(t, newWireServer(t, ctx, events))

	// Rewrite the counters in the form they travel, which is the masked one.
	// The hop cannot know the mask, and it does not need to: any change to
	// the header breaks the signature over the header as it stands.
	p.mu.Lock()
	p.editRequestHeaders = func(h http.Header) {
		for _, name := range []string{"X-Seq", "X-Ack"} {
			v := h.Get(name)
			if v == "" {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			h.Set(name, strconv.FormatUint(n+1, 10))
		}
	}
	p.mu.Unlock()

	conn := wireDial(t, ctx, p)
	defer conn.Close()

	if _, err := conn.Write(bytes.Repeat([]byte{0x5a}, 64)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// A rewritten counter breaks the credential, not the body digest: this is
	// an authentication rejection.
	waitForEvent(t, events, AuthRejected{}.Kind(), 10*time.Second)
}

// TestSignedPadLengthCannotBeMovedOnTheWire pins the uplink half of the pad
// work. The length says where a poll body's payload starts, so it is the one
// number in the envelope a hop can move to make the reader skip a different
// number of bytes than the writer prefixed — and a hop that deletes it also
// removes the request's credentials, because the pad is inside the signed
// message. Neither hop needs the key: the pad travels masked, but any change
// to the header breaks the signature over the header as it stands.
func TestSignedPadLengthCannotBeMovedOnTheWire(t *testing.T) {
	bumpPad := func(h http.Header) {
		v := h.Get(PadHeader)
		if v == "" {
			return
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return
		}
		h.Set(PadHeader, strconv.FormatUint((n+1)%65536, 10))
	}
	for _, tc := range []struct {
		name string
		edit func(h http.Header)
	}{
		// A CDN that forwards only the headers it knows about.
		{"stripped", func(h http.Header) { h.Del(PadHeader) }},
		// A hop that moves the boundary by one byte: the padding then ends
		// somewhere other than where the writer put its first frame.
		{"rewritten", bumpPad},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			events := make(chan SessionEvent, 64)
			p := newWireProxy(t, newWireServer(t, ctx, events))
			p.mu.Lock()
			p.editRequestHeaders = tc.edit
			p.mu.Unlock()

			conn := wireDial(t, ctx, p)
			defer conn.Close()

			if _, err := conn.Write(bytes.Repeat([]byte{0x5a}, 64)); err != nil {
				t.Fatalf("write: %v", err)
			}

			// The request stops being one this PSK signed, which is the
			// strongest thing the pad could be inside: a hop cannot move the
			// boundary without also losing the credential.
			waitForEvent(t, events, AuthRejected{}.Kind(), 10*time.Second)
			if !eventually(5*time.Second, func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				for _, s := range p.statuses {
					if s == http.StatusProxyAuthRequired {
						return true
					}
				}
				return false
			}) {
				p.mu.Lock()
				statuses := append([]int(nil), p.statuses...)
				p.mu.Unlock()
				t.Fatalf("the origin never refused the credentials: statuses %v", statuses)
			}
		})
	}
}

// TestSignedRequestThatStatesNoPadIsRefused is the other half of the same rule,
// and the reason the rule exists at all. A missing pad length is not a pad of
// zero: it is a statement the sender did not make, and reading it as zero is
// what hands the padding to the reassembly as payload. This request holds the
// PSK and is signed correctly — including over an absent pad — so it is the
// strongest client the guard is there for, and the one a signature check
// cannot catch.
func TestSignedRequestThatStatesNoPadIsRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const secret = "wire-secret"
	events := make(chan SessionEvent, 64)
	origin := newWireServer(t, ctx, events)

	// A body of nothing but pad: the shape whose payload length is zero, and
	// therefore the one a missing pad length would turn into 200+ bytes of
	// padding delivered as data.
	snapshotPadding(t)
	if err := SetPadding("200-400"); err != nil {
		t.Fatal(err)
	}
	padded, pad, err := padPollBody(nil)
	if err != nil {
		t.Fatalf("padPollBody: %v", err)
	}
	if pad < 200 {
		t.Fatalf("the draw produced a pad of %d bytes, too small for this to mean anything", pad)
	}

	nonce, err := newAuthNonce()
	if err != nil {
		t.Fatalf("newAuthNonce: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, origin.String(), bytes.NewReader(padded))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(padded))
	req.Header.Set(ProtoHeader, strconv.Itoa(offeredProtoVersion))
	req.Header.Set("X-Target", "127.0.0.1:9")
	req.Header.Set("X-Network", "tcp")
	req.Header.Set("X-Session-ID", strings.Repeat("ab", 16))
	req.Header.Set(AuthNonceHeader, nonce)

	// Everything else in the message is what the sender really means, and the
	// pad is the one field it leaves unsaid.
	a := requestAuth{
		sessionID: req.Header.Get("X-Session-ID"),
		network:   "tcp",
		target:    "127.0.0.1:9",
		method:    http.MethodPost,
		proto:     offeredProtoVersion,
		bodyKind:  bodyKindPoll,
		body:      padded,
	}
	wire := counters{}
	req.Header.Set(AuthMACHeader, authMAC(secret, v3Message(nonce, a, wire)))
	digest := sha256.Sum256(padded)
	req.Header.Set(AuthBodyMACHeader, bodyMAC(secret, nonce, &digest))

	resp, err := (&http.Transport{}).RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	// Refused, and not authenticated: a 407 would mean the signature was
	// what caught it, which it cannot be here.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a request that left its pad unsaid was admitted", resp.StatusCode)
	}
}

// TestSignedResponseWithoutItsPadLengthKillsTheTunnel is the downlink half.
// The response is the direction a tunnelled application reads, so a hop that
// removes its pad length leaves bytes this side cannot place: reading them as
// carrying no pad would hand the padding to the reassembly as payload, and
// the digest cannot be checked against a length that is not there. The
// session has to end instead.
func TestSignedResponseWithoutItsPadLengthKillsTheTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	p := newWireProxy(t, newWireServer(t, ctx, events))
	conn := wireDial(t, ctx, p)
	defer conn.Close()

	payload := bytes.Repeat([]byte{0x5a}, 64)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readFullBefore(conn, len(payload), 10*time.Second); err != nil {
		t.Fatalf("a clean round trip before the hop is armed: %v", err)
	}

	p.mu.Lock()
	p.editResponseHeaders = func(h http.Header) { h.Del(PadHeader) }
	p.mu.Unlock()

	if _, err := conn.Write(bytes.Repeat([]byte{0x77}, 64)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A response whose pad length was dropped must not reach the application
	// as data. Either the session ends or the read keeps failing: both are
	// the correct answer, and a whole payload arriving is not.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(make([]byte, 64))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n > 0 {
			t.Fatal("a response the hop stripped the pad length from was delivered as data")
		}
	}
	t.Fatal("the tunnel kept serving data after its responses lost their pad length")
}

// TestIdlePollsArePostRatherThanGet pins the request-shape half of the
// padding work. An idle poll used to be a GET, and that was readable from a
// long way off: the method differed from every other request in the session,
// and it carried a body of zero bytes — the one size no padding rule can
// smooth, because there was nothing there to pad.
func TestIdlePollsArePostRatherThanGet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	p := newWireProxy(t, newWireServer(t, ctx, events))
	conn := wireDial(t, ctx, p)
	defer conn.Close()

	// One clean round trip, then leave it alone: the pump keeps an idle
	// poller parked, so the session goes on issuing requests with nothing to
	// send.
	payload := bytes.Repeat([]byte{0x5a}, 64)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readFullBefore(conn, len(payload), 10*time.Second); err != nil {
		t.Fatalf("read: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	p.mu.Lock()
	methods := append([]string(nil), p.methods...)
	p.mu.Unlock()
	if len(methods) < 3 {
		t.Fatalf("the hop saw %d requests, too few to include an idle one", len(methods))
	}
	for i, m := range methods {
		if m != http.MethodPost {
			t.Fatalf("request %d is a %s: an idle poll must look like every other request, and the tunnel has no GET left to send", i, m)
		}
	}
}

// TestPadLengthOnTheWireIsUnreadableWithoutTheKey pins the observable half of
// the same property, from outside the session: the header is there, and it says
// nothing. The pad length is what would let an observer subtract it from
// Content-Length and learn the payload exactly.
func TestPadLengthOnTheWireIsUnreadableWithoutTheKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	p := newWireProxy(t, newWireServer(t, ctx, events))
	conn := wireDial(t, ctx, p)
	defer conn.Close()

	payload := bytes.Repeat([]byte{0x5a}, 256)
	for i := 0; i < 3; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := readFullBefore(conn, len(payload), 10*time.Second); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}

	p.mu.Lock()
	values := append([]string(nil), p.padHeaders...)
	p.mu.Unlock()
	if len(values) < 4 {
		t.Fatalf("the hop saw %d pad lengths, too few to say anything about them", len(values))
	}
	distinct := map[string]bool{}
	for _, v := range values {
		distinct[v] = true
	}
	// The same pad length would produce the same plaintext every time. What an
	// observer sees instead is a different value per request, because the
	// keystream is drawn per nonce.
	if len(distinct) < 4 {
		t.Fatalf("%d requests carried %d distinct pad lengths: the value is readable", len(values), len(distinct))
	}
	for _, v := range values {
		if v == "" {
			t.Fatal("a pad length travelled as an empty header: it is in the clear")
		}
	}
}
