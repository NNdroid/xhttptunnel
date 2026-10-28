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
	"testing"
	"time"
)

// recordedBody is one body a forwarding proxy saw, in one direction.
type recordedBody struct {
	method  string
	status  int
	body    []byte
	isReply bool
}

// bodyRecorder forwards to an origin and keeps a copy of every body it sees.
// It buffers instead of streaming, which is safe for what it is used on: poll
// bodies are Content-Length bounded and complete before the handler runs.
type bodyRecorder struct {
	server *httptest.Server
	origin *url.URL

	mu     sync.Mutex
	bodies []recordedBody
}

func newBodyRecorder(t *testing.T, originURL *url.URL) *bodyRecorder {
	t.Helper()
	rec := &bodyRecorder{origin: originURL}
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "proxy read failed", http.StatusBadGateway)
			return
		}
		r.Body.Close()
		if len(sent) > 0 {
			rec.record(recordedBody{method: r.Method, body: sent})
		}

		r.RequestURI = ""
		r.URL.Scheme = rec.origin.Scheme
		r.URL.Host = rec.origin.Host
		r.Host = rec.origin.Host
		r.Body = io.NopCloser(bytes.NewReader(sent))
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
			rec.record(recordedBody{status: resp.StatusCode, body: got, isReply: true})
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
	t.Cleanup(rec.server.Close)
	return rec
}

func (r *bodyRecorder) record(b recordedBody) {
	r.mu.Lock()
	r.bodies = append(r.bodies, b)
	r.mu.Unlock()
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

// TestPollBodiesCarryPaddedFrames pins the fact that the long-poll transport
// needs no padding of its own: the session conn frames every write before it
// reaches the ring, so a poll body is a run of frames and the frame rule has
// already shaped it. An earlier review called this transport unprotected
// because the POST body "looks" like raw payload at the call site; this test is
// what disproves that, and what would catch a future change that starts putting
// unframed bytes in the ring.
func TestPollBodiesCarryPaddedFrames(t *testing.T) {
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

	// A frame is 6 header bytes plus pad plus payload, and the rule keeps
	// pad+payload inside 400..600, so a padded frame totals 406..606.
	check := func(dir string, b recordedBody) {
		t.Helper()
		frames := splitInnerFrames(t, b.body)
		if len(frames) == 0 {
			t.Fatalf("%s: a %d-byte body holds no frame", dir, len(b.body))
		}
		for i, f := range frames {
			if f.payload != len(payload) {
				t.Fatalf("%s frame %d: payloadLen=%d, want %d — the body is not a run of data frames, so the frame rule is not covering it", dir, i, f.payload, len(payload))
			}
			if f.total < 406 || f.total > 606 {
				t.Fatalf("%s frame %d: total=%d (pad=%d), want 406..606", dir, i, f.total, f.pad)
			}
		}
	}
	for _, b := range sent {
		check("poll POST", b)
	}
	for _, b := range replies {
		check("poll response", b)
	}
}
