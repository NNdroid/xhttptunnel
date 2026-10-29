package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// Echo traffic piggybacks ACKs and hides stalls in a one-way transfer.
func TestStreamOneWayBeyondWindow(t *testing.T) {
	for _, alpn := range []string{"h1", "h2", "h3"} {
		for _, direction := range []string{"upload", "download"} {
			t.Run(alpn+"/"+direction, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				payload := bytes.Repeat([]byte("integrity-test!"), 1<<20)
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				result := make(chan error, 1)
				go func() {
					c, err := ln.Accept()
					if err != nil {
						result <- err
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(10 * time.Second))
					if direction == "upload" {
						got := make([]byte, len(payload))
						_, err = io.ReadFull(c, got)
						if err == nil && !bytes.Equal(payload, got) {
							err = io.ErrUnexpectedEOF
						}
						result <- err
					} else {
						_, err = c.Write(payload)
						result <- err
					}
					<-ctx.Done()
				}()
				u, cfg := startTunnelServer(t, ctx, alpn)
				cfg.StreamMode = "stream"
				c, err := DialXHTTP(ctx, u, cfg, ln.Addr().String(), "tcp")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				clientDone := make(chan error, 1)
				go func() {
					if direction == "upload" {
						// One write also tests publishing partial batches when the
						// application write is larger than the entire ring.
						_, err := c.Write(payload)
						clientDone <- err
					} else {
						got := make([]byte, len(payload))
						_, err := io.ReadFull(c, got)
						if err == nil && !bytes.Equal(payload, got) {
							err = io.ErrUnexpectedEOF
						}
						clientDone <- err
					}
				}()
				for _, done := range []<-chan error{clientDone, result} {
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("one-way transfer stalled beyond its window")
					}
				}
			})
		}
	}
}

func TestStreamDialWaitsForUplinkAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := NewServer(ServerConfig{Path: "/stream", Handler: func(c *XHTTPConn) {
		defer c.Close()
		<-ctx.Done()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	handler := s.Handler()
	postSeen := make(chan struct{}, 1)
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == streamContentType {
			postSeen <- struct{}{}
			_ = http.NewResponseController(w).EnableFullDuplex()
			http.Error(w, "refused", http.StatusProxyAuthRequired)
			_ = http.NewResponseController(w).Flush()
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() { cancel(); host.Close() }()
	u, _ := url.Parse(host.URL + "/stream")
	c, err := DialXHTTP(ctx, u, &DialConfig{Path: "/stream", ALPN: "h1", StreamMode: "stream"}, "echo:1", "tcp")
	if err == nil {
		c.Close()
		t.Fatal("Dial succeeded before the rejected uplink was admitted")
	}
	if !errors.Is(err, errAuthRejected) {
		t.Fatalf("dial error = %v", err)
	}
	select {
	case <-postSeen:
	default:
		t.Fatal("uplink was not attempted")
	}
}

type interruptedResponse struct {
	http.ResponseWriter
	faults  *atomic.Int32
	written int
}

func (w *interruptedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *interruptedResponse) Write(p []byte) (int, error) {
	if w.written >= 256*1024 {
		for {
			left := w.faults.Load()
			if left == 0 {
				break
			}
			if w.faults.CompareAndSwap(left, left-1) {
				return 0, io.ErrUnexpectedEOF
			}
		}
	}
	n, err := w.ResponseWriter.Write(p)
	w.written += n
	return n, err
}

func TestStreamResumePreservesBytesAfterRepeatedBreaks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := NewServer(ServerConfig{Path: "/stream", Handler: func(c *XHTTPConn) {
		defer c.Close()
		_, _ = io.Copy(c, c)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var faults atomic.Int32
	faults.Store(3)
	handler := s.Handler()
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Downstream") == "1" {
			w = &interruptedResponse{ResponseWriter: w, faults: &faults}
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() { cancel(); host.Close() }()
	u, _ := url.Parse(host.URL + "/stream")
	c, err := DialXHTTP(ctx, u, &DialConfig{Path: "/stream", ALPN: "h1", StreamMode: "stream"}, "echo:1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("resumed-byte-stream!"), 1<<20)
	writeDone := make(chan error, 1)
	go func() { _, err := c.Write(payload); writeDone <- err }()
	readDone := make(chan error, 1)
	got := make([]byte, len(payload))
	go func() { _, err := io.ReadFull(c, got); readDone <- err }()
	for _, done := range []<-chan error{writeDone, readDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("resume stalled")
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resume lost or duplicated bytes")
	}
	if faults.Load() != 0 {
		t.Fatalf("only %d breaks exercised", 3-faults.Load())
	}
}

// Mount under short absolute HTTP deadlines: active streams must override
// them, while ordinary endpoints continue to use the host's limits.
func TestStreamOverridesAbsoluteHTTPTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := NewServer(ServerConfig{Path: "/stream", Handler: func(c *XHTTPConn) {
		defer c.Close()
		_, _ = io.Copy(c, c)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: time.Second, ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond}
	defer hs.Close()
	go hs.Serve(ln)
	u, _ := url.Parse("http://" + ln.Addr().String() + "/stream")
	c, err := DialXHTTP(ctx, u, &DialConfig{Path: "/stream", ALPN: "h1", StreamMode: "stream"}, "echo:1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for i := 0; i < 12; i++ {
		<-tick.C
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			t.Fatal(err)
		}
		if b[0] != byte(i) {
			t.Fatal("echo mismatch")
		}
	}
}

// TestStreamProbeAdaptiveWindowSucceedsOnSlowHandshake guards the timer-reset
// fix: the probe window should cover the hello wait, not the connection setup
// that has already completed. Without the reset, a 3s handshake consumes most
// of the 5s window, and a hello arriving 2s after the headers lands at 5s —
// right at the deadline. With the reset, the window restarts at the headers,
// giving the full 5s for the hello.
func TestStreamProbeAdaptiveWindowSucceedsOnSlowHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hello, err := streamFrameBytes(0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := streamTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Content-Type") == streamContentType {
			io.Copy(io.Discard, r.Body)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
		}
		time.Sleep(3 * time.Second) // simulate slow TCP+TLS+HTTP handshake
		ch := make(chan struct{})
		go func() { time.Sleep(2 * time.Second); close(ch) }()
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"X-Downstream-Accepted": {"1"}, "X-Stream-Uplink-Sync": {"1"}},
			Body:       &delayedHelloBody{ctx: r.Context(), hello: hello, release: ch},
			Request:    r,
		}, nil
	})

	established := make(chan struct{})
	hub := newEventHub(func(ev Event) {
		if _, ok := ev.(TunnelEstablished); ok {
			close(established)
		}
	})
	defer hub.close()

	result := make(chan error, 1)
	go func() {
		conn, err := dialXHTTPStream(streamDialArgs{
			ctx: ctx, cfg: &DialConfig{StreamMode: "stream"},
			rt: rt, client: &http.Client{Transport: rt},
			reqURL: "http://fixture/stream", sessionID: "adaptive-probe",
			key: "adaptive-probe", logger: zap.NewNop(), events: hub,
		})
		result <- err
		if conn != nil {
			conn.Close()
		}
	}()

	select {
	case <-established:
		// Probe succeeded despite the slow handshake.
	case err := <-result:
		if err != nil {
			t.Fatalf("probe failed with slow handshake: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("probe did not establish within timeout")
	}
	cancel()
}

// delayedHelloBody releases its hello frame only after the release channel is
// closed, simulating a server that takes time to process the companion POST
// before sending the hello frame.
type delayedHelloBody struct {
	ctx      context.Context
	hello    []byte
	release  chan struct{}
	released bool
}

func (b *delayedHelloBody) Read(p []byte) (int, error) {
	if !b.released {
		select {
		case <-b.release:
		case <-b.ctx.Done():
			return 0, b.ctx.Err()
		}
		b.released = true
	}
	if len(b.hello) > 0 {
		n := copy(p, b.hello)
		b.hello = b.hello[n:]
		return n, nil
	}
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
}

func (b *delayedHelloBody) Close() error { return nil }
