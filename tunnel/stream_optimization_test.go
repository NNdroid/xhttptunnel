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
		if r.Method == http.MethodPost {
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
		if r.Method == http.MethodGet {
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
