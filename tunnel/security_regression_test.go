package tunnel

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type failingStreamResponse struct {
	header               http.Header
	writes, flushes      int
	failWrite, failFlush int
	cancel               context.CancelFunc
	vc                   *meekVirtualConn
}

func (w *failingStreamResponse) Header() http.Header { return w.header }
func (*failingStreamResponse) WriteHeader(int)       {}
func (w *failingStreamResponse) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > 3 {
		_ = w.vc.Close()
	} // Bound the pre-fix busy-loop reproducer.
	if w.cancel != nil && w.writes == 2 {
		w.cancel()
	}
	if w.failWrite == w.writes {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func (w *failingStreamResponse) FlushError() error {
	w.flushes++
	if w.failFlush == w.flushes {
		return io.ErrClosedPipe
	}
	return nil
}

func TestStreamDownlinkStopsOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		write, flush int
	}{
		{"hello-write", 1, 0}, {"hello-flush", 0, 2},
		{"keepalive-write", 2, 0}, {"keepalive-flush", 0, 3}, {"cancel", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			vc := newMeekVirtualConn("idle", nil, nil, nil)
			defer vc.Close()
			atomic.StoreInt64(&vc.lastActive, 1)
			w := &failingStreamResponse{header: make(http.Header), failWrite: tc.write, failFlush: tc.flush, cancel: cancel, vc: vc}
			r := httptest.NewRequest(http.MethodGet, "/stream", nil).WithContext(ctx)
			serveStreamDownlink(w, r, newServerState(1), vc, "idle", false)
			if w.writes > 2 {
				t.Fatalf("abandoned handler kept writing: %d writes", w.writes)
			}
			if tc.name != "cancel" && atomic.LoadInt64(&vc.lastActive) != 1 {
				t.Fatal("failed stream refreshed liveness")
			}
		})
	}
}

func TestReliableBufferRejectsExtremeOffsets(t *testing.T) {
	for _, seq := range []uint64{math.MaxUint64, 1 << 63, 1 << 32, 1 << 31} {
		t.Run(fmtUint(seq), func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("peer offset panicked: %v", p)
				}
			}()
			rb := newReliableBuffer(16)
			_, _ = rb.Write([]byte("abc"))
			data, _, ptr := rb.GetSlice(seq, seq, 16)
			safelyPutSendBuf(ptr)
			if len(data) != 0 || rb.Len() != 3 {
				t.Fatalf("invalid offset consumed queued data: len=%d buffered=%d", len(data), rb.Len())
			}
			if rb.undispatched(seq) != 0 {
				t.Fatal("invalid dispatch reported pending data")
			}
			rb.mu.Lock()
			pending := rb.pendingBeyond(seq)
			rb.mu.Unlock()
			if pending {
				t.Fatal("overflow created phantom data")
			}
			if rb.validAck(seq) {
				t.Fatal("extreme acknowledgement was accepted")
			}
		})
	}
}

func TestPutReadDataContextCancellationKeepsSessionUsable(t *testing.T) {
	vc := newMeekVirtualConn("backpressure", nil, nil, nil)
	defer vc.Close()
	if ack, err := vc.PutReadDataContext(context.Background(), 0, make([]byte, maxReassemblyBytes)); err != nil || ack != maxReassemblyBytes {
		t.Fatalf("fill reassembly buffer: ack=%d err=%v", ack, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := vc.PutReadDataContext(ctx, maxReassemblyBytes, []byte{1})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("blocked producer returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled producer remained blocked")
	}
	if vc.isClosed() {
		t.Fatal("request cancellation closed the healthy session")
	}

	buf := make([]byte, maxReassemblyBytes)
	if n, err := io.ReadFull(vc, buf); err != nil || n != len(buf) {
		t.Fatalf("session unusable after cancellation: n=%d err=%v", n, err)
	}
	if ack, err := vc.PutReadDataContext(context.Background(), maxReassemblyBytes, []byte{1}); err != nil || ack != maxReassemblyBytes+1 {
		t.Fatalf("reuse after cancellation: ack=%d err=%v", ack, err)
	}
}

func TestPutReadDataContextAcceptsPartialRetransmission(t *testing.T) {
	vc := newMeekVirtualConn("overlap", nil, nil, nil)
	defer vc.Close()
	if ack, err := vc.PutReadDataContext(context.Background(), 0, []byte("abc")); err != nil || ack != 3 {
		t.Fatalf("first chunk: ack=%d err=%v", ack, err)
	}
	if ack, err := vc.PutReadDataContext(context.Background(), 1, []byte("bcdef")); err != nil || ack != 6 {
		t.Fatalf("overlap chunk: ack=%d err=%v", ack, err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(vc, got); err != nil || string(got) != "abcdef" {
		t.Fatalf("reassembled %q, err=%v", got, err)
	}
}

func TestPutReadDataContextPrunesCoveredOutOfOrderData(t *testing.T) {
	vc := newMeekVirtualConn("overlap-ooo", nil, nil, nil)
	defer vc.Close()
	if ack, err := vc.PutReadDataContext(context.Background(), 4, []byte("efgh")); err != nil || ack != 0 {
		t.Fatalf("cache ahead: ack=%d err=%v", ack, err)
	}
	if ack, err := vc.PutReadDataContext(context.Background(), 0, []byte("abcdef")); err != nil || ack != 8 {
		t.Fatalf("cover cached prefix: ack=%d err=%v", ack, err)
	}
	if len(vc.oooBuf) != 0 || vc.oooBytes != 0 {
		t.Fatalf("stale OOO state: entries=%d bytes=%d", len(vc.oooBuf), vc.oooBytes)
	}
	got := make([]byte, 8)
	if _, err := io.ReadFull(vc, got); err != nil || string(got) != "abcdefgh" {
		t.Fatalf("reassembled %q, err=%v", got, err)
	}
	if ack, err := vc.PutReadDataContext(context.Background(), 10, []byte("kl")); err != nil || ack != 8 {
		t.Fatalf("later OOO insert blocked or failed: ack=%d err=%v", ack, err)
	}
}

func TestPutReadDataContextExtendsSameStartChunk(t *testing.T) {
	vc := newMeekVirtualConn("same-start", nil, nil, nil)
	defer vc.Close()
	_, _ = vc.PutReadDataContext(context.Background(), 2, []byte("cd"))
	_, _ = vc.PutReadDataContext(context.Background(), 2, []byte("cdef"))
	if ack, err := vc.PutReadDataContext(context.Background(), 0, []byte("ab")); err != nil || ack != 6 {
		t.Fatalf("same-start extension: ack=%d err=%v", ack, err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(vc, got); err != nil || string(got) != "abcdef" {
		t.Fatalf("reassembled %q, err=%v", got, err)
	}
}

func TestForcedStreamDialWaitsForUplinkAdmission(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == streamContentType {
			posts.Add(1)
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("X-Downstream-Accepted", "1")
		w.Header().Set("X-Stream-Uplink-Sync", "1")
		w.Header().Set(ProtoHeader, strconv.Itoa(tunnelProtoVersion))
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	var established atomic.Int32
	hub := newEventHub(func(ev Event) {
		if _, ok := ev.(TunnelEstablished); ok {
			established.Add(1)
		}
	})
	defer hub.close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := DialXHTTP(ctx, serverURL, &DialConfig{
		Path: "/", ALPN: "h1", StreamMode: "stream", events: hub,
	}, "target.invalid:1", "tcp")
	if conn != nil {
		conn.Close()
	}
	if err == nil || (!strings.Contains(err.Error(), "stream") && !errors.Is(err, context.Canceled)) {
		t.Fatalf("forced stream dial error = %v, want negotiation failure (posts=%d)", err, posts.Load())
	}
	if posts.Load() != 1 {
		t.Fatalf("companion upload attempts = %d, want 1", posts.Load())
	}
	if elapsed := time.Since(start); elapsed > streamProbeMinWindow+500*time.Millisecond {
		t.Fatalf("upload rejection exceeded the bounded negotiation window: %v", elapsed)
	}
	time.Sleep(20 * time.Millisecond) // allow asynchronous event delivery
	if established.Load() != 0 {
		t.Fatal("TunnelEstablished emitted before uplink admission")
	}
}

func fmtUint(v uint64) string { // keep test names architecture-independent
	if v == math.MaxUint64 {
		return "max-uint64"
	}
	if v == 1<<63 {
		return "sign64"
	}
	if v == 1<<32 {
		return "wrap32"
	}
	return "sign32"
}
