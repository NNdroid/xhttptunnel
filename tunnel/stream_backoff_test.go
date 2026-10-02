package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
)

type streamTestTransport func(*http.Request) (*http.Response, error)

func (f streamTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type timedStreamBody struct {
	ctx    context.Context
	hello  *bytes.Reader
	timer  *time.Timer
	closed chan struct{}
	once   sync.Once
}

func (b *timedStreamBody) Read(p []byte) (int, error) {
	if b.hello.Len() > 0 {
		return b.hello.Read(p)
	}
	select {
	case <-b.timer.C:
		return 0, io.EOF
	case <-b.closed:
		return 0, io.EOF
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
}
func (b *timedStreamBody) Close() error {
	b.once.Do(func() { b.timer.Stop(); close(b.closed) })
	return nil
}

func TestStreamReconnectResetsAfterHealthyRound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		retries := make(chan int, 8)
		hub := newEventHub(func(e Event) {
			if r, ok := e.(Reconnecting); ok {
				retries <- r.Nth
			}
		})
		defer hub.close()
		round := 0
		rt := streamTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPost {
				_, err := io.Copy(io.Discard, r.Body)
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: r}, nil
			}
			round++
			life := time.Millisecond
			if round == 3 {
				life = reconnectHealthyWindow + time.Second
			}
			if round > 3 {
				life = time.Hour
			}
			hello, err := streamFrameBytes(0, 0, nil)
			if err != nil {
				return nil, err
			}
			body := &timedStreamBody{ctx: r.Context(), hello: bytes.NewReader(hello), timer: time.NewTimer(life), closed: make(chan struct{})}
			return &http.Response{StatusCode: 200, Header: http.Header{"X-Downstream-Accepted": {"1"}, "X-Stream-Uplink-Sync": {"1"}}, Body: body, Request: r}, nil
		})
		conn, err := dialXHTTPStream(streamDialArgs{ctx: ctx, cfg: &DialConfig{StreamMode: "stream"}, rt: rt, client: &http.Client{Transport: rt}, reqURL: "http://fixture/stream", sessionID: "healthy-reset", key: "healthy-reset", logger: zap.NewNop(), events: hub})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for _, want := range []int{1, 2, 1} {
			select {
			case got := <-retries:
				if got != want {
					t.Fatalf("retry count %d, want %d", got, want)
				}
			case <-time.After(time.Minute):
				t.Fatal("missing reconnect event")
			}
		}
		cancel()
		conn.Close()
		synctest.Wait()
	})
}

type timeoutStreamReader struct{}

func (timeoutStreamReader) Read([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

func TestStreamReadTimeoutKeepsResumableSession(t *testing.T) {
	vc := newMeekVirtualConn("timeout-resume", nil, nil, nil)
	defer vc.Close()
	r, _ := http.NewRequest(http.MethodPost, "http://fixture/stream", io.NopCloser(timeoutStreamReader{}))
	r.Header.Set("X-Stream-Resume", "1")
	serveStreamUplink(httptest.NewRecorder(), r, newServerState(1), vc, "timeout-resume")
	if vc.isClosed() {
		t.Fatal("transport read timeout destroyed resumable application state")
	}
}

type deadlineResponse struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineResponse) SetReadDeadline(t time.Time) error {
	w.deadline = t
	return nil
}

type slowProgressBody struct {
	data []byte
	w    *deadlineResponse
}

func (b *slowProgressBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	time.Sleep(3 * time.Second)
	if deadlineExpired(b.w.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	p[0] = b.data[0]
	b.data = b.data[1:]
	return 1, nil
}

func TestStreamSlowReadProgressRefreshesDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &deadlineResponse{ResponseRecorder: httptest.NewRecorder()}
		frame := streamFrameStorage(nil, 0, 0, 5, 0)
		body := &slowProgressBody{data: frame, w: w}
		r, _ := http.NewRequest(http.MethodPost, "http://fixture/stream", io.NopCloser(body))
		r.Header.Set("X-Stream-Resume", "1")
		vc := newMeekVirtualConn("slow-progress", nil, nil, nil)
		defer vc.Close()
		start := time.Now()
		serveStreamUplink(w, r, newServerState(1), vc, "slow-progress")
		if time.Since(start) <= streamWatchdogTimeout {
			t.Fatal("fixture did not cross the original frame deadline")
		}
		if vc.consumedUpSeq() != 5 || vc.isClosed() {
			t.Fatal("active slow upload was interrupted by an absolute frame deadline")
		}
	})
}
