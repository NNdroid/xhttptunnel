package tunnel

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestWindowValidationAndClientIsolation(t *testing.T) {
	for _, mb := range []int{-1, 65} {
		if _, err := NewClient(ClientConfig{ServerURL: "http://example.com/stream", WindowSizeMB: mb}); err == nil {
			t.Fatalf("client accepted %d", mb)
		}
		if _, err := NewServer(ServerConfig{WindowSizeMB: mb}); err == nil {
			t.Fatalf("server accepted %d", mb)
		}
	}
	for _, budget := range []int{-1, 1, 65537} {
		if _, err := NewServer(ServerConfig{BufferBudgetMB: budget}); err == nil {
			t.Fatalf("server accepted budget %d", budget)
		}
	}
	for _, mb := range []int{0, 1, 16, 64} {
		c, err := NewClient(ClientConfig{ServerURL: "http://example.com/stream", WindowSizeMB: mb})
		if err != nil {
			t.Fatal(err)
		}
		if c.dialCfg.WindowSizeMB != mb {
			t.Fatal("lost per-client window")
		}
		c.Close()
	}
}

func TestBufferBudgetConcurrentReservations(t *testing.T) {
	b := &bufferBudget{limit: 10}
	var wg sync.WaitGroup
	accepted := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			if b.reserve(1) {
				accepted <- struct{}{}
			}
		})
	}
	wg.Wait()
	if len(accepted) != 10 || b.used.Load() != 10 {
		t.Fatalf("admission overshot budget: %d / %d", len(accepted), b.used.Load())
	}
}

func TestServerBufferBudgetReleasedOnClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	window := 16
	reservation := bufferReservation(window << 20)
	budgetMB := int((reservation + (1 << 20) - 1) >> 20)
	s, u, dial := newHardenedServer(t, ctx, ServerConfig{
		WindowSizeMB: window, BufferBudgetMB: budgetMB,
		Handler: func(c *XHTTPConn) { defer c.Close(); _, _ = io.Copy(c, c) },
	})
	defer s.Close()
	dial.WindowSizeMB = 1 // peer windows need not match
	c1, err := DialXHTTP(ctx, u, dial, "x:1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	if s.state.bufferBudget.used.Load() != reservation {
		t.Fatal("session did not reserve configured buffers")
	}
	if stats := s.Stats(); stats.BufferReservedBytes != reservation || stats.BufferBudgetBytes != int64(budgetMB)<<20 {
		t.Fatalf("budget stats mismatch: %+v", stats)
	}
	c2, err := DialXHTTP(ctx, u, dial, "x:2", "tcp")
	if err == nil {
		c2.Close()
		t.Fatal("second session exceeded the budget")
	}
	_ = c1.Close()
	deadline := time.Now().Add(3 * time.Second)
	for s.state.bufferBudget.used.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.state.bufferBudget.used.Load() != 0 {
		t.Fatal("closed session leaked budget")
	}
	c3, err := DialXHTTP(ctx, u, dial, "x:3", "tcp")
	if err != nil {
		t.Fatalf("capacity did not recover: %v", err)
	}
	c3.Close()
}

func TestStreamReconnectBackoffBounds(t *testing.T) {
	for _, failures := range []int{1, 2, 4, 8, 1000000} {
		base := 300 * time.Millisecond
		for i := 1; i < failures && base < reconnectBackoffCap; i++ {
			base *= 2
		}
		if base > reconnectBackoffCap {
			base = reconnectBackoffCap
		}
		values := make(map[time.Duration]bool)
		for i := 0; i < 100; i++ {
			d := streamReconnectBackoff(failures)
			if d < base/2 || d > base {
				t.Fatalf("failure %d: delay %s outside [%s,%s]", failures, d, base/2, base)
			}
			values[d] = true
		}
		if len(values) == 1 {
			t.Fatal("retry delays have no jitter")
		}
	}
}
