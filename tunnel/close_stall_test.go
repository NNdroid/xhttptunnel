package tunnel

import (
	"context"
	"testing"
	"time"
)

// TestXHTTPTunnel_CloseIsNotStalledByLongPoll guards a regression where every
// session Close() blocked for exactly longPollTimeout (5s): the closer waited
// for pumpDone while a worker sat parked in an empty GET long poll that the
// server only releases after the full timeout. The close frame rides a POST,
// so aborting the parked GET is lossless — the fix cancels it via a per-poll
// handle.
//
// The sink target never sends downlink data, which is exactly the condition
// that parks a GET for the full 5s.
func TestXHTTPTunnel_CloseIsNotStalledByLongPoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, dial := startTunnelServer(t, ctx, "h1")
	sinkAddr, closeSink := startTCPSinkServer(t)
	defer closeSink()

	for round := 1; round <= 3; round++ {
		conn, err := DialXHTTP(ctx, serverURL, dial, sinkAddr, "tcp")
		if err != nil {
			t.Fatalf("round %d dial: %v", round, err)
		}
		// Queue a payload so the close frame has company in the write buffer
		// (the branch that used to wait on pumpDone).
		if _, err := conn.Write(make([]byte, 64*1024)); err != nil {
			t.Fatalf("round %d write: %v", round, err)
		}

		start := time.Now()
		if err := conn.Close(); err != nil {
			t.Fatalf("round %d close: %v", round, err)
		}
		elapsed := time.Since(start)

		// The original bug stalled Close for exactly longPollTimeout (5s) and
		// the stream mode may legitimately spend up to streamCloseGrace (2s)
		// flushing its close marker; the threshold must sit between them.
		if elapsed > 3500*time.Millisecond {
			t.Errorf("round %d: Close took %s, want <3.5s (long-poll stall is back)", round, elapsed)
		}
	}
}
