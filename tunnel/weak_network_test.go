package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Weak-network behaviour.
//
// The scenarios here are the ones a lossy or congested path produces and a
// healthy path never does: a hop that accepts the request and answers nothing,
// a link that comes back after an outage, a server that advertises how long it
// parks a poll. Each of them was a place where the client and the server
// disagreed about what a failure means, and where the disagreement cost
// minutes of a user's time rather than a retry.
// ---------------------------------------------------------------------------

// TestSlowBodyIsNotCutOffByTheHeaderDeadline is the scenario the two
// deadlines exist for.
//
// A poll that carries a quarter of a megabyte over a slow link is a healthy
// transfer that takes a while. If the header deadline governed the body as
// well, the client would abandon it partway through and the tunnel would
// report a failure for a link that was working exactly as it should.
//
// The body here trickles: it delivers a few bytes at a time, slowly enough
// that the whole transfer takes longer than the header deadline, and every
// byte has to arrive.
func TestSlowBodyIsNotCutOffByTheHeaderDeadline(t *testing.T) {
	const headerDeadline = 100 * time.Millisecond
	const chunk = 512
	const chunks = 20

	// A body that dribbles out its bytes with a pause between them, so the
	// whole transfer takes far longer than the header deadline.
	slow := &slowReader{chunk: chunk, chunks: chunks, gap: 20 * time.Millisecond}
	body := newDeadlineBody(slow, pollBodyBudget(headerDeadline))
	defer body.Close()

	start := time.Now()
	got := make([]byte, 0, chunk*chunks)
	buf := make([]byte, chunk)
	for len(got) < chunk*chunks {
		n, err := body.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("the slow body was cut off after %d of %d bytes (%v): %v",
				len(got), chunk*chunks, time.Since(start).Round(time.Millisecond), err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < headerDeadline {
		t.Fatalf("the transfer finished in %v, which is too fast to have proved anything", elapsed)
	}
	t.Logf("a %d-byte body arrived over %v, past the %v header deadline", len(got), elapsed.Round(time.Millisecond), headerDeadline)
}

// TestTheBodyGetsItsOwnDeadline pins that the body is wrapped with the
// scaled budget rather than with the header deadline.
//
// The test above exercises the wrapper directly, and a wrapper can be
// perfect while the code that uses it passes the wrong number. This reads
// the call site out of the source, which is the only place the two can be
// tied together.
func TestTheBodyGetsItsOwnDeadline(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatalf("read client.go: %v", err)
	}
	if !bytes.Contains(src, []byte("newDeadlineBody(resp.Body, pollBodyBudget(reqDeadline))")) {
		t.Fatal("the poll body does not get its own budget: it is on the header deadline")
	}
}

// slowReader delivers its bytes in chunks with a pause between them.
type slowReader struct {
	chunk  int
	chunks int
	gap    time.Duration
	served int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.served >= r.chunks {
		return 0, io.EOF
	}
	time.Sleep(r.gap)
	n := r.chunk
	if n > len(p) {
		n = len(p)
	}
	for i := 0; i < n; i++ {
		p[i] = byte(r.served)
	}
	r.served++
	return n, nil
}

func (r *slowReader) Close() error { return nil }

// TestPollBodyBudgetOutlivesTheHeaderDeadline pins the separation between the
// two deadlines.
//
// The header deadline answers "is the path alive?" and has to be short: a
// dead path must not look alive for the length of a request timeout. The body
// deadline answers "is the data arriving?" and has to be long: a poll body
// can be a quarter of a megabyte, and on a slow link that is tens of seconds
// of perfectly healthy transfer.
//
// One deadline for both would have to be the larger of the two, and the
// larger one is exactly the one that hides a dead path. So the body budget
// has to be strictly larger than the header deadline, and large enough for
// the biggest body on a slow link.
func TestPollBodyBudgetOutlivesTheHeaderDeadline(t *testing.T) {
	for _, header := range []time.Duration{
		5 * time.Second,
		20 * time.Second,
		45 * time.Second,
	} {
		budget := pollBodyBudget(header)
		if budget <= header {
			t.Errorf("pollBodyBudget(%v) = %v, which does not outlive the header deadline", header, budget)
		}
		if budget < pollBodyBudgetFloor {
			t.Errorf("pollBodyBudget(%v) = %v, below the %v floor", header, budget, pollBodyBudgetFloor)
		}
		if budget > clientRequestTimeout {
			t.Errorf("pollBodyBudget(%v) = %v, past the %v ceiling", header, budget, clientRequestTimeout)
		}
	}
}

// blockingReader never returns any bytes until it is closed. It is what a
// link that stops delivering mid-body looks like to the reader.
type blockingReader struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingReader() *blockingReader {
	return &blockingReader{closed: make(chan struct{})}
}

func (b *blockingReader) Read(p []byte) (int, error) {
	<-b.closed
	return 0, errPollBodyTimeout
}

func (b *blockingReader) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// TestDeadlineBodyTimesOutOnItsOwn pins that the body's deadline is the one
// that governs it, and not the request's. The body reads through a context of
// its own so that the header deadline — which was about a different question
// — cannot cut a healthy transfer short.
func TestDeadlineBodyTimesOutOnItsOwn(t *testing.T) {
	// A body that never delivers anything.
	stuck := newBlockingReader()
	body := newDeadlineBody(stuck, 100*time.Millisecond)
	defer body.Close()

	start := time.Now()
	_, err := body.Read(make([]byte, 16))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a body that delivers nothing did not time out")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the body read took %v to give up, which is past its own budget", elapsed)
	}
}

// TestPollRequestTimeoutFollowsTheServersWindow pins the rule that decides
// how long a poll may take: the server's own long-poll window plus a grace,
// not a fixed ceiling chosen by the client.
//
// The fixed ceiling was the problem. It had to be large enough to cover a
// long poll that comes back empty, and that made it large enough to cover a
// link that a NAT dropped silently — the two are indistinguishable to a
// client that does not know the server's window. So a dead path looked alive
// for the whole ceiling, and the recovery machinery never got to run.
//
// A server that does not advertise its window keeps the old behaviour, so
// this is a hint the client can do without, never a dependency.
func TestPollRequestTimeoutFollowsTheServersWindow(t *testing.T) {
	cases := []struct {
		name       string
		serverWait time.Duration
		want       time.Duration
	}{
		// The server says 5s: a healthy poll fits in 5+15, a dead path fails
		// in 20s instead of 90.
		{"advertised", 5 * time.Second, 20 * time.Second},
		// A long poll on a slow server: 10+15=25.
		{"slow server", 10 * time.Second, 25 * time.Second},
		// No advertisement: the client's own conservative bound.
		{"not advertised", 0, clientRequestTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pollRequestTimeout(tc.serverWait); got != tc.want {
				t.Fatalf("pollRequestTimeout(%v) = %v, want %v", tc.serverWait, got, tc.want)
			}
		})
	}
}

// TestPollRequestTimeoutNeverExceedsTheCeiling is the other half of the rule:
// a server that advertises a very long poll must not be able to push the
// client's deadline past what the client was ever willing to wait.
func TestPollRequestTimeoutNeverExceedsTheCeiling(t *testing.T) {
	for _, wait := range []time.Duration{
		30 * time.Second,
		60 * time.Second,
		10 * time.Minute,
		time.Hour,
	} {
		if got := pollRequestTimeout(wait); got > clientRequestTimeout {
			t.Fatalf("pollRequestTimeout(%v) = %v, which exceeds the ceiling %v", wait, got, clientRequestTimeout)
		}
	}
}

// TestServerPollWaitFromHeader pins the parsing of the advertised window. A
// value that is not a positive number of seconds means "not advertised" —
// including a negative one and a non-numeric one, because a hop that mangled
// the header must not be able to make the client wait for nothing.
func TestServerPollWaitFromHeader(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"5", 5 * time.Second},
		{"30", 30 * time.Second},
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"abc", 0},
		{"61", 0},   // longer than any long poll this protocol knows
		{"3600", 0}, // an hour is not a long poll, it is a mistake
	}
	for _, tc := range cases {
		if got := serverPollWaitFromHeader(tc.raw); got != tc.want {
			t.Errorf("serverPollWaitFromHeader(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// TestPollRestartBackoffIsJittered pins the rule that the recovery backoff
// must not be deterministic.
//
// A deterministic sequence means every client that lost the same link comes
// back at the same instants, so the edge sees a synchronised stampede right
// after the outage that caused it — exactly when it can least absorb one.
// The stream path has jittered since it was written; the poll path did not,
// and the poll path is the one that fails in bulk.
func TestPollRestartBackoffIsJittered(t *testing.T) {
	// Every round must produce more than one distinct value over enough
	// draws, and every value must stay inside its half-open interval.
	for round := 1; round <= 6; round++ {
		seen := make(map[time.Duration]bool)
		for i := 0; i < 64; i++ {
			d := pollRestartBackoff(round)
			seen[d] = true
			if d <= 0 {
				t.Fatalf("pollRestartBackoff(%d) = %v, want a positive delay", round, d)
			}
			if d > pollRestartBackoffCap {
				t.Fatalf("pollRestartBackoff(%d) = %v, which exceeds the cap %v", round, d, pollRestartBackoffCap)
			}
		}
		if len(seen) < 2 {
			t.Fatalf("pollRestartBackoff(%d) returned a single value %v across 64 draws: the delay is not jittered", round, seen)
		}
	}
}

// TestPollRestartBackoffGrowsAndCaps pins the shape of the curve: it starts
// small, grows, and stops at the cap. A backoff that never grows hammers the
// edge; one that never caps never comes back.
func TestPollRestartBackoffGrowsAndCaps(t *testing.T) {
	// The nominal sequence behind the jitter: 2s, 4s, 8s, 16s, 30s, 30s.
	// The jittered value is drawn from the upper half of each interval, so
	// the minimum observable delay is half the nominal one.
	nominal := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, want := range nominal {
		round := i + 1
		min := want / 2
		for draw := 0; draw < 32; draw++ {
			got := pollRestartBackoff(round)
			if got < min || got > want {
				t.Fatalf("pollRestartBackoff(%d) = %v, want it within [%v, %v]", round, got, min, want)
			}
		}
	}
}

// TestSilentLinkIsNoticedInSecondsRatherThanMinutes is the end-to-end version
// of the rule above, and the one that matters to a user.
//
// A hop that accepts the request and answers nothing is what a NAT that
// drops a flow looks like. The client used to notice it only when its own
// fixed request timeout expired — a minute and a half — because the deadline
// had to be long enough to cover a long poll that comes back empty, and the
// client had no way to tell those two situations apart.
//
// The observation is made from outside the client: the proxy holds the
// request open and records how long it was held. A request the client
// abandons ends at the client's own deadline, so the span is a direct
// measurement of that deadline. Asserting on the application's read instead
// would measure the test's own read timeout, which is not the thing being
// claimed.
func TestSilentLinkIsNoticedInSecondsRatherThanMinutes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	origin := newWireServer(t, ctx, events)
	p := newWireProxy(t, origin)

	conn, err := DialXHTTP(ctx, mustParseURL(t, p.server.URL+"/stream"), &DialConfig{
		Password:   "wire-secret",
		Path:       "/stream",
		ALPN:       "h1",
		StreamMode: "poll",
	}, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, buf[:5]); err != nil {
		t.Fatalf("read: %v", err)
	}

	// The link goes silent. The server advertised a 5s window, so the
	// client's deadline is 5s plus the grace.
	p.mu.Lock()
	p.silent = true
	p.mu.Unlock()

	want := pollRequestTimeout(longPollTimeout)
	if want >= clientRequestTimeout {
		t.Fatalf("the derived deadline %v is not tighter than the ceiling %v: the test would not prove anything", want, clientRequestTimeout)
	}

	// Wait for the client to abandon a request to the silent hop. The span
	// the proxy records is the client's deadline.
	deadline := time.Now().Add(clientRequestTimeout + 30*time.Second)
	var span time.Duration
	for time.Now().Before(deadline) {
		p.mu.Lock()
		if len(p.requestSpans) > 0 {
			span = p.requestSpans[len(p.requestSpans)-1]
			p.mu.Unlock()
			break
		}
		p.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	if span == 0 {
		t.Fatal("the client never abandoned a request to the silent hop")
	}

	// The span has to be the derived deadline, not the fixed ceiling. A
	// little slack either way: the client's timer and the proxy's clock are
	// not the same clock.
	t.Logf("the client abandoned the request after %v (derived deadline %v, ceiling %v)",
		span.Round(100*time.Millisecond), want, clientRequestTimeout)
	if span > want+5*time.Second {
		t.Fatalf("the client waited %v before giving up on a silent link, which is past the derived deadline %v; it is falling back to the %v ceiling",
			span, want, clientRequestTimeout)
	}
	if span < want-5*time.Second {
		t.Fatalf("the client gave up after %v, well before its %v deadline: it is cutting healthy polls short", span, want)
	}
}

// TestTheServerAdvertisesItsLongPollWindow pins the server half of the
// contract: the client cannot derive a deadline from a window it was never
// told, so the server has to say it.
func TestTheServerAdvertisesItsLongPollWindow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan SessionEvent, 64)
	origin := newWireServer(t, ctx, events)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String(), strings.NewReader(""))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The request has to be authenticated to reach the poll handler, so this
	// asks the server the question the client asks: what is your window?
	// A 401 or 403 means the header was not set on the error path, which is
	// not what is being tested; the test wants a request that gets far
	// enough to be answered.
	req.Header.Set("X-Target", "127.0.0.1:9")
	req.Header.Set("X-Network", "tcp")
	req.Header.Set("X-Session-ID", "poll-window-probe")
	req.Header.Set(ProtoHeader, "3")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	got := resp.Header.Get(PollTimeoutHeader)
	if got == "" {
		t.Fatalf("the server did not advertise its long-poll window in %q", PollTimeoutHeader)
	}
	wait := serverPollWaitFromHeader(got)
	if wait != longPollTimeout {
		t.Fatalf("advertised window = %v (raw %q), want %v", wait, got, longPollTimeout)
	}
}

// TestPollFailureThresholdScalesWithTheDeadline pins the rule that decides
// when a worker stops retrying one connection and asks for a new one.
//
// The threshold was a bare count — twenty-one consecutive failures — and a
// count only means something next to what a failure costs. With the deadline
// now derived from the server's window, a failure costs seconds rather than
// a minute and a half, so the same count described a different decision: it
// kept retrying a dead connection for seven minutes instead of thirty.
//
// What the number really expresses is a duration, and the duration is what
// the test pins.
func TestPollFailureThresholdScalesWithTheDeadline(t *testing.T) {
	// The exact counts, so that any change to the formula shows up as a
	// changed number rather than as a number that happens to fall inside a
	// range.
	//
	// 5s window  -> 20s deadline -> 8 attempts within the 3-minute budget
	// 90s fallback-> 90s deadline -> 3 attempts (the floor: one failure
	//                                already costs more than the budget)
	// 30s window -> 45s deadline -> 3 attempts (the floor again)
	// 1s window  -> 16s deadline -> 11 attempts
	cases := []struct {
		name   string
		waitNs int64
		want   int32
	}{
		{"advertised window", int64(longPollTimeout), 8},
		{"unknown window", 0, 3},
		{"slow server", int64(30 * time.Second), 3},
		{"fast server", int64(time.Second), 11},
	}
	for _, tc := range cases {
		if got := pollFailureThreshold(tc.waitNs); got != tc.want {
			t.Errorf("%s: threshold = %d, want %d", tc.name, got, tc.want)
		}
	}

	// The property the numbers exist to serve: a cheap failure buys more
	// attempts than an expensive one.
	slow := pollFailureThreshold(int64(clientRequestTimeout))
	fast := pollFailureThreshold(int64(longPollTimeout))
	if fast < slow {
		t.Fatalf("a cheap failure produced fewer attempts (%d) than an expensive one (%d): the count is not scaled by the deadline", fast, slow)
	}
}

// TestPollFailureThresholdIsUsedAtTheCallSite pins that the worker actually
// consults the scaled threshold.
//
// The function above can be perfect while the code that uses it keeps a
// hard-coded number, and nothing else would notice: a test of the function
// alone passes while the behaviour it was written for is absent. This reads
// the call site out of the source, which is the only place the two can be
// tied together.
func TestPollFailureThresholdIsUsedAtTheCallSite(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatalf("read client.go: %v", err)
	}
	if !bytes.Contains(src, []byte("atomic.AddInt32(&consecutiveErrors, 1) > pollFailureThreshold(")) {
		t.Fatal("the worker does not consult the scaled failure threshold: a hard-coded count is back")
	}
}

// TestRetryAfterDelayIsHonoured pins the rule that a rate limiter's own
// instruction about when to come back is followed.
//
// A CDN that answers a 429 with Retry-After is saying "come back at this
// time". Retrying in a second anyway is how one rate limit becomes a
// sustained one: the retries are what keeps the limiter angry, and the client
// is the one making it angry.
func TestRetryAfterDelayIsHonoured(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"seconds", "30", 30 * time.Second},
		{"one second", "1", time.Second},
		// Beyond the ceiling: an edge that asks for an hour does not get to
		// park the client for one.
		{"over the ceiling", "3600", 60 * time.Second},
		{"missing", "", time.Second},
		{"garbage", "soon", time.Second},
		{"zero", "0", time.Second},
		{"negative", "-5", time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfterDelay(tc.raw); got != tc.want {
				t.Fatalf("retryAfterDelay(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestRetryAfterDelayReadsTheDateForm pins the other form the header takes.
// Cloudflare sends an HTTP date rather than a number of seconds, and a parser
// that only reads numbers ignores it exactly where it matters most.
func TestRetryAfterDelayReadsTheDateForm(t *testing.T) {
	// A date 20 seconds in the future.
	when := time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat)
	got := retryAfterDelay(when)
	if got < 15*time.Second || got > 25*time.Second {
		t.Fatalf("retryAfterDelay(%q) = %v, want roughly 20s", when, got)
	}
	// A date in the past means "now", not "negative".
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := retryAfterDelay(past); got != time.Second {
		t.Fatalf("retryAfterDelay(%q) = %v, want the 1s fallback", past, got)
	}
}

// mustParseURL parses a URL or fails the test.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// countingHandler counts the requests it served. It exists so a test can
// assert that a server was asked again, without caring about the payload.
type countingHandler struct {
	n atomic.Int32
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.n.Add(1)
	w.WriteHeader(http.StatusOK)
}
