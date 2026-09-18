package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// ---------------------------------------------------------------------------
// Wire formats
// ---------------------------------------------------------------------------

func TestPackBrutalParams(t *testing.T) {
	const rate = 0x0102030405060708
	const group = 0x1122334455667788
	const gain = 20

	// {u64 rate; u32 cwnd_gain; u64 group_id} __packed is 8 + 4 + 8 = 20 bytes.
	// There is no alignment padding after the u32; an unpacked layout would be
	// 24 and would hand the kernel a struct it has never seen.
	out := packBrutalParams(rate, group, gain)
	if len(out) != brutalParamsLen {
		t.Fatalf("length = %d, want %d", len(out), brutalParamsLen)
	}
	const want = "0807060504030201140000008877665544332211"
	if got := hex.EncodeToString(out); got != want {
		t.Errorf("bytes = %s, want %s", got, want)
	}
	if got := binary.LittleEndian.Uint64(out[:8]); got != rate {
		t.Errorf("rate field = %#x, want %#x", got, rate)
	}
	if got := binary.LittleEndian.Uint32(out[8:12]); got != gain {
		t.Errorf("cwnd_gain field = %d, want %d", got, gain)
	}
	if got := binary.LittleEndian.Uint64(out[12:20]); got != group {
		t.Errorf("group_id field = %#x, want %#x", got, group)
	}
	// The group id must always travel: the module's per-connection behaviour
	// comes from sending zero, so omitting the field would silently change it.
	if got := packBrutalParams(1, 0, 15); len(got) != brutalParamsLen {
		t.Errorf("a zero group id still occupies %d bytes, got %d", brutalParamsLen, len(got))
	}
}

// ---------------------------------------------------------------------------
// The degradation ladder
// ---------------------------------------------------------------------------

// brutalFakeOps drives every branch of enableBrutal without a kernel module.
type brutalFakeOps struct {
	congestionErr  error
	congestionAlgo string
	paramsErr      error
	paramsCalls    int
	gotParams      []byte
}

func (s *brutalFakeOps) setCongestion(fd uintptr) error { return s.congestionErr }
func (s *brutalFakeOps) getCongestion(fd uintptr) (string, error) {
	return s.congestionAlgo, nil
}
func (s *brutalFakeOps) setParams(fd uintptr, data []byte) error {
	s.paramsCalls++
	s.gotParams = append([]byte(nil), data...)
	return s.paramsErr
}

func TestEnableBrutalLadder(t *testing.T) {
	p := brutalParams{rate: 1_000_000, cwndGain: 20, groupID: 0xdead}
	errCubic := errors.New("invalid argument")
	errTransient := errors.New("temporary failure")

	cases := []struct {
		name      string
		ops       *brutalFakeOps
		wantErr   bool
		wantCalls int
		wantLen   int
	}{
		{
			name:      "happy path carries the group id",
			ops:       &brutalFakeOps{},
			wantCalls: 1,
			wantLen:   brutalParamsLen,
		},
		{
			name:      "congestion locked onto brutal leaves the rule alone",
			ops:       &brutalFakeOps{congestionErr: errLocked, congestionAlgo: "brutal"},
			wantCalls: 0,
			wantLen:   0,
		},
		{
			name:      "a locked route on another algorithm is a real failure",
			ops:       &brutalFakeOps{congestionErr: errLocked, congestionAlgo: "cubic"},
			wantErr:   true,
			wantCalls: 0,
			wantLen:   0,
		},
		{
			name:      "congestion refused for another reason propagates",
			ops:       &brutalFakeOps{congestionErr: errCubic},
			wantErr:   true,
			wantCalls: 0,
			wantLen:   0,
		},
		{
			name:      "params locked by a rule is a success",
			ops:       &brutalFakeOps{paramsErr: errLocked},
			wantCalls: 1,
			wantLen:   brutalParamsLen,
		},
		{
			name:      "an unexplained params failure propagates",
			ops:       &brutalFakeOps{paramsErr: errTransient},
			wantErr:   true,
			wantCalls: 1,
			wantLen:   brutalParamsLen,
		},
		{
			name: "a module that refuses the 20-byte struct is reported, not fatal",
			// The algorithm name was accepted, so the module is loaded; a
			// refusal of the struct itself means a brutal version predating
			// group_id. There is no 12-byte fallback: the error is returned and
			// the caller reports it once, leaving the connection uncapped.
			ops:       &brutalFakeOps{paramsErr: errors.New("invalid argument")},
			wantErr:   true,
			wantCalls: 1,
			wantLen:   brutalParamsLen,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enableBrutal(3, p, tc.ops)
			if got := err != nil; got != tc.wantErr {
				t.Fatalf("enableBrutal returned %v, want error = %v", err, tc.wantErr)
			}
			if tc.ops.paramsCalls != tc.wantCalls {
				t.Errorf("setsockopt(TCP_BRUTAL_PARAMS) called %d times, want %d", tc.ops.paramsCalls, tc.wantCalls)
			}
			if tc.wantCalls == 0 {
				return
			}
			if len(tc.ops.gotParams) != tc.wantLen {
				t.Fatalf("params length = %d, want %d", len(tc.ops.gotParams), tc.wantLen)
			}
			if got := binary.LittleEndian.Uint64(tc.ops.gotParams[:8]); got != p.rate {
				t.Errorf("rate = %d, want %d", got, p.rate)
			}
			if got := binary.LittleEndian.Uint32(tc.ops.gotParams[8:12]); got != p.cwndGain {
				t.Errorf("cwnd_gain = %d, want %d", got, p.cwndGain)
			}
			if got := binary.LittleEndian.Uint64(tc.ops.gotParams[12:20]); got != p.groupID {
				t.Errorf("group_id = %x, want %x", tc.ops.gotParams[12:20], p.groupID)
			}
		})
	}
}

// TestEnableBrutalNeverWritesARatelessStruct pins the zero-rate guard: a zero
// rate means "not configured yet", and passing one to the kernel would cap the
// connection at zero, which stalls it rather than leaving it uncapped.
func TestBrutalParamsValid(t *testing.T) {
	// Parentheses are mandatory: "if brutalParams{}" is not a parseable
	// expression in Go, so the composite literal needs grouping.
	if (brutalParams{}).valid() {
		t.Error("an unset rate must not be considered valid")
	}
	if (brutalParams{rate: 1}).valid() {
		t.Error("a zero cwnd_gain must not be considered valid")
	}
	if !(brutalParams{rate: 1, cwndGain: 20}).valid() {
		t.Error("a rate and a cwnd_gain together are valid")
	}
}

// ---------------------------------------------------------------------------
// Warning dedup
// ---------------------------------------------------------------------------

func TestWarnGateReportsEachKeyOnce(t *testing.T) {
	core, obs := observer.New(zap.WarnLevel)
	lg := zap.New(core)
	g := newWarnGate()

	g.warnOnce("a", "first", lg)
	g.warnOnce("a", "first again", lg)
	g.warnOnce("b", "second", lg)
	if got := obs.Len(); got != 2 {
		t.Fatalf("gate logged %d warnings, want 2 (one per key)", got)
	}
	if got := obs.All()[1].Message; got != "second" {
		t.Errorf("second warning = %q, want the distinct message", got)
	}

	// A nil gate and a nil logger must both be inert, not a panic: applyBrutal
	// is called from the dial hot path with whatever a caller hands over.
	(*warnGate)(nil).warnOnce("c", "nil gate", lg)
	g.warnOnce("d", "nil logger", nil)
	if got := obs.Len(); got != 2 {
		t.Errorf("nil gate or nil logger added %d warnings", got-2)
	}
}

// ---------------------------------------------------------------------------
// The listener wrapper and the non-TCP paths
// ---------------------------------------------------------------------------

// TestBrutalListenerNeverFailsAnAccept is the cardinal invariant of the whole
// feature: an optimisation that cannot be applied must not take a tunnel
// connection down.
func TestBrutalListenerNeverFailsAnAccept(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wrapped := newBrutalListener(ln, func(net.Conn) {})
	if wrapped.Addr() != ln.Addr() {
		t.Fatalf("Addr() = %v, want the wrapped listener's %v", wrapped.Addr(), ln.Addr())
	}

	dialer, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("Accept() failed: %v — an accept must never fail because brutal could not be applied", err)
	}
	conn.Close()

	// Close propagates, so the wrapper is a drop-in.
	if err := wrapped.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if _, err := wrapped.Accept(); err == nil {
		t.Error("Accept after Close returned no error")
	}

	// A nil apply hook is the "brutal is off" shape: still a plain pass-through.
	plain := newBrutalListener(ln, nil)
	plain.Close()
}

// TestApplyBrutalNeverTouchesANonTCPConn covers HTTP/3 (QUIC over UDP) and an
// embedder that injected a DialContext returning something that is not a TCP
// socket. Neither is a failure, so neither may panic or log.
func TestApplyBrutalNeverTouchesANonTCPConn(t *testing.T) {
	core, obs := observer.New(zap.WarnLevel)
	lg := zap.New(core)
	p := brutalParams{rate: 1_000_000, cwndGain: 20}

	udpLn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	// A round trip turns the listener into a real *net.UDPConn holding a live
	// socket descriptor, so applyBrutal runs its full non-TCP check and finds
	// nothing to set.
	// Dial the listener itself: port 0 on the peer side means "throw this
	// packet away", not "bind me and match it with the listener".
	udp, err := net.Dial("udp4", udpLn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := udp.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	udpSrv, ok := udpLn.(*net.UDPConn)
	if !ok {
		t.Fatalf("ListenPacket returned %T, want *net.UDPConn", udpLn)
	}
	udpSrv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	if _, _, err := udpSrv.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := udpSrv.WriteTo([]byte("reply"), udp.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	applyBrutal(p, udpSrv, newWarnGate(), lg)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	applyBrutal(p, a, newWarnGate(), lg)

	if got := obs.Len(); got != 0 {
		t.Errorf("a non-TCP connection produced %d warnings, want none", got)
	}
}

// TestApplyBrutalWarnsAtMostOncePerGate is the log-flood guard on a real TCP
// socket. On a host without the module this warns and moves on; on a host with
// it the socket is capped and nothing is logged. Either way the second call
// must be silent.
func TestApplyBrutalWarnsAtMostOncePerGate(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	core, obs := observer.New(zap.WarnLevel)
	g := newWarnGate()
	applyBrutal(brutalParams{rate: 1_000_000, cwndGain: 20}, conn, g, zap.New(core))
	applyBrutal(brutalParams{rate: 1_000_000, cwndGain: 20}, conn, g, zap.New(core))
	if got := obs.Len(); got > 1 {
		t.Errorf("two attempts on one gate logged %d warnings, want at most 1", got)
	}

	// A second gate is a second socket's worth of reporting.
	core2, obs2 := observer.New(zap.WarnLevel)
	applyBrutal(brutalParams{rate: 1_000_000, cwndGain: 20}, conn, newWarnGate(), zap.New(core2))
	if obs2.Len() == 0 && obs.Len() > 0 {
		t.Error("a fresh gate should report the same failure again")
	}
}

// ---------------------------------------------------------------------------
// Connection groups
// ---------------------------------------------------------------------------

func TestGroupIDFromRemote(t *testing.T) {
	samePort := groupIDFromRemote("127.0.0.1:5000")
	if samePort == 0 {
		t.Fatal("a group id must never be zero: zero means per-connection, no group")
	}
	// The key assertion: a source port is ephemeral, so hashing "ip:port"
	// would make every connection its own group and defeat the aggregate cap.
	if otherPort := groupIDFromRemote("127.0.0.1:5001"); otherPort != samePort {
		t.Errorf("127.0.0.1:5000 -> %d but 127.0.0.1:5001 -> %d; only the host is hashed", samePort, otherPort)
	}
	if again := groupIDFromRemote("127.0.0.1:5000"); again != samePort {
		t.Errorf("not stable: %d then %d", samePort, again)
	}
	if other := groupIDFromRemote("10.0.0.7:5000"); other == samePort {
		t.Error("two different hosts shared one group")
	}
	// Peers behind one NAT deliberately share a group; that is intended.
	if groupIDFromRemote("192.168.1.20:40000") != groupIDFromRemote("192.168.1.20:55000") {
		t.Error("a NAT address must yield one group for all of its connections")
	}
	// An address with no port is used verbatim rather than rejected.
	if groupIDFromRemote("10.0.0.7") == 0 {
		t.Error("a bare host must still yield a non-zero group id")
	}
	// Bracketed IPv6 literals must hash the bare address, so ports vary freely.
	if groupIDFromRemote("[::1]:443") == 0 {
		t.Fatal("an IPv6 literal must yield a non-zero group id")
	}
	if groupIDFromRemote("[::1]:443") != groupIDFromRemote("[::1]:51234") {
		t.Error("an IPv6 source port split the group")
	}
	if groupIDFromRemote("[::1]:443") == groupIDFromRemote("127.0.0.1:443") {
		t.Error("::1 and 127.0.0.1 must not share a group")
	}
}

func TestMergeBrutalRate(t *testing.T) {
	cases := []struct {
		configured, advertised, want uint64
	}{
		{0, 0, 0},                 // neither side offers anything
		{5, 0, 5},                 // peer declined to advertise
		{0, 3, 3},                 // static is unset, so the peer's value stands
		{10, 3, 3},                // peer lowers the ceiling
		{3, 10, 3},                // a peer may never raise it
		{5, 5, 5},                 // equal values
		{1_000_000_000_000, 1, 1}, // the hostile case: a tiny value wins
	}
	for _, tc := range cases {
		if got := mergeBrutalRate(tc.configured, tc.advertised); got != tc.want {
			t.Errorf("mergeBrutalRate(%d, %d) = %d, want %d", tc.configured, tc.advertised, got, tc.want)
		}
	}
}

func TestParseBwValue(t *testing.T) {
	for _, s := range []string{"1", "1000000", "  1000000  ", strconv.FormatUint(bwWireMax, 10)} {
		v, ok := parseBwValue(s)
		if !ok {
			t.Errorf("parseBwValue(%q) rejected a valid value", s)
			continue
		}
		want, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
		if v != want {
			t.Errorf("parseBwValue(%q) = %d, want %d", s, v, want)
		}
	}
	for _, s := range []string{
		"", "0", "-1", "abc", "1e12", "1.5", "0x10",
		strconv.FormatUint(bwWireMax+1, 10), // just over the wire bound
		"99999999999999999999999999",        // overflow
		"1000000 1000000",
	} {
		if _, ok := parseBwValue(s); ok {
			t.Errorf("parseBwValue(%q) accepted an invalid value", s)
		}
	}
}

func TestHasBrutalBwCap(t *testing.T) {
	for _, s := range []string{
		CapBrutalBw,
		"foo, " + CapBrutalBw + " ,bar",
		"  " + CapBrutalBw + "  ",
		CapBrutalBw + ",foo",
	} {
		if !hasBrutalBwCap(s) {
			t.Errorf("hasBrutalBwCap(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "foo,bar", CapBrutalBw + "X", "brutal-bwX,foo"} {
		if hasBrutalBwCap(s) {
			t.Errorf("hasBrutalBwCap(%q) = true, want false", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestBrutalConfigValidate(t *testing.T) {
	off := func() BrutalConfig { return BrutalConfig{} }
	cases := []struct {
		name     string
		mode     string
		mutate   func(*BrutalConfig)
		wantErr  string
		wantGain uint32
		wantIntv int
	}{
		{name: "fully off is always legal", mode: "client", mutate: func(*BrutalConfig) {}},
		{
			name: "enabled with a static rate", mode: "client",
			mutate: func(c *BrutalConfig) { c.Enabled, c.Rate = true, 1_000_000 },
		},
		{
			name:   "enabled with no rate is legal when the exchange supplies one",
			mode:   "client",
			mutate: func(c *BrutalConfig) { c.Enabled, c.BWExchange = true, true },
		},
		{
			name: "enabled with no rate and no exchange is rejected",
			mode: "client", mutate: func(c *BrutalConfig) { c.Enabled = true },
			wantErr: "brutal.rate is 0",
		},
		{
			name: "bw_exchange without enabled is rejected",
			mode: "client", mutate: func(c *BrutalConfig) { c.BWExchange = true },
			wantErr: "brutal.bw_exchange requires brutal.enabled",
		},
		{
			name: "bw_advertise without bw_exchange is rejected",
			mode: "server", mutate: func(c *BrutalConfig) { c.BWAdvertise = 1 },
			wantErr: "brutal.bw_advertise requires brutal.bw_exchange",
		},
		{
			name:   "bw_advertise with bw_exchange is legal even when rate is 0",
			mode:   "server",
			mutate: func(c *BrutalConfig) { c.Enabled, c.BWExchange, c.BWAdvertise = true, true, 1 },
		},
		{
			name: "a rate over the wire bound is rejected",
			mode: "client", mutate: func(c *BrutalConfig) { c.Enabled, c.Rate = true, bwWireMax+1 },
			wantErr: "brutal.rate",
		},
		{
			name: "a rate at the wire bound is accepted",
			mode: "client", mutate: func(c *BrutalConfig) { c.Enabled, c.Rate = true, bwWireMax },
		},
		{
			name: "an advertisement over the wire bound is rejected",
			mode: "server", mutate: func(c *BrutalConfig) { c.BWAdvertise = bwWireMax + 1 },
			wantErr: "brutal.bw_advertise",
		},
		{
			name: "a cwnd_gain above the range is rejected",
			mode: "client", mutate: func(c *BrutalConfig) { c.CwndGain = brutalGainMax + 1 },
			wantErr: "brutal.cwnd_gain",
		},
		{
			name: "a cwnd_gain at the range is accepted", mode: "client",
			mutate: func(c *BrutalConfig) { c.CwndGain = brutalGainMax }, wantGain: brutalGainMax,
		},
		{
			name: "a negative bw_interval is rejected",
			mode: "client", mutate: func(c *BrutalConfig) { c.BWInterval = -1 },
			wantErr: "brutal.bw_interval",
		},
		{
			name: "group_from_remote is server only",
			mode: "client", mutate: func(c *BrutalConfig) { c.GroupFromRemote = true },
			wantErr: "server-side option",
		},
		{
			name: "group_from_remote on a server is legal",
			mode: "server", mutate: func(c *BrutalConfig) { c.GroupFromRemote = true },
		},
		{
			name:     "zero values normalise even when brutal is off",
			mode:     "client",
			mutate:   func(*BrutalConfig) {},
			wantGain: brutalGainDefault,
			wantIntv: bwIntervalDefault,
		},
		{
			name:     "an explicit bw_interval is kept",
			mode:     "client",
			mutate:   func(c *BrutalConfig) { c.BWInterval = 7 },
			wantIntv: 7,
		},
		{
			name:    "a negative bw_interval is rejected even when brutal is off",
			mode:    "client",
			mutate:  func(c *BrutalConfig) { c.BWInterval = -3 },
			wantErr: "brutal.bw_interval",
		},
		{
			name:    "an invalid cwnd_gain is rejected even when brutal is off",
			mode:    "client",
			mutate:  func(c *BrutalConfig) { c.CwndGain = 200 },
			wantErr: "brutal.cwnd_gain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := off()
			tc.mutate(&c)
			err := c.Validate(tc.mode)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate returned %v, want nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate returned %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantGain != 0 && c.CwndGain != tc.wantGain {
				t.Errorf("cwnd_gain = %d, want %d", c.CwndGain, tc.wantGain)
			}
			if tc.wantIntv != 0 && c.BWInterval != tc.wantIntv {
				t.Errorf("bw_interval = %d, want %d", c.BWInterval, tc.wantIntv)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The bandwidth exchange, server side
// ---------------------------------------------------------------------------

const bwTestPSK = "bw-exchange-secret"

func bwTestState(cfg BrutalConfig) *serverState {
	st := newServerState(1)
	st.brutalCfg = cfg
	st.customLog = zap.NewNop()
	return st
}

// bwTestServer brings up a real server whose allowlist denies the ordinary
// targets the requests below ask for. That makes a denied target's 403 the
// marker for "authentication passed", 407 the marker for "authentication
// failed", and it proves the exchange is not silently caught by the allowlist.
func bwTestServer(t *testing.T, ctx context.Context, cfg ServerConfig) *url.URL {
	t.Helper()
	cfg.Listen = "tcp://127.0.0.1:0"
	cfg.Path = "/t"
	cfg.PSK = bwTestPSK
	if len(cfg.AllowedTargets) == 0 {
		cfg.AllowedTargets = []string{"127.0.0.1:9"}
	}
	if cfg.Handler == nil {
		cfg.Handler = func(c *XHTTPConn) { defer c.Close() }
	}
	srv, err := NewServer(cfg)
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
	return &url.URL{Scheme: "http", Host: srv.Addr().String(), Path: "/t"}
}

func bwSignedHeaders(t *testing.T, key, target, advertised string) map[string]string {
	t.Helper()
	const session = "bw-exchange-sid"
	nonce, err := newAuthNonce()
	if err != nil {
		t.Fatalf("newAuthNonce: %v", err)
	}
	h := map[string]string{
		"X-Session-ID":  session,
		"X-Target":      target,
		ProtoHeader:     strconv.Itoa(offeredProtoVersion),
		AuthNonceHeader: nonce,
		AuthMACHeader:   authMAC(key, authMessage(nonce, session, target)),
	}
	if advertised != "" {
		h[BwHeader] = advertised
	}
	return h
}

func bwPost(t *testing.T, base *url.URL, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base.String(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp
}

func TestBwExchangeServerServesExchange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := bwTestServer(t, ctx, ServerConfig{
		Brutal: BrutalConfig{
			Enabled: true, Rate: 20_000_000,
			GroupFromRemote: true, BWExchange: true, BWAdvertise: 5_000_000,
		},
	})

	resp := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, TargetBwExchange, "8000000"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get(CapsHeader); got != CapBrutalBw {
		t.Errorf("capability header = %q, want %q", got, CapBrutalBw)
	}
	if got := resp.Header.Get(BwHeader); got != "5000000" {
		t.Errorf("advertised bandwidth = %q, want the server's 5000000", got)
	}
	// The handler also sends "Connection: close" (see the direct assertions
	// in TestBwExchangeHandlerHeaders), but net/http drops hop-by-hop headers
	// from the response, so it is not observable here.
}

// TestBwExchangeRequiresAuth pins the branch order: the exchange sits after
// authentication, so it cannot be used unauthenticated.
func TestBwExchangeRequiresAuth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := bwTestServer(t, ctx, ServerConfig{
		Brutal: BrutalConfig{Enabled: true, Rate: 1_000_000, BWExchange: true},
	})

	// No credentials at all.
	plain := map[string]string{"X-Session-ID": "bw-exchange-sid", "X-Target": TargetBwExchange, ProtoHeader: "1"}
	if got := bwPost(t, base, plain).StatusCode; got != http.StatusProxyAuthRequired {
		t.Errorf("unauthenticated exchange = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	// A wrong key.
	if got := bwPost(t, base, bwSignedHeaders(t, "wrong-key", TargetBwExchange, "")).StatusCode; got != http.StatusProxyAuthRequired {
		t.Errorf("bad-key exchange = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	// A valid signature.
	if got := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, TargetBwExchange, "")).StatusCode; got != http.StatusOK {
		t.Errorf("authenticated exchange = %d, want 200", got)
	}
}

// TestBwExchangeSignedNonceBindsSpecialTarget proves the special target goes
// through the same signed-nonce machinery as every other target, with no
// separate code path: a signature minted for a real address must not open an
// exchange.
func TestBwExchangeSignedNonceBindsSpecialTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := bwTestServer(t, ctx, ServerConfig{
		Brutal: BrutalConfig{Enabled: true, Rate: 1_000_000, BWExchange: true},
	})

	for _, tc := range []struct {
		name       string
		signFor    string
		sendTarget string
	}{
		{"a signature for a real address cannot open an exchange", "127.0.0.1:22", TargetBwExchange},
		{"an exchange signature cannot be retargeted", TargetBwExchange, "127.0.0.1:22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := bwSignedHeaders(t, bwTestPSK, tc.signFor, "")
			h["X-Target"] = tc.sendTarget
			if got := bwPost(t, base, h).StatusCode; got != http.StatusProxyAuthRequired {
				t.Errorf("retargeted request = %d, want %d", got, http.StatusProxyAuthRequired)
			}
		})
	}
}

// TestBwExchangeRejectedWhenServerOptedOut is the backwards-compatibility
// half: a server that does not implement the protocol answers like any
// unparseable target, so an old server costs a client at most one probe.
func TestBwExchangeRejectedWhenServerOptedOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := bwTestServer(t, ctx, ServerConfig{
		Brutal: BrutalConfig{Enabled: true, Rate: 1_000_000, BWExchange: false},
	})
	resp := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, TargetBwExchange, "1000000"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an opted-out server answered %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestBwExchangeBypassesTheAllowlist: the special target is a protocol request
// rather than an address, so it must not be rejected by address policy. The
// server's allowlist below denies every ordinary target, which is the point.
func TestBwExchangeBypassesTheAllowlist(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := bwTestServer(t, ctx, ServerConfig{
		AllowedTargets: []string{"127.0.0.1:9"},
		Brutal:         BrutalConfig{Enabled: true, Rate: 1_000_000, BWExchange: true},
	})

	if got := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, TargetBwExchange, "")).StatusCode; got != http.StatusOK {
		t.Errorf("exchange = %d, want 200: the special target must not be subject to the allowlist", got)
	}
	if got := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, "127.0.0.1:22", "")).StatusCode; got != http.StatusForbidden {
		t.Errorf("an ordinary denied target = %d, want %d", got, http.StatusForbidden)
	}
	if got := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, "127.0.0.1:9", "")).StatusCode; got != http.StatusOK {
		t.Errorf("an allowlisted target = %d, want 200", got)
	}
}

// TestBwExchangeRegistersNoSession: the exchange opens no bridge, so it must
// not consume the session budget.
func TestBwExchangeRegistersNoSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := ServerConfig{
		MaxSessions: 3,
		Brutal:      BrutalConfig{Enabled: true, Rate: 1_000_000, BWExchange: true},
	}
	srv, err := NewServer(withBwDefaults(cfg))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	base := &url.URL{Scheme: "http", Host: srv.Addr().String(), Path: "/t"}

	for i := 0; i < 10; i++ {
		resp := bwPost(t, base, bwSignedHeaders(t, bwTestPSK, TargetBwExchange, strconv.Itoa(1000000+i)))
		resp.Body.Close()
	}
	if got := srv.ActiveSessions(); got != 0 {
		t.Errorf("ten exchanges left %d live sessions, want 0", got)
	}
	if got := srv.SessionIDs(); len(got) != 0 {
		t.Errorf("ten exchanges registered %v, want nothing", got)
	}
}

// withBwDefaults fills in the fields bwTestServer would otherwise set, for the
// one test that needs to reach the Server value directly.
func withBwDefaults(cfg ServerConfig) ServerConfig {
	cfg.Listen = "tcp://127.0.0.1:0"
	cfg.Path = "/t"
	cfg.PSK = bwTestPSK
	if len(cfg.AllowedTargets) == 0 {
		cfg.AllowedTargets = []string{"127.0.0.1:9"}
	}
	if cfg.Handler == nil {
		cfg.Handler = func(c *XHTTPConn) { defer c.Close() }
	}
	return cfg
}

func TestBwExchangeUpdatesTheGroupRate(t *testing.T) {
	cases := []struct {
		name       string
		advertised string
		want       uint64
	}{
		{"the peer lowers the ceiling", "8000000", 8_000_000},
		{"the peer cannot raise it", "99999999999", 20_000_000},
		{"the configured value is the ceiling", "20000000", 20_000_000},
		{"no advertisement keeps the rate that is in force", "", 20_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := bwTestState(BrutalConfig{Enabled: true, Rate: 20_000_000, GroupFromRemote: true, BWExchange: true})
			r := httptest.NewRequest(http.MethodPost, "/t", http.NoBody)
			r.RemoteAddr = "10.0.0.7:51000"
			if tc.advertised != "" {
				r.Header.Set(BwHeader, tc.advertised)
			}
			st.handleBwExchange(httptest.NewRecorder(), r, "10.0.0.7")
			gid := groupIDFromRemote(r.RemoteAddr)
			if got := st.groupRate(gid, 20_000_000); got != tc.want {
				t.Errorf("group rate = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestBwExchangeRejectsMalformedAdvertise: a garbage or hostile value must
// never stall the group, which is what applying a zero rate would do.
func TestBwExchangeRejectsMalformedAdvertise(t *testing.T) {
	for _, raw := range []string{"0", "-1", "abc", "1e12", "1.5", "99999999999999999999", "1000000000001"} {
		t.Run(raw, func(t *testing.T) {
			st := bwTestState(BrutalConfig{Enabled: true, Rate: 20_000_000, GroupFromRemote: true, BWExchange: true})
			r := httptest.NewRequest(http.MethodPost, "/t", http.NoBody)
			r.RemoteAddr = "10.0.0.7:51000"
			r.Header.Set(BwHeader, raw)
			rr := httptest.NewRecorder()
			st.handleBwExchange(rr, r, "10.0.0.7")
			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200: an invalid advertisement is not an error", rr.Code)
			}
			gid := groupIDFromRemote(r.RemoteAddr)
			if got := st.groupRate(gid, 20_000_000); got != 20_000_000 {
				t.Errorf("an invalid value changed the group rate to %d, want the unchanged 20000000", got)
			}
		})
	}
}

func TestBwExchangeDoesNotAdvertiseWhenConfiguredAsZero(t *testing.T) {
	st := bwTestState(BrutalConfig{Enabled: true, Rate: 1_000_000, BWExchange: true, BWAdvertise: 0})
	rr := httptest.NewRecorder()
	st.handleBwExchange(rr, httptest.NewRequest(http.MethodPost, "/t", http.NoBody), "10.0.0.7")
	if got := rr.Header().Get(BwHeader); got != "" {
		t.Errorf("an unset bw_advertise still advertised %q", got)
	}
	if got := rr.Header().Get(CapsHeader); got != CapBrutalBw {
		t.Errorf("capability = %q, want %q", got, CapBrutalBw)
	}
	if got := rr.Code; got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
}

// TestBwExchangeHandlerHeaders pins the wire shape of the reply. The
// recorder sees what the handler actually wrote, including the hop-by-hop
// header net/http would strip on the way through a real client.
func TestBwExchangeHandlerHeaders(t *testing.T) {
	st := bwTestState(BrutalConfig{
		Enabled: true, Rate: 1_000_000, BWExchange: true, BWAdvertise: 2_500_000,
	})
	rr := httptest.NewRecorder()
	st.handleBwExchange(rr, httptest.NewRequest(http.MethodPost, "/t", http.NoBody), "10.0.0.7")

	if got := rr.Code; got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
	if got := rr.Header().Get(CapsHeader); got != CapBrutalBw {
		t.Errorf("capability = %q, want %q", got, CapBrutalBw)
	}
	if got := rr.Header().Get(BwHeader); got != "2500000" {
		t.Errorf("advertised bandwidth = %q, want 2500000", got)
	}
	// One tiny request per bw_interval; there is no reason to keep the socket
	// warm for it, so the handler tells the client to go home.
	if got := rr.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close", got)
	}
	// And nothing in the body.
	if got := rr.Body.String(); got != "" {
		t.Errorf("body = %q, want empty", got)
	}
}

// TestServerGroupRateTable covers the gap the kernel leaves: a brutal group's
// state exists only while at least one member is open, so a value negotiated
// while the group is alive must survive the last member closing and be
// re-applied to the next one.
func TestServerGroupRateTable(t *testing.T) {
	st := bwTestState(BrutalConfig{Enabled: true, Rate: 100, CwndGain: 20})

	if got := st.groupRate(7, 100); got != 100 {
		t.Fatalf("an unrecorded group falls back to the configured rate: got %d, want 100", got)
	}
	st.setGroupRate(7, 42)
	if got := st.groupRate(7, 100); got != 42 {
		t.Fatalf("group 7 = %d, want the negotiated 42", got)
	}
	if got := st.groupRate(8, 100); got != 100 {
		t.Errorf("a rate set for group 7 leaked into group 8: %d", got)
	}
	// A zero group id is the per-connection case; it is still keyed, and it
	// must not collide with a real group.
	st.setGroupRate(0, 5)
	if got := st.groupRate(0, 100); got != 5 {
		t.Errorf("group 0 = %d, want 5", got)
	}
	if got := st.groupRate(7, 100); got != 42 {
		t.Errorf("group 7 = %d after touching group 0, want 42", got)
	}
	// Re-negotiating replaces the value rather than stacking on it.
	st.setGroupRate(7, 99)
	if got := st.groupRate(7, 100); got != 99 {
		t.Errorf("group 7 = %d after re-negotiation, want 99", got)
	}
}

// TestServerGroupRateSurvivesTheLastMember is the reason the table exists at
// all: noteGroupConn forgets a closed connection, and the next accept for the
// same group must still see the negotiated rate.
func TestServerGroupRateSurvivesTheLastMember(t *testing.T) {
	st := bwTestState(BrutalConfig{Enabled: true, Rate: 100, CwndGain: 20})
	gid := groupIDFromRemote("10.0.0.7:51000")

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	st.noteGroupConn(gid, a)
	st.setGroupRate(gid, 37)
	// The group's only member closes, so the kernel drops its state.
	a.Close()
	b.Close()

	if got := st.groupRate(gid, 100); got != 37 {
		t.Fatalf("after the last member closed, group %d = %d, want the remembered 37", gid, got)
	}
	// The next member is recorded and offered the remembered rate.
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	st.noteGroupConn(gid, c)
	if got := st.groupRate(gid, 100); got != 37 {
		t.Errorf("a new member sees group rate %d, want 37", got)
	}
}

// ---------------------------------------------------------------------------
// The bandwidth exchange, client side
// ---------------------------------------------------------------------------

// bwExchangeClient builds a client pointed at url with the exchange enabled.
func bwExchangeClient(t *testing.T, url string, cfg BrutalConfig) *Client {
	t.Helper()
	if err := cfg.Validate("client"); err != nil {
		t.Fatalf("BrutalConfig.Validate: %v", err)
	}
	client, err := NewClient(ClientConfig{
		ServerURL:  url,
		PSK:        bwTestPSK,
		ALPN:       "h1",
		StreamMode: "poll",
		Brutal:     cfg,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestBwExchangeClientAppliesAdvertised is the symmetric direction: the peer's
// advertised ingest capacity becomes this side's send rate, merged against the
// configured ceiling.
func TestBwExchangeClientAppliesAdvertised(t *testing.T) {
	var sawTarget, sawCaps, sawBW, sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTarget = r.Header.Get("X-Target")
		sawCaps = r.Header.Get(CapsHeader)
		sawBW = r.Header.Get(BwHeader)
		sawAuth = r.Header.Get(AuthNonceHeader)
		w.Header().Set(CapsHeader, CapBrutalBw)
		w.Header().Set(BwHeader, "5000000")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := bwExchangeClient(t, srv.URL+"/t", BrutalConfig{
		Enabled: true, Rate: 20_000_000, BWExchange: true, BWAdvertise: 7_000_000,
	})
	if !client.doBwExchange(context.Background()) {
		t.Fatal("a completed exchange must stay enabled")
	}
	if got := client.bwNegotiated.Load(); got != 5_000_000 {
		t.Errorf("bwNegotiated = %d, want the peer's advertised 5000000", got)
	}
	if got := mergeBrutalRate(20_000_000, client.bwNegotiated.Load()); got != 5_000_000 {
		t.Errorf("effective rate = %d, want 5000000", got)
	}
	if sawTarget != TargetBwExchange {
		t.Errorf("target = %q, want %q", sawTarget, TargetBwExchange)
	}
	if sawAuth == "" {
		t.Error("the exchange request carried no nonce, so it is not authenticated")
	}
	if sawBW != "7000000" {
		t.Errorf("advertised bandwidth = %q, want the configured 7000000", sawBW)
	}
	if sawCaps != "" {
		t.Errorf("the client must not send a capability list, got %q", sawCaps)
	}
}

// TestBwExchangeClientClassifiesFailure keeps the two failure classes apart: an
// old server's 404 is permanent, while an unreachable server is transient and
// worth retrying after bw_interval.
func TestBwExchangeClientClassifiesFailure(t *testing.T) {
	var hits int64
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer oldServer.Close()

	client := bwExchangeClient(t, oldServer.URL+"/t", BrutalConfig{
		Enabled: true, Rate: 1_000_000, BWExchange: true, BWInterval: 60,
	})
	if client.doBwExchange(context.Background()) {
		t.Fatal("an old server's 404 must disable the loop permanently")
	}

	// An unreachable server must not disable it.
	clientUnreachable := bwExchangeClient(t, "http://127.0.0.1:1/t", BrutalConfig{
		Enabled: true, Rate: 1_000_000, BWExchange: true, BWInterval: 60,
	})
	if !clientUnreachable.doBwExchange(context.Background()) {
		t.Fatal("an unreachable server is transient and must be retried")
	}

	// And a server that answers the protocol but declines to advertise has
	// nothing to apply: still a success, still enabled.
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(CapsHeader, CapBrutalBw)
		w.WriteHeader(http.StatusOK)
	}))
	defer silent.Close()
	clientSilent := bwExchangeClient(t, silent.URL+"/t", BrutalConfig{
		Enabled: true, Rate: 1_000_000, BWExchange: true, BWInterval: 60,
	})
	if !clientSilent.doBwExchange(context.Background()) {
		t.Fatal("a server that declined to advertise must keep the loop enabled")
	}
	if got := clientSilent.bwNegotiated.Load(); got != 0 {
		t.Errorf("bwNegotiated = %d after a silent server, want 0", got)
	}

	// A server that implements the protocol but sends a malformed value keeps
	// the loop enabled and keeps the rate it had.
	badValue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(CapsHeader, CapBrutalBw)
		w.Header().Set(BwHeader, "not-a-rate")
		w.WriteHeader(http.StatusOK)
	}))
	defer badValue.Close()
	clientBad := bwExchangeClient(t, badValue.URL+"/t", BrutalConfig{
		Enabled: true, Rate: 1_000_000, BWExchange: true, BWInterval: 60,
	})
	if !clientBad.doBwExchange(context.Background()) {
		t.Fatal("a malformed advertisement must not disable the loop")
	}
	if got := clientBad.bwNegotiated.Load(); got != 0 {
		t.Errorf("bwNegotiated = %d after a malformed advertisement, want 0", got)
	}

	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("the old server saw %d probes, want 1", got)
	}
}

// TestBwExchangeClientDisablesAfterOneProbe exercises the throttling and the
// permanent disable together: one process lifetime must cost the server at most
// one session against a version that predates the protocol.
func TestBwExchangeClientDisablesAfterOneProbe(t *testing.T) {
	var hits int64
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer oldServer.Close()

	client := bwExchangeClient(t, oldServer.URL+"/t", BrutalConfig{
		Enabled: true, Rate: 1_000_000, BWExchange: true, BWInterval: 60,
	})
	ctx := context.Background()

	// The first dial probes. bwBusy keeps concurrent dials to one attempt.
	for i := 0; i < 5; i++ {
		client.maybeBwExchange(ctx)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !client.bwDone.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !client.bwDone.Load() {
		t.Fatal("an old server's response did not disable the exchange")
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("five concurrent dials sent %d probes, want 1", got)
	}
	// After the disable every further dial is inert.
	for i := 0; i < 20; i++ {
		client.maybeBwExchange(ctx)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("the disabled loop sent %d probes in total, want 1", got)
	}
}

// TestBwExchangeClientHonoursTheInterval: the exchange is a full round trip, so
// a burst of dials within bw_interval must not each send one.
func TestBwExchangeClientHonoursTheInterval(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set(CapsHeader, CapBrutalBw)
		w.Header().Set(BwHeader, "1000000")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := bwExchangeClient(t, srv.URL+"/t", BrutalConfig{
		Enabled: true, Rate: 10_000_000, BWExchange: true, BWInterval: 60,
	})
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		client.maybeBwExchange(ctx)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && client.bwBusy.Load() != 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("twenty-five dials within one interval sent %d probes, want 1", got)
	}
	if got := client.bwNegotiated.Load(); got != 1_000_000 {
		t.Errorf("bwNegotiated = %d, want 1000000", got)
	}
	if client.bwDone.Load() {
		t.Error("a successful exchange must not disable the loop")
	}
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

// TestBwExchangeEndToEnd runs a real server and a real client, both with the
// exchange enabled, over loopback. The point is twofold: the negotiation
// actually converges, and — the cardinal invariant — data still tunnels.
func TestBwExchangeEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	// No Handler: the end-to-end test needs the built-in target bridge, and
	// withBwDefaults installs a close-and-exit stub whenever Handler is nil.
	cfg := ServerConfig{
		Listen:         "tcp://127.0.0.1:0",
		Path:           "/t",
		PSK:            bwTestPSK,
		AllowedTargets: []string{"*"}, // the client dials a random echo port
		Brutal: BrutalConfig{
			Enabled: true, Rate: 20_000_000,
			BWExchange: true, BWAdvertise: 3_000_000, BWInterval: 60,
		},
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.ListenAndServe(ctx) }()
	t.Cleanup(func() { _ = srv.Close() })
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("server did not bind")
	}

	client := bwExchangeClient(t, "http://"+srv.Addr().String()+"/t", BrutalConfig{
		Enabled: true, Rate: 40_000_000,
		BWExchange: true, BWAdvertise: 2_000_000, BWInterval: 60,
	})

	// A tunnel dial is what triggers the exchange. This connection is the one
	// that gets thrown away: with no connection group there is nothing to
	// push a new rate onto, so applyBw closes idle pooled connections and
	// makes them redial at the negotiated rate. Dial again for the data.
	if conn, err := client.DialContext(ctx, "tcp", echoLn.Addr().String()); err != nil {
		t.Fatalf("DialContext: %v", err)
	} else {
		conn.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && client.bwNegotiated.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := client.bwNegotiated.Load(); got != 3_000_000 {
		t.Fatalf("the client negotiated %d, want the server's advertised 3000000", got)
	}
	if got := mergeBrutalRate(40_000_000, client.bwNegotiated.Load()); got != 3_000_000 {
		t.Errorf("effective rate = %d, want 3000000", got)
	}
	if client.bwDone.Load() {
		t.Error("a successful end-to-end exchange disabled the loop")
	}

	conn, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext after negotiation: %v", err)
	}
	defer conn.Close()

	// The tunnel itself still works: the negotiated rate must not have broken
	// the data path.
	payload := []byte("tcp brutal must not break a tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	buf := make([]byte, len(payload))
	n := 0
	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		m, err := conn.Read(buf[n:])
		n += m
		if n == len(payload) {
			break
		}
		if err != nil {
			t.Fatalf("read through the tunnel after %d bytes: %v", n, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out reading the echo back, got %q of %q", buf[:n], payload)
		}
	}
	if string(buf) != string(payload) {
		t.Errorf("echoed %q, want %q", buf, payload)
	}
}
