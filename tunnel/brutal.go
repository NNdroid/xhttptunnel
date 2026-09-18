// brutal.go implements TCP Brutal support and the bandwidth exchange that goes
// with it.
//
// TCP Brutal is a Linux kernel TCP congestion control that caps how fast a
// connection — or a *group* of connections — may send, in bytes per second.
// This file holds everything platform-neutral: configuration and validation,
// the on-wire formats, the degradation ladder, connection groups and the
// bandwidth exchange. The actual setsockopt calls sit behind the brutalOps
// interface, which brutal_linux.go implements and every other platform
// replaces with a no-op.
//
// Brutal is an optimisation, never a dependency: no socket error here may be
// able to fail a tunnel connection. Only configuration mistakes are rejected,
// and only at startup.

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const (
	// TargetBwExchange is the special target address that turns a tunnel
	// session into a bandwidth exchange instead of a forwarding connection.
	// The literal is the one the upstream TCP Brutal guide recommends, so a
	// server built against another implementation stays interoperable.
	TargetBwExchange = "_BrutalBwExchange"

	// BwHeader carries the receiver-side ceiling: the fastest the peer may
	// send this side data, in bytes/s. The peer applies it as its own send
	// rate, so the two ends converge on whatever the slower link tolerates.
	//
	// The value is what this side can *ingest*, not what it wants to send.
	// Advertising your downlink makes the server slow its uplink down to it;
	// the server advertising its ingest capacity makes the client slow its
	// uplink down.
	BwHeader = "X-HTTP-Tunnel-Bw"

	// CapsHeader lists the extensions a server implements. The client reads it
	// to tell an exchange-capable server from an older one with no protocol
	// bump: an old server rejects TargetBwExchange like any unparseable
	// target, which is a clean non-200 rather than a partial exchange.
	CapsHeader  = "X-HTTP-Tunnel-Caps"
	CapBrutalBw = "brutal-bw"

	// TCP_BRUTAL_PARAMS. A private option number owned by the module, not
	// published by any standards body, so it is named here rather than
	// referenced from a system header.
	brutalParamsOpt = 23301

	// The struct is __packed, so there is no alignment padding between the u32
	// and the trailing u64: 8 + 4 + 8 = 20 bytes, matching
	// struct.pack("<QIQ", rate, cwnd_gain, group_id). An unpacked layout would
	// be 24 and would hand the kernel a struct it has never seen.
	brutalParamsLen = 20

	// cwnd_gain is stored in tenths because the kernel cannot take a float:
	// 10 is 1.0x, 15 is 1.5x, 20 is 2.0x. The default is the top of the range
	// the upstream guide recommends (1.5x-2.0x).
	brutalGainDefault = 20
	brutalGainMax     = 100

	// bwWireMax bounds any value that crosses the wire, so a garbage or hostile
	// advertisement cannot be applied. 1 TB/s.
	bwWireMax uint64 = 1_000_000_000_000

	bwIntervalDefault = 60
	bwIntervalMin     = 1
)

var (
	// errLocked means a locked TCP Brutal route rule already owns this
	// connection. The rule's parameters must not be overwritten, so a locked
	// socket is a success for our purposes rather than a failure.
	errLocked = errors.New("tcp brutal: a locked route rule owns this connection")

	// errNoModule means the kernel answers that the option is unknown, i.e. no
	// brutal module is loaded. The connection still works, uncapped.
	errNoModule = errors.New("tcp brutal: the kernel has no brutal module loaded")

	// errBrutalUnsupported means the platform has no implementation compiled in
	// at all. See brutal_other.go.
	errBrutalUnsupported = errors.New("tcp brutal: not supported on this platform")
)

// BrutalConfig enables TCP Brutal on the tunnel's TCP sockets. The struct is
// pure data on purpose: the mutable side (the rate negotiated by the bandwidth
// exchange, the warnings already reported) lives in separate types so the
// config stays copyable and comparable.
type BrutalConfig struct {
	// Enabled turns brutal on. False means setsockopt is never called at all,
	// so the option costs nothing on hosts that do not run the module.
	Enabled bool `json:"enabled"`
	// Rate caps the send rate of a connection in bytes/s. It is a ceiling: the
	// bandwidth exchange can only lower it. Zero is legal only together with
	// BWExchange, where the rate is supplied by the peer.
	Rate uint64 `json:"rate"`
	// CwndGain is the congestion window gain in tenths, so 15 means 1.5x.
	// Zero takes the default of 20 (2.0x).
	CwndGain uint32 `json:"cwnd_gain"`
	// GroupID groups connections: members with the same non-zero id within the
	// same user and network namespace share Rate as an aggregate ceiling, and
	// setting the parameters on any one member updates the whole group. Zero
	// means per-connection only, with no aggregate ceiling.
	GroupID uint64 `json:"group_id"`
	// GroupFromRemote (server only) derives the group id from the peer's IP
	// address instead of using GroupID. A static GroupID on a server would pool
	// every client into one limit, which is a global rate cap rather than a
	// per-client one.
	GroupFromRemote bool `json:"group_from_remote"`
	// BWExchange enables the _BrutalBwExchange protocol, which lets each side
	// tell the other how fast it can ingest.
	BWExchange bool `json:"bw_exchange"`
	// BWAdvertise is the rate this side tells its peer it can ingest, in
	// bytes/s. Zero means do not advertise anything; the other side's value is
	// still accepted and applied.
	BWAdvertise uint64 `json:"bw_advertise"`
	// BWInterval is the minimum gap between exchange attempts, in seconds. Zero
	// takes the default.
	BWInterval int `json:"bw_interval"`
}

// Validate applies the defaults and rejects combinations that cannot work. It
// normalises CwndGain and BWInterval in place, so callers must use the value
// after calling it. mode is "server" or "client" and is only needed to reject
// GroupFromRemote off-server, where there is no peer address to derive an id
// from.
func (c *BrutalConfig) Validate(mode string) error {
	if c.Rate > bwWireMax {
		return fmt.Errorf("tunnel: brutal.rate %d exceeds the %d bytes/s limit", c.Rate, bwWireMax)
	}
	if c.BWAdvertise > bwWireMax {
		return fmt.Errorf("tunnel: brutal.bw_advertise %d exceeds the %d bytes/s limit", c.BWAdvertise, bwWireMax)
	}
	if c.BWAdvertise > 0 && !c.BWExchange {
		// bw_advertise is only ever sent on an exchange request, so without
		// bw_exchange it is inert. Fail rather than accept a value that looks
		// like it is doing work but is not.
		return fmt.Errorf("tunnel: brutal.bw_advertise requires brutal.bw_exchange")
	}
	if c.BWExchange && !c.Enabled {
		return fmt.Errorf("tunnel: brutal.bw_exchange requires brutal.enabled")
	}
	// These two normalise even when brutal is off, so a rendered config always
	// shows the values that will be in force if the block is switched on later,
	// rather than a 0 that needs a comment to decode.
	if c.CwndGain == 0 {
		c.CwndGain = brutalGainDefault
	}
	if c.CwndGain > brutalGainMax {
		return fmt.Errorf("tunnel: brutal.cwnd_gain %d is out of range: use 1-%d tenths (20 means 2.0x), or 0 for the default", c.CwndGain, brutalGainMax)
	}
	if c.BWInterval == 0 {
		c.BWInterval = bwIntervalDefault
	}
	if c.BWInterval < bwIntervalMin {
		return fmt.Errorf("tunnel: brutal.bw_interval %d is too small (minimum %d seconds)", c.BWInterval, bwIntervalMin)
	}
	if c.GroupFromRemote && mode != "server" {
		return fmt.Errorf("tunnel: brutal.group_from_remote is a server-side option; %q mode has no peer address to derive a group id from", mode)
	}
	if !c.Enabled {
		return nil
	}
	if c.Rate == 0 && !c.BWExchange {
		return fmt.Errorf("tunnel: brutal.enabled is set but brutal.rate is 0: set a rate in bytes/s, or enable bw_exchange to let each peer supply one")
	}
	return nil
}

// bwCapable reports whether an exchange is worth attempting at all: brutal
// must be enabled, since a negotiated rate has nowhere to be applied.
func (c *BrutalConfig) bwCapable() bool { return c.Enabled && c.BWExchange }

// warnGate reports each distinct message at most once. The connection pool
// opens and closes sockets constantly, so an unusable option must not turn
// into a log flood: the first occurrence is the one that tells the operator
// anything.
type warnGate struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newWarnGate() *warnGate { return &warnGate{seen: make(map[string]struct{})} }

// warnOnce logs msg unless key has already been reported on this gate.
func (g *warnGate) warnOnce(key, msg string, lg *zap.Logger, fields ...zap.Field) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if _, ok := g.seen[key]; ok {
		g.mu.Unlock()
		return
	}
	g.seen[key] = struct{}{}
	g.mu.Unlock()
	if lg != nil {
		lg.Warn(msg, fields...)
	}
}

// brutalParams is the fully resolved configuration handed to enableBrutal. It
// is a value type so a caller can capture it for later re-application, which
// is exactly what pushing a negotiated rate to an existing group does.
type brutalParams struct {
	rate     uint64
	cwndGain uint32
	groupID  uint64
}

// valid reports whether there is anything to configure. A zero rate means
// "not configured yet" — either brutal is off or the bandwidth exchange has
// not negotiated a value — and calling setsockopt with a zero rate would be a
// mistake rather than a no-op.
func (p brutalParams) valid() bool { return p.rate > 0 && p.cwndGain > 0 }

// packBrutalParams encodes the __packed brutal_params struct in little-endian
// byte order: rate (u64), cwnd_gain (u32), group_id (u64). The layout is
// written by hand rather than via unsafe because the struct is packed, so its
// in-memory size is not the size the kernel expects.
func packBrutalParams(rate, groupID uint64, cwndGain uint32) []byte {
	out := make([]byte, brutalParamsLen)
	binary.LittleEndian.PutUint64(out[:8], rate)
	binary.LittleEndian.PutUint32(out[8:12], cwndGain)
	binary.LittleEndian.PutUint64(out[12:20], groupID)
	return out
}

// brutalOps is the socket-level surface enableBrutal drives. Production points
// it at the real syscalls; the non-Linux platform files return
// errBrutalUnsupported, and tests stub it to exercise every branch of the
// ladder without a kernel module. Errnos are normalised into the sentinels
// above so this file never imports the syscall package, which is what keeps the
// tests compiling on Windows.
type brutalOps interface {
	setCongestion(fd uintptr) error
	getCongestion(fd uintptr) (string, error)
	setParams(fd uintptr, data []byte) error
}

// enableBrutal turns brutal on for one socket, following the degradation
// ladder the module requires:
//
//  1. Select the algorithm. EPERM here means a locked route rule already owns
//     the connection, so the current algorithm is read back and, if it is
//     already brutal, the socket is left exactly as it is — overwriting the
//     rule's parameters is the one thing that must not happen.
//  2. Write the parameters. EPERM means a locked rule owns this connection and
//     the rule wins; that is a success.
//
// There is deliberately no fallback for a module that refuses the struct. A
// host where the algorithm name is accepted but the 20-byte write is not is
// running a brutal version that predates group_id; rather than silently
// dropping the group id and capping anyway, the error is returned so the
// caller reports it once and leaves the connection uncapped.
//
// errNoModule is not an error condition for the caller: the connection
// proceeds without a rate cap and the failure is reported once.
func enableBrutal(fd uintptr, p brutalParams, ops brutalOps) error {
	if err := ops.setCongestion(fd); err != nil {
		if !errors.Is(err, errLocked) {
			return err
		}
		algo, err := ops.getCongestion(fd)
		if err != nil {
			return err
		}
		if algo != "brutal" {
			return fmt.Errorf("tcp brutal: the route is locked with algorithm %q instead of brutal", algo)
		}
		return nil
	}

	if err := ops.setParams(fd, packBrutalParams(p.rate, p.groupID, p.cwndGain)); err != nil {
		if errors.Is(err, errLocked) {
			return nil
		}
		return err
	}
	return nil
}

// applyBrutal enables brutal on c. It never reports an error: brutal is an
// optimisation, and a missing kernel module must not be able to take a tunnel
// connection down. Each distinct failure is reported once per gate.
//
// The socket is reached with TCPConn.SyscallConn().Control rather than
// FileConn: Control borrows the descriptor for the duration of the callback and
// leaves the netpoller in charge, whereas FileConn would require
// SetBlocking(true) and hand the connection off the poller entirely.
func applyBrutal(p brutalParams, c net.Conn, gate *warnGate, lg *zap.Logger) {
	if !p.valid() {
		return
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		// UDP (HTTP/3), or an injected dialer that did not hand back a TCP
		// socket. The option does not exist for either, and there is nothing to
		// warn about — this is not a failure, just a path brutal does not apply
		// to.
		return
	}
	rc, rcErr := tc.SyscallConn()
	if rcErr != nil {
		gate.warnOnce("rawconn", "⚠️ [TCP] could not reach the socket descriptor for TCP Brutal; continuing without it", lg, zap.Error(rcErr))
		return
	}
	// Control's callback takes no return value, so the syscall error is
	// captured here and read back after Control has synchronised. Control's own
	// error only means the descriptor could not be borrowed at all.
	var setErr error
	err := rc.Control(func(fd uintptr) {
		setErr = enableBrutal(fd, p, defaultBrutalOps)
	})
	if err != nil {
		gate.warnOnce("rawconn", "⚠️ [TCP] could not reach the socket descriptor for TCP Brutal; continuing without it", lg, zap.Error(err))
		return
	}
	if setErr != nil {
		err = setErr
	} else {
		if ce := lg.Check(zap.DebugLevel, "⚡ [TCP] brutal enabled"); ce != nil {
			ce.Write(
				zap.Uint64("rate", p.rate),
				zap.Uint32("cwnd_gain", p.cwndGain),
				zap.Uint64("group_id", p.groupID),
			)
		}
		return
	}
	switch {
	case errors.Is(err, errLocked):
		gate.warnOnce("locked", "🔒 [TCP] a locked TCP Brutal route rule owns this connection; keeping the kernel's parameters", lg, zap.Error(err))
	case errors.Is(err, errNoModule):
		gate.warnOnce("nomodule", "⚠️ [TCP] TCP Brutal requested but the kernel has no brutal module loaded; the tunnel still works without it", lg, zap.Error(err))
	case errors.Is(err, errBrutalUnsupported):
		gate.warnOnce("un-supported", "⚠️ [TCP] TCP Brutal requested but it is Linux-only; the tunnel still works without it", lg)
	default:
		gate.warnOnce("other", "⚠️ [TCP] could not enable TCP Brutal; continuing without it", lg, zap.Error(err))
	}
}

// newBrutalApplier returns the per-socket hook the dial path calls after a
// successful connect, or nil when there is nothing to do. A nil hook leaves
// the dial path byte-for-byte what it was before brutal existed, so a client
// that never configures it pays nothing.
//
// The rate is looked up per socket rather than captured once: the bandwidth
// exchange may have negotiated a value between when the config was validated
// and when this socket was opened, and each pooled connection needs whatever
// is in force at its own connect time.
func newBrutalApplier(cfg *DialConfig) func(net.Conn) {
	if cfg == nil || !cfg.Brutal.Enabled || !brutalAvailable() {
		return nil
	}
	bc := cfg.Brutal
	gate := cfg.brutalWarns
	if gate == nil {
		gate = newWarnGate()
	}
	return func(c net.Conn) {
		rate := mergeBrutalRate(bc.Rate, cfg.bwRate())
		if rate == 0 {
			// bw_exchange without bw_advertise or a static rate, and no peer
			// value yet. Calling setsockopt with a zero rate would be wrong,
			// so there is simply nothing to configure.
			return
		}
		applyBrutal(brutalParams{rate: rate, cwndGain: bc.CwndGain, groupID: bc.GroupID}, c, gate, cfg.lg())
	}
}

// groupIDFromRemote derives a connection-group id from a peer address in
// "ip:port" form. Only the host is hashed: a source port is ephemeral, so
// hashing "ip:port" would make every connection its own group and defeat the
// purpose. Peers behind the same NAT naturally share one group, which is the
// intended behaviour. The result is never zero, which TCP Brutal reserves for
// "per-connection, no group".
//
// It is keyed off the real TCP peer, not a proxy header: the kernel names a
// group by the connection, and a spoofable header would let a client pick its
// own group and so its own aggregate ceiling.
func groupIDFromRemote(remote string) uint64 {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	h64 := fnv.New64a()
	_, _ = h64.Write([]byte(host))
	return h64.Sum64() | 1
}

// mergeBrutalRate combines a configured rate with one received from the peer.
// The configured value is a ceiling, so a peer can only lower it, never raise
// it — which also bounds a hostile advertisement, since it cannot push the rate
// above what the operator set. An advertised value of zero means the peer
// declined to report, so the configured value stands alone.
func mergeBrutalRate(configured, advertised uint64) uint64 {
	if advertised == 0 {
		return configured
	}
	if configured == 0 || advertised < configured {
		return advertised
	}
	return configured
}

// parseBwValue parses the X-HTTP-Tunnel-Bw header. ok is false for an empty,
// non-numeric, zero or out-of-range value; the caller must keep its current
// rate rather than apply zero, which would stall the connection.
func parseBwValue(s string) (v uint64, ok bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil || n == 0 || n > bwWireMax {
		return 0, false
	}
	return n, true
}

// hasBrutalBwCap reports whether a comma-separated X-HTTP-Tunnel-Caps value
// advertises the bandwidth exchange.
func hasBrutalBwCap(s string) bool {
	for _, cap := range strings.Split(s, ",") {
		if strings.TrimSpace(cap) == CapBrutalBw {
			return true
		}
	}
	return false
}

// brutalListener applies brutal to every connection it accepts, then hands the
// connection back unchanged. The apply hook is best-effort by contract: an
// accept must never fail because an optimisation could not be applied, so no
// error is ever returned from it.
//
// Wrapping the listener rather than using http.Server.ConnState is deliberate:
// in TLS mode ConnState hands back *tls.Conn, so reaching the raw TCP
// descriptor means an extra unwrap, and ConnState fires after the handshake has
// already started.
type brutalListener struct {
	ln    net.Listener
	apply func(net.Conn)
}

func newBrutalListener(ln net.Listener, apply func(net.Conn)) net.Listener {
	return &brutalListener{ln: ln, apply: apply}
}

func (l *brutalListener) Accept() (net.Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	if l.apply != nil {
		l.apply(c)
	}
	return c, nil
}

func (l *brutalListener) Close() error { return l.ln.Close() }
func (l *brutalListener) Addr() net.Addr {
	return l.ln.Addr()
}
