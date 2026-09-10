package tunnel

import (
	"sync"
)

// Event is the union of all typed tunnel events delivered through
// Client.SetEventHandler and ServerConfig.EventHandler. Events are advisory:
// delivery is best-effort (a slow or panicking handler never affects the
// tunnel itself), so handlers that must observe liveness should also select
// on the session's Done channel.
type Event interface {
	// Kind returns a stable machine-readable identifier for the event,
	// suitable for SIEM routing or switch dispatch.
	Kind() string
}

// TunnelEstablished fires once per tunnel session when the Split-HTTP
// handshake has completed and bytes can flow. Client-side it follows the
// first successful dial (stream or poll); server-side it follows session
// registration and bridge dispatch.
type TunnelEstablished struct {
	SessionID string
	Target    string // "host:port" the session is bridging to
	Network   string // "tcp" or "udp"
}

func (TunnelEstablished) Kind() string { return "tunnel.established" }

// TunnelDied fires when a tunnel session terminates for a reason other than a
// clean local Close. Reason values are stable strings:
//
//	"idle timeout"  — the local forwarder reaped a silent connection
//	"max retries"   — the pump gave up after repeated transport failures
//	"peer closed"   — the peer ended the session (close marker / FIN)
//	"error"         — anything else; Detail carries the underlying error text
type TunnelDied struct {
	SessionID string
	Target    string
	Network   string
	Reason    string
	Detail    string // unwrapped error text, empty when there is none
}

func (TunnelDied) Kind() string { return "tunnel.died" }

// Reconnecting fires each time the client pump starts a fresh transport
// round after the previous one broke. Nth is 1-based within one tunnel
// session's lifetime.
type Reconnecting struct {
	SessionID string
	Nth       int
	Reason    string // why the previous round ended
}

func (Reconnecting) Kind() string { return "tunnel.reconnecting" }

// TargetDenied fires when the server refuses a session because its target is
// not on the allowlist (ServerConfig.AllowedTargets).
type TargetDenied struct {
	SessionID string
	Target    string
	Network   string
	Remote    string // client address as seen by the server
}

func (TargetDenied) Kind() string { return "target.denied" }

// AuthRejected fires when the server rejects a request's credentials. This is
// the security-relevant signal for SIEM ingestion: repeated rejections from
// one address indicate credential guessing.
type AuthRejected struct {
	Remote string // client address as seen by the server
	Path   string
}

func (AuthRejected) Kind() string { return "auth.rejected" }

// SessionLimitRejected fires when the server refuses a new session because
// ServerConfig.MaxSessions sessions are already open.
type SessionLimitRejected struct {
	SessionID string
	Remote    string
}

func (SessionLimitRejected) Kind() string { return "session.limit_rejected" }

// SessionEventHandler receives typed server-side session events.
type SessionEventHandler func(SessionEvent)

// SessionEvent is the union of server-side session events. Kind() returns a
// stable identifier for SIEM routing; handlers run off the HTTP path.
type SessionEvent interface {
	Kind() string
}

// SessionEstablished fires when a new tunnel session is registered and
// dispatched to the bridge (or custom Handler).
type SessionEstablished struct {
	SessionID string
	Target    string
	Network   string
	Remote    string
}

func (SessionEstablished) Kind() string { return "session.established" }

// SessionClosed fires when a session is removed from the registry — cleanly
// (client ended the tunnel) or forcibly (kick/reaper). Reason: "client",
// "kicked", "reaped".
type SessionClosed struct {
	SessionID string
	Reason    string
}

func (SessionClosed) Kind() string { return "session.closed" }

// ReplayDropped fires when a poll/stream frame arrives with a sequence the
// session has already consumed (a duplicate retransmission). Occasional
// duplicates are normal transport behaviour; a sustained high rate from one
// session can indicate a replay attempt and is worth watching.
type ReplayDropped struct {
	SessionID string
	Seq       uint64
}

func (ReplayDropped) Kind() string { return "replay.dropped" }

// eventHub serialises event delivery: the handler runs on a dedicated
// goroutine fed by a small buffer, never on the tunnel's data path. A
// panicking handler is contained by recover and does not kill the pump.
type eventHub struct {
	mu          sync.Mutex
	ch          chan Event
	closed      bool
	dispatching bool
	wg          sync.WaitGroup
}

func newEventHub(handler func(Event)) *eventHub {
	h := &eventHub{ch: make(chan Event, 64)}
	if handler == nil {
		return h // emits are no-ops until start is called with a handler
	}
	h.start(handler)
	return h
}

// start launches the dispatch goroutine for fn. It is a no-op if the hub
// already has a dispatcher.
func (h *eventHub) start(fn func(Event)) {
	if fn == nil {
		return
	}
	h.mu.Lock()
	already := h.dispatching
	h.dispatching = true
	h.mu.Unlock()
	if already {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for ev := range h.ch {
			func() {
				defer func() { _ = recover() }() // a bad handler must not kill the pump
				fn(ev)
			}()
		}
	}()
}

// emit queues ev for delivery. Never blocks: when the buffer is full the
// event is dropped (the tunnel's data path must not stall on a slow
// consumer). A nil hub (low-level DialXHTTP without a Client) is a no-op.
func (h *eventHub) emit(ev Event) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	select {
	case h.ch <- ev:
	default:
	}
}

// close stops delivery and drains in-flight events. Safe to call on a nil
// hub and repeatedly.
func (h *eventHub) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	close(h.ch)
}
