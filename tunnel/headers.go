package tunnel

import (
	"net/http"
	"strconv"
	"strings"
)

// This file is the single source of truth for every header the tunnel protocol
// reads or writes. Each field is a named constant so a rename touches one
// place, and the protocolHeaders registry below is what the fallback scrubber
// and its completeness test both iterate — a header added to the protocol
// without being classified here is caught by the test instead of silently
// leaking to a disguise site.
//
// The names are deliberately neutral. Nothing under X-HTTP-Tunnel- is left:
// that prefix is what identifies a hop as this protocol, so every header was
// renamed away from it. The chosen names are also outside nginx's
// proxy_hide_header default list (Date, Server, X-Pad, X-Accel-*), so no
// reverse proxy strips them, and they avoid the headers a real CDN or proxy
// generates or rewrites (X-Forwarded-*, X-Request-Id, CF-*, X-Cache-*), so a
// middlebox does not collide with them. X-Offset is the exception that started
// the rename: it was already outside the namespace to dodge the nginx list.
//
// Renaming these is a wire-format change with no negotiation fallback: the
// version header itself (X-Ver, formerly X-XHTTP-Proto) is one of them, so an
// old client and a new server cannot even agree on what the other speaks. A
// mixed deployment fails closed (HTTP 407, no signature found) rather than
// corrupting — upgrade both ends together.

// AuthNonceHeader carries a 32-hex-char nonce, fresh for every request. It is
// the anti-replay credential: a captured request cannot be replayed because the
// nonce is single-use inside the replay window.
const AuthNonceHeader = "X-Req-Id"

// AuthMACHeader carries the hex HMAC-SHA256 of the signed auth message under
// the pre-shared key.
const AuthMACHeader = "X-Req-Sig"

// AuthBodyMACHeader carries the hex HMAC-SHA256 of a request body, binding the
// bytes into the signature so a hop that rewrites them is refused.
const AuthBodyMACHeader = "X-Body-Sig"

// AuthRespMACHeader carries the hex HMAC-SHA256 of a response: its masked
// counters and a digest of its body, keyed to the nonce of the request that
// asked for it. It is response-only and never rides a forwarded request.
const AuthRespMACHeader = "X-Resp-Sig"

// BwHeader carries the receiver-side ingest ceiling, in bytes/s, for the
// bandwidth exchange. The peer applies it as its own send rate.
const BwHeader = "X-Ingest"

// CapsHeader lists the extensions a server implements. The client reads it to
// tell a capability-supporting server from an older one.
const CapsHeader = "X-Features"

// PadHeader carries the byte count of a poll body's leading pad. It is sent on
// requests and responses alike, travels masked, and is bound into the
// signature. Deliberately outside the old X-HTTP-Tunnel- namespace: nginx
// hides the old X-Pad name by default, and this name carries no protocol hint.
const PadHeader = "X-Offset"

// PollTimeoutHeader tells the client how long this server parks an idle poll,
// in seconds. It is a hint, not a credential. Response-only.
const PollTimeoutHeader = "X-Wait"

// ProtoHeader advertises the wire-protocol generation a request speaks and is
// echoed by the server in every response. Renaming this alongside the other
// headers is what makes the camouflage a hard cutover: two builds cannot
// negotiate through a header neither one calls by the same name.
const ProtoHeader = "X-Ver"

// TargetHeader names the internal address a client is dialing through.
const TargetHeader = "X-Route"

// NetworkHeader names the network protocol for the dial (tcp/udp/tcp+udp).
const NetworkHeader = "X-Net"

// SessionIDHeader carries the session identifier binding a request to a
// virtual connection.
const SessionIDHeader = "X-Trace"

// SeqHeader carries the uplink (client-to-server) sequence number.
const SeqHeader = "X-Pos"

// AckHeader carries the downlink (server-to-client) acknowledgement sequence
// number.
const AckHeader = "X-Cursor"

// RetryHeader marks a re-sent poll on a recovered link ("1").
const RetryHeader = "X-Retries"

// DownstreamHeader marks the streaming downlink request ("1").
const DownstreamHeader = "X-Mode"

// StreamResumeHeader marks a resumed streaming uplink ("1").
const StreamResumeHeader = "X-Resume"

// StreamProbeWindowHeader carries the client's hello-frame wait window, in
// seconds (1-60).
const StreamProbeWindowHeader = "X-Probe"

// DownstreamAcceptedHeader confirms the server accepted a streaming downlink
// ("1"). Response-only.
const DownstreamAcceptedHeader = "X-Mode-Accepted"

// StreamUplinkSyncHeader confirms the server has the uplink stream in sync
// ("1"). Response-only.
const StreamUplinkSyncHeader = "X-Sync"

// SessionCreatedHeader confirms the server created a new session ("1").
// Response-only.
const SessionCreatedHeader = "X-Fresh"

// protocolHeaders is every header this protocol reads or writes. It is the
// registry the fallback scrubber and its completeness test iterate, so a
// header added here without being classified is caught rather than leaked.
var protocolHeaders = []string{
	AuthNonceHeader,
	AuthMACHeader,
	AuthBodyMACHeader,
	AuthRespMACHeader,
	BwHeader,
	CapsHeader,
	PadHeader,
	PollTimeoutHeader,
	ProtoHeader,
	TargetHeader,
	NetworkHeader,
	SessionIDHeader,
	SeqHeader,
	AckHeader,
	RetryHeader,
	DownstreamHeader,
	StreamResumeHeader,
	StreamProbeWindowHeader,
	DownstreamAcceptedHeader,
	StreamUplinkSyncHeader,
	SessionCreatedHeader,
}

// responseOnlyHeaders are the protocol headers the server sends and the client
// reads, which never ride a request the origin forwards to a disguise site.
// They are excluded from the scrub list; the completeness test accounts for
// them explicitly so a header is never silently unscoped.
var responseOnlyHeaders = []string{
	AuthRespMACHeader,
	PollTimeoutHeader,
	DownstreamAcceptedHeader,
	StreamUplinkSyncHeader,
	SessionCreatedHeader,
}

// headerSlot identifies one protocol header position. The slot number is the
// domain separator inside the derived-name HMAC, so it is part of what both
// ends agree on: renumbering or reordering it is a wire-format change with no
// negotiation fallback, exactly like renaming a constant above.
type headerSlot int

const (
	slotAuthNonce headerSlot = iota
	slotAuthMAC
	slotAuthBodyMAC
	slotAuthRespMAC
	slotBw
	slotCaps
	slotPad
	slotPollTimeout
	slotProto
	slotTarget
	slotNetwork
	slotSessionID
	slotSeq
	slotAck
	slotRetry
	slotDownstream
	slotStreamResume
	slotStreamProbeWindow
	slotDownstreamAccepted
	slotStreamUplinkSync
	slotSessionCreated
	slotCount
)

// nameDomain separates derived header names from every other HMAC in the
// protocol, so a derived name can never be confused with a signature, a mask
// or a body digest.
const nameDomain = "xhttptunnel/headername/v3"

// saltParam is the URL query parameter that carries the session id in derived
// mode. The session id is the salt: per-session, 128-bit random, already bound
// into the signed message, and the one value both ends know before they need to
// agree on names. It rides the URL rather than a header because the server
// cannot read a header whose name it has not derived yet (the chicken-and-egg
// that would otherwise make the feature impossible).
const saltParam = "s"

// derivedNameBytes is how many bytes of HMAC go into a derived header name,
// hex-encoded into 16 characters. Eight bytes makes collisions between the 21
// slots negligible while keeping the names short enough to read as ordinary
// headers.
const derivedNameBytes = 8

// headerNamer resolves each protocol slot to the header name a request or
// response must use. It has two modes:
//
//   - default: the constant names from the top of this file. Used when there is
//     no PSK (an open tunnel has no shared secret to derive from, so the names
//     would leak everything anyway) or when the session id is unknown (an error
//     response before the salt has been read). This mode is byte-for-byte the
//     current wire format.
//
//   - derived: names are HMAC-SHA256(PSK, nameDomain || NUL || sessionID || NUL
//     || slot), truncated, and the session id moves to the URL query parameter
//     (saltParam) instead of SessionIDHeader. An observer without the PSK sees
//     opaque names that change every session and cannot be mapped to the
//     protocol; a hop that learns one session's names learns nothing reusable.
type headerNamer struct {
	names          [slotCount]string
	sessionIDInURL bool
}

// defaultHeaderNamer returns the constant names. A zero-value headerNamer is
// not valid; always build one through deriveHeaderNamer or defaultHeaderNamer.
func defaultHeaderNamer() headerNamer {
	return headerNamer{
		names: [slotCount]string{
			AuthNonceHeader,
			AuthMACHeader,
			AuthBodyMACHeader,
			AuthRespMACHeader,
			BwHeader,
			CapsHeader,
			PadHeader,
			PollTimeoutHeader,
			ProtoHeader,
			TargetHeader,
			NetworkHeader,
			SessionIDHeader,
			SeqHeader,
			AckHeader,
			RetryHeader,
			DownstreamHeader,
			StreamResumeHeader,
			StreamProbeWindowHeader,
			DownstreamAcceptedHeader,
			StreamUplinkSyncHeader,
			SessionCreatedHeader,
		},
	}
}

// deriveHeaderNamer builds the namer for a session. An empty PSK or an empty
// session id yields the default (constant) names: an open tunnel has no shared
// secret to derive from, and an unknown session id cannot be salted. Both ends
// must call this with the same PSK and session id to agree on names.
func deriveHeaderNamer(psk, sessionID string) headerNamer {
	if psk == "" || sessionID == "" {
		return defaultHeaderNamer()
	}
	n := headerNamer{sessionIDInURL: true}
	slotBuf := make([]byte, 0, 4)
	for i := 0; i < int(slotCount); i++ {
		slotBuf = strconv.AppendInt(slotBuf[:0], int64(i), 10)
		msg := make([]byte, 0, len(nameDomain)+len(sessionID)+len(slotBuf)+2)
		msg = append(msg, nameDomain...)
		msg = append(msg, 0)
		msg = append(msg, sessionID...)
		msg = append(msg, 0)
		msg = append(msg, slotBuf...)
		mac := authMAC(psk, msg)
		n.names[i] = "X-" + mac[:derivedNameBytes*2]
	}
	return n
}

// defaultNames is a zero-value headerNamer's fallback: a namer built without
// deriveHeaderNamer (a literal, or a conn that predates its namer being set)
// resolves to the constant names rather than to empty header names, which
// would silently read and write nothing.
var defaultNames = func() [slotCount]string { return defaultHeaderNamer().names }()

// defaultNamer is the shared constant-name namer. It is what an open tunnel
// uses, and what error responses are answered under before a request
// authenticates and its own namer is known.
var defaultNamer = defaultHeaderNamer()

// name returns the header name for a slot. A zero-value namer (names all
// empty) resolves to the default constant name, so a header read or write
// through an unset namer still lands on the current wire format.
func (n headerNamer) name(slot headerSlot) string {
	if name := n.names[slot]; name != "" {
		return name
	}
	return defaultNames[slot]
}

// sessionIDFromRequest reads the session id the way this namer carries it: the
// URL salt in derived mode, the session-id header in default mode. Both ends
// agree on which, because both derived the same namer from the same PSK.
func (n headerNamer) sessionIDFromRequest(r *http.Request) string {
	if n.sessionIDInURL {
		return r.URL.Query().Get(saltParam)
	}
	return r.Header.Get(n.name(slotSessionID))
}

// exposeList renders an Access-Control-Expose-Headers value for the given
// slots under this namer's names, followed by any literal names a response
// also exposes (Content-Length, which is never derived). In default mode this
// reproduces the historical strings exactly; in derived mode it lists the
// derived names so a browser-side client can read the same headers. The only
// consumer of CORS headers is a browser, which a Go tunnel client is not, so
// this is cosmetic — but it must not advertise names that no longer exist.
func (n headerNamer) exposeList(slots []headerSlot, trailing ...string) string {
	names := make([]string, 0, len(slots)+len(trailing))
	for _, s := range slots {
		names = append(names, n.name(s))
	}
	return strings.Join(append(names, trailing...), ", ")
}

// sessionIDName returns the header name to read the session id from, or "" if
// the session id travels in the URL query instead. Callers must read the URL
// salt (saltParam) when this is empty.
func (n headerNamer) sessionIDName() string {
	if n.sessionIDInURL {
		return ""
	}
	return n.names[slotSessionID]
}

// responseOnlySlot reports whether a slot's header is response-only and so
// never rides a request the server forwards to a disguise site. Kept in step
// with responseOnlyHeaders above; the completeness test and a namer test
// pin the two together.
func responseOnlySlot(slot headerSlot) bool {
	switch slot {
	case slotAuthRespMAC, slotPollTimeout, slotDownstreamAccepted,
		slotStreamUplinkSync, slotSessionCreated:
		return true
	}
	return false
}

// requestScrubNames returns the names a disguise-site scrubber must delete from
// a request it is about to forward: every request-carrying protocol header (the
// registry minus the response-only ones) plus the operator-configurable
// X-Auth-Token. In derived mode the session id is not a header at all, so it
// contributes no name.
func (n headerNamer) requestScrubNames() []string {
	names := make([]string, 0, len(tunnelRequestHeaders))
	for i := 0; i < int(slotCount); i++ {
		slot := headerSlot(i)
		if responseOnlySlot(slot) {
			continue
		}
		if slot == slotSessionID && n.sessionIDInURL {
			continue
		}
		names = append(names, n.name(slot))
	}
	return append(names, "X-Auth-Token")
}
