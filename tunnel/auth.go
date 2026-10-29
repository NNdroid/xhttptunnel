// auth.go implements the protocol's v2 credential exchange: the pre-shared key
// is never sent. Each request carries a fresh nonce plus its HMAC over the
// nonce, the session id and the target, so one signature cannot be replayed or
// lifted onto another session or target.

package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// AuthNonceHeader carries a 32-hex-char nonce, fresh for every request.
const AuthNonceHeader = "X-HTTP-Tunnel-Nonce"

// AuthMACHeader carries the hex HMAC-SHA256 of authMessage under the PSK.
const AuthMACHeader = "X-HTTP-Tunnel-MAC"

const (
	// authNonceBytes is the entropy per request. It only needs to resist
	// guessing within the replay window, not to be a general secret.
	authNonceBytes = 16
	// authDomain separates this MAC from any other application HMAC that
	// happens to reuse the same key.
	authDomain = "xhttptunnel/auth/v2"
	// authNonceTTL matches sessionIdleTimeout: a request older than the idle
	// reaper's horizon can no longer be tied to a live session, so replaying it
	// would be meaningless even if it still signed correctly.
	authNonceTTL = 120 * time.Second
	// authNonceMaxEntries is the size at which an insert triggers a sweep of
	// expired entries. It is a growth guard, not a capacity limit — see the
	// nonceWindow comment for why the map cannot be hard-capped.
	authNonceMaxEntries = 20000
)

// nonceWindow rejects nonces already seen within authNonceTTL. The check and
// the record happen under one lock, so two concurrent requests sharing a nonce
// cannot both pass: whichever grabs the lock first wins, the other sees the
// entry and is refused.
//
// Size is bounded by authenticated request rate times the TTL, not by maxLen:
// entries are only evictable once they expire, so a flood of unique nonces
// with nothing expired yet cannot be shrunk. That is acceptable because a
// nonce only enters the map after a valid signature, so growing it costs the
// attacker a working PSK — which already means full access — and the operator
// already caps authenticated concurrency with max_conns.
type nonceWindow struct {
	mu     sync.Mutex
	ttl    time.Duration
	seen   map[string]time.Time
	maxLen int
	// now is the clock mark reads. Injectable so a test can step past the TTL
	// without sleeping, and without relying on two calls being spaced by more
	// than a nanosecond.
	now func() time.Time
}

func newNonceWindow() *nonceWindow {
	return &nonceWindow{
		ttl:    authNonceTTL,
		seen:   make(map[string]time.Time),
		maxLen: authNonceMaxEntries,
		now:    time.Now,
	}
}

// mark records nonce and reports whether it was new (true) or a replay inside
// the window (false). Expired entries are overwritten as fresh, which is
// correct: outside the window a nonce has no replay meaning left.
func (w *nonceWindow) mark(nonce string) bool {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if exp, ok := w.seen[nonce]; ok && now.Before(exp) {
		return false
	}
	w.seen[nonce] = now.Add(w.ttl)
	if len(w.seen) > w.maxLen {
		w.sweepLocked(now)
	}
	return true
}

func (w *nonceWindow) sweepLocked(now time.Time) {
	for n, exp := range w.seen {
		if !now.Before(exp) {
			delete(w.seen, n)
		}
	}
}

// authMessage renders the signed payload. Fields are NUL-delimited rather than
// whitespace-delimited because a space is legal inside a session id and a
// target, so whitespace cannot be a separator. NUL is not: HTTP/1.1 forbids
// control characters in header values, so the four fields can never bleed
// into one another and nonce "abc" plus session "def" cannot read as "abcdef".
func authMessage(nonce, sessionID, network, target string) []byte {
	msg := make([]byte, 0, len(authDomain)+len(nonce)+len(sessionID)+len(network)+len(target)+3)
	msg = append(msg, authDomain...)
	msg = append(msg, nonce...)
	msg = append(msg, 0)
	msg = append(msg, sessionID...)
	msg = append(msg, 0)
	msg = append(msg, network...)
	msg = append(msg, 0)
	msg = append(msg, target...)
	return msg
}

func authMAC(key string, msg []byte) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(msg)
	return hex.EncodeToString(h.Sum(nil))
}

// authMACMatches verifies a hex MAC without falling into a timing oracle: the
// MAC itself is compared with hmac.Equal, and a malformed value fails closed
// on the length check before any comparison happens.
func authMACMatches(key string, msg []byte, want string) bool {
	if !validHex(want, sha256.Size) {
		return false
	}
	wantBytes, _ := hex.DecodeString(want)
	h := hmac.New(sha256.New, []byte(key))
	h.Write(msg)
	return hmac.Equal(h.Sum(nil), wantBytes)
}

// validHex reports whether s is lowercase-or-uppercase hex for exactly n bytes.
func validHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n
}

// validAuthNonce enforces the exact nonce shape before it is used as a map key.
// Without this an unauthenticated caller could plant arbitrarily long or
// expensive keys in the window.
func validAuthNonce(s string) bool {
	return validHex(s, authNonceBytes)
}

// newAuthNonce draws the nonce from crypto/rand. Failing loudly on a bad
// entropy source is deliberate: a deterministic fallback would make every
// request's nonce predictable and turn the replay protection into a no-op.
func newAuthNonce() (string, error) {
	buf := make([]byte, authNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// signRequest authenticates one request with a fresh nonce and returns that
// nonce, which the response signature is keyed to. Only the HMACs cross the
// wire — the PSK stays client-side. The session id, network, target, method,
// generation, capabilities, counters and a digest of the body are all bound
// into the signed message, so a captured request cannot be replayed after a
// reconnect with a new session, retargeted at another address, switched to a
// different transport, or rewritten in flight without being refused.
//
// An empty password leaves the request unauthenticated: an open tunnel has no
// credential scheme to sign, and the server must be refusing auth too.
func signRequest(req *http.Request, password string, a requestAuth) (string, error) {
	if password == "" {
		return "", nil
	}
	nonce, err := newAuthNonce()
	if err != nil {
		return "", err
	}
	return nonce, setRequestAuth(req, password, nonce, a)
}

// responseMaskFor derives the mask a response's counters were masked with,
// from the nonce this side drew for the request that asked for it.
func responseMaskFor(password, nonce string) []byte {
	if password == "" || nonce == "" {
		return nil
	}
	return maskFor(respMaskDomain, password, nonce)
}

// Generation 3: the counters and the bytes themselves are inside the trust
// boundary, not just the credential.
//
// A v2 signature answers "who is this". It says nothing about what the request
// says, because the tunnel's own metadata — the sequence numbers that place a
// body in the stream — is not in the signed message, and the body is not in it
// either. This project is built to run behind a CDN, which is a hop that can
// rewrite both; a rewrite used to land in the receive ring and show up as a
// corrupt application stream, if it showed up at all.
//
// So v3 does two things: it binds the metadata and a digest of the body into
// the signature, turning a rewrite from silent corruption into a refusal, and
// it masks the counters, which takes away the edge's ability to read exact
// payload lengths off the headers even when it touches nothing.
//
// The pad is not among the bound metadata, and does not need to be. It says
// where it ends inside the signed bytes, so a hop that changes it has to change
// the bytes the digest covers — the pad is protected by being part of the
// object rather than by being a field beside it.

const (
	// AuthBodyMACHeader carries the hex HMAC-SHA256 of a request body. The
	// body is verified in the session handler rather than in the auth path,
	// because the credential has to be checked before a byte of it is read.
	AuthBodyMACHeader = "X-HTTP-Tunnel-Body-MAC"
	// AuthRespMACHeader carries the hex HMAC-SHA256 of a response: its
	// counters and a digest of its body, keyed to the nonce of the request
	// that asked for it. The downlink is the half a tunnelled application
	// receives, so it gets the same protection as the uplink.
	AuthRespMACHeader = "X-HTTP-Tunnel-Resp-MAC"
)

const (
	authDomainV3   = "xhttptunnel/auth/v3"
	bodyDomain     = "xhttptunnel/body/v3"
	respDomain     = "xhttptunnel/resp/v3"
	reqMaskDomain  = "xhttptunnel/req-mask/v3"
	respMaskDomain = "xhttptunnel/resp-mask/v3"
	// maskBytes carries two 8-byte counters and one 2-byte pad length, with
	// its own mask per direction so the two never share bytes.
	maskBytes = 18
)

// The kind of body a request carries, which is part of what its signature
// covers. A body has to be bounded to be digestible, and a continuous upload
// is not; the two are otherwise told apart by Content-Type, which is not
// signed, so a hop could label a bounded body a stream and have its bytes
// accepted unverified. Carrying the kind inside the signed message means the
// two ends have to agree about it, and a hop can move a request between the
// kinds only by breaking the signature.
const (
	// bodyKindPoll marks a request whose body is bounded and therefore
	// digestible. Polls and the streaming downlink request use it, which is
	// also what lets a streaming downlink request whose X-Downstream header
	// was stripped degrade into an ordinary idle poll.
	bodyKindPoll = "poll"
	// bodyKindStream marks the continuous upload, which has no end to digest
	// and so carries no body signature at all. It says so in as many words,
	// rather than by the absence of a header a hop can arrange.
	bodyKindStream = "stream"
)

// counters are the three sequence fields as they travel: masked for v3, plain
// for older generations. An empty member means the field is off the wire,
// which is what an old peer does when it has nothing to report — and for a
// signed request it is a refusal, because an absent field is not the one that
// was signed.
type counters struct {
	seq, ack, pad string
}

// requestAuth is everything a request states about itself that v3 binds into
// its signatures. The counters hold the plaintext the caller means; the wire
// form is derived inside, so a caller cannot sign one thing and send another.
type requestAuth struct {
	sessionID, network, target string
	method                     string
	proto                      int
	// caps is the capability announcement to write. It is deliberately not
	// signed: a middlebox that strips it costs only the traffic shape, and
	// binding it into the signature would turn that into an authentication
	// failure instead of a fallback.
	caps          string
	seq, ack, pad string
	// bodyKind says what kind of body follows, and it is signed.
	bodyKind string
	// body is the exact bytes the request will carry, so the signature can
	// cover them: a body a middlebox padded up to 400 bytes has to be as
	// detectable as one it cut short.
	body []byte
}

// errRequestBodyTampered reports a body whose bytes do not match the signature
// that arrived with them. It closes the session rather than acting as a
// retryable error: the stream it belongs to can no longer be trusted, and the
// two ends disagree about what was sent.
var errRequestBodyTampered = errors.New("tunnel: request body does not match its signature")

// errResponseBodyTampered is the same, for the half the client receives.
var errResponseBodyTampered = errors.New("tunnel: response body does not match its signature")

// setRequestAuth writes the nonce, the counters and the two signatures. It is
// the one place a request's secret material is produced, so the masked values
// on the wire and the plaintext they mask cannot drift apart.
func setRequestAuth(req *http.Request, password, nonce string, a requestAuth) error {
	if password == "" {
		return nil
	}
	// A signed request always states how much pad its body carries, including
	// when the answer is none. An absent header is not a pad of zero: it is a
	// header a hop removed, and only the signature can tell the two apart —
	// which is the whole reason the request is signed.
	if a.pad == "" {
		a.pad = "0"
	}
	req.Header.Set(AuthNonceHeader, nonce)
	wire := a.onTheWire(password, nonce)
	if wire.seq != "" {
		req.Header.Set("X-Seq", wire.seq)
	}
	if wire.ack != "" {
		req.Header.Set("X-Ack", wire.ack)
	}
	if wire.pad != "" {
		req.Header.Set(PadHeader, wire.pad)
	}
	// The capability is signed as it stands, not masked: it is a public
	// announcement, and the signature is what stops it being added or removed.
	if a.caps != "" {
		req.Header.Set(CapsHeader, a.caps)
	}
	req.Header.Set(AuthMACHeader, authMAC(password, v3Message(nonce, a, wire)))
	if a.bodyKind == bodyKindPoll {
		// An idle poll signs the digest of nothing, which is not the same as
		// signing nothing: a hop that gives it a body is then as detectable
		// as one that empties a busy one.
		digest := sha256.Sum256(a.body)
		req.Header.Set(AuthBodyMACHeader, bodyMAC(password, nonce, &digest))
	}
	return nil
}

// onTheWire masks the counters this request carries. Empty members stay empty:
// a request with no downlink cursor to report sends none rather than sending a
// masked zero, which would look like a real one.
func (a requestAuth) onTheWire(password, nonce string) counters {
	if password == "" {
		return counters{seq: a.seq, ack: a.ack, pad: a.pad}
	}
	m := maskFor(reqMaskDomain, password, nonce)
	wire := counters{}
	if a.seq != "" {
		if v, err := strconv.ParseUint(a.seq, 10, 64); err == nil {
			wire.seq = strconv.FormatUint(maskU64(v, m, 0), 10)
		}
	}
	if a.ack != "" {
		if v, err := strconv.ParseUint(a.ack, 10, 64); err == nil {
			wire.ack = strconv.FormatUint(maskU64(v, m, 8), 10)
		}
	}
	if a.pad != "" {
		if v, err := strconv.Atoi(a.pad); err == nil {
			wire.pad = strconv.Itoa(int(maskU16(v, m, 16)))
		}
	}
	return wire
}

// v3Message renders the v3 signed payload. Every field is something the
// dispatcher acts on, and the counters are the strings that travel — not the
// numbers they conceal.
func v3Message(nonce string, a requestAuth, wire counters) []byte {
	msg := make([]byte, 0, len(authDomainV3)+len(nonce)+96)
	msg = append(msg, authDomainV3...)
	msg = append(msg, nonce...)
	for _, field := range []string{a.sessionID, a.network, a.target, a.method,
		strconv.Itoa(a.proto), a.bodyKind, wire.seq, wire.ack, wire.pad} {
		msg = append(msg, 0)
		msg = append(msg, field...)
	}
	return msg
}

// maskFor derives the counter mask for one direction. It is keyed to the
// nonce, which is public and unique per request, so both ends reach the same
// bytes while an observer holding the nonce and a year of traffic still has no
// counters to difference.
func maskFor(domain, key, nonce string) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(domain))
	h.Write([]byte(nonce))
	return h.Sum(nil)[:maskBytes]
}

// responseCounters renders a response's two sequence fields in the form they
// travel: masked under the response's key, or in the clear when the peer did
// not sign the request. The pad is not among them — it rides in the body.
func responseCounters(seq, ack uint64, pad int, m []byte) counters {
	if m == nil {
		return counters{seq: strconv.FormatUint(seq, 10), ack: strconv.FormatUint(ack, 10), pad: strconv.Itoa(pad)}
	}
	return counters{
		seq: strconv.FormatUint(maskU64(seq, m, 0), 10),
		ack: strconv.FormatUint(maskU64(ack, m, 8), 10),
		pad: strconv.Itoa(int(maskU16(pad, m, 16))),
	}
}

func maskU16(v int, m []byte, off int) uint16 {
	if off+2 > len(m) {
		return uint16(v)
	}
	return uint16(v) ^ binary.BigEndian.Uint16(m[off:])
}

func maskU64(v uint64, m []byte, off int) uint64 {
	if off+8 > len(m) {
		return v
	}
	return v ^ binary.BigEndian.Uint64(m[off:])
}

// decodeCounters reads the two fields back. Empty means zero, which is what
// an old peer sends by leaving the field out; anything else has to be a
// number, or the request is a forgery rather than a request.
//
// The mask is applied per field, not to the pair: a counter that is off the
// wire was never masked, so unmasking it would turn its absence into the mask
// bytes — an absent X-Ack would read as a huge sequence number instead of
// zero, and the sender's own key would be what decided what it said.
// decodeCounters reads the three fields back. Empty means zero, and the mask is
// applied last, in the form the field travelled. A signed request is held to all
// three: a field it left off the wire is not the one it signed, and an absent
// pad length would otherwise be read as "there is no pad", which is exactly the
// answer that hands the padding to the reassembly as payload.
func decodeCounters(m []byte, c counters) (seq, ack uint64, pad int, err error) {
	if c.seq != "" {
		if seq, err = strconv.ParseUint(c.seq, 10, 64); err != nil {
			return 0, 0, 0, fmt.Errorf("tunnel: unreadable X-Seq %q", c.seq)
		}
		if m != nil {
			seq = maskU64(seq, m, 0)
		}
	}
	if c.ack != "" {
		if ack, err = strconv.ParseUint(c.ack, 10, 64); err != nil {
			return 0, 0, 0, fmt.Errorf("tunnel: unreadable X-Ack %q", c.ack)
		}
		if m != nil {
			ack = maskU64(ack, m, 8)
		}
	}
	if c.pad != "" {
		var p uint64
		if p, err = strconv.ParseUint(c.pad, 10, 64); err != nil {
			return 0, 0, 0, fmt.Errorf("tunnel: unreadable %s %q", PadHeader, c.pad)
		}
		if p > maxPaddingTotal {
			return 0, 0, 0, fmt.Errorf("tunnel: %s %d exceeds %d", PadHeader, p, maxPaddingTotal)
		}
		if m != nil {
			p = uint64(maskU16(int(p), m, 16))
		}
		pad = int(p)
	}
	return seq, ack, pad, nil
}

func bodyMessage(nonce string, digest *[sha256.Size]byte) []byte {
	msg := make([]byte, 0, len(bodyDomain)+len(nonce)+1+sha256.Size)
	msg = append(msg, bodyDomain...)
	msg = append(msg, nonce...)
	msg = append(msg, 0)
	msg = append(msg, digest[:]...)
	return msg
}

func bodyMAC(key, nonce string, digest *[sha256.Size]byte) string {
	return authMAC(key, bodyMessage(nonce, digest))
}

func bodyMACMatches(key, nonce string, digest *[sha256.Size]byte, want string) bool {
	return authMACMatches(key, bodyMessage(nonce, digest), want)
}

// respMessage binds a response to the request that asked for it: the nonce
// makes it impossible to lift onto another request, the counters are what a
// middlebox would otherwise rewrite, and the digest covers the bytes it would
// otherwise change.
//
// The capability announcement is deliberately left out, the same way it is on
// requests: a middlebox that strips it costs only the traffic shape, and
// signing it would turn that into an authentication failure.
func respMessage(nonce string, c counters, digest *[sha256.Size]byte) []byte {
	msg := make([]byte, 0, len(respDomain)+len(nonce)+64+sha256.Size)
	msg = append(msg, respDomain...)
	msg = append(msg, nonce...)
	for _, field := range []string{c.seq, c.ack, c.pad} {
		msg = append(msg, 0)
		msg = append(msg, field...)
	}
	msg = append(msg, 0)
	msg = append(msg, digest[:]...)
	return msg
}

func respMAC(key, nonce string, c counters, digest *[sha256.Size]byte) string {
	return authMAC(key, respMessage(nonce, c, digest))
}

func respMACMatches(key, nonce string, c counters, want string, digest *[sha256.Size]byte) bool {
	return authMACMatches(key, respMessage(nonce, c, digest), want)
}
