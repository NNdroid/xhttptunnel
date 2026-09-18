// auth.go implements the protocol's v2 credential exchange: the pre-shared key
// is never sent. Each request carries a fresh nonce plus its HMAC over the
// nonce, the session id and the target, so one signature cannot be replayed or
// lifted onto another session or target.

package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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
}

func newNonceWindow() *nonceWindow {
	return &nonceWindow{
		ttl:    authNonceTTL,
		seen:   make(map[string]time.Time),
		maxLen: authNonceMaxEntries,
	}
}

// mark records nonce and reports whether it was new (true) or a replay inside
// the window (false). Expired entries are overwritten as fresh, which is
// correct: outside the window a nonce has no replay meaning left.
func (w *nonceWindow) mark(nonce string) bool {
	now := time.Now()
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
// control characters in header values, so the three fields can never bleed
// into one another and nonce "abc" plus session "def" cannot read as "abcdef".
func authMessage(nonce, sessionID, target string) []byte {
	msg := make([]byte, 0, len(authDomain)+len(nonce)+len(sessionID)+len(target)+2)
	msg = append(msg, authDomain...)
	msg = append(msg, nonce...)
	msg = append(msg, 0)
	msg = append(msg, sessionID...)
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

// setAuthHeaders authenticates one request with a fresh nonce. Only the HMAC
// crosses the wire — the PSK stays client-side. The session id and target are
// bound into the signed message as well, so a captured request cannot be
// replayed after a reconnect with a new session, nor retargeted at another
// address the same client is allowed to reach.
//
// An empty password leaves the request unauthenticated: an open tunnel has no
// credential scheme to sign, and the server must be refusing auth too.
func setAuthHeaders(req *http.Request, password, sessionID, targetAddr string) error {
	if password == "" {
		return nil
	}
	nonce, err := newAuthNonce()
	if err != nil {
		return err
	}
	req.Header.Set(AuthNonceHeader, nonce)
	req.Header.Set(AuthMACHeader, authMAC(password, authMessage(nonce, sessionID, targetAddr)))
	return nil
}
