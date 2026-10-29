package tunnel

import (
	"crypto/rand"
	"fmt"
	"io"
)

// The long-poll transport has no frame of its own: a poll body is the run of
// session frames the ring produced, shipped verbatim behind Content-Length. So
// the pad that shapes a poll body goes in front of that run, and the reader has
// to be told where the run starts.
//
// It is told in X-Pad, and that used to be the whole of it: a plaintext byte
// count in a header. That is a length oracle for anyone reading the wire — it
// turns a padded body into an exact statement of the payload inside it — and it
// is a second channel beside the bytes it describes, with its own ways to go
// wrong. A hop that dropped the header handed the padding to the reassembly as
// payload, and one that rewrote it made the reader skip a different number of
// bytes than the writer prefixed. Both were silent: the sequence numbers still
// added up, because they counted bytes the ring never meant to see.
//
// The length now travels the way the counters do: masked with a per-request
// keystream, and bound into the signed message. An observer reads a value it
// cannot invert, and a hop cannot drop or alter it without the request being
// refused — a missing header decodes to zero, which is not what was signed, so
// the request is refused before a byte of it reaches the ring.
//
// It stays a header rather than moving into the body, because the body is not a
// place a reader can look before it knows what it is holding. A poll body is a
// slice of a byte stream, and a resumption can start in the middle of a frame,
// so its first bytes are arbitrary: there is no prefix, and no byte value a pad
// can open with, that a body is guaranteed not to open with. Self-delimiting
// padding has to guess from those bytes, and guessing badly feeds payload to
// the reassembly — which is a worse failure than the one it was meant to close.

// padPollBody returns payload with padding in front so the whole body lands in
// the rule's band, together with the length of the pad it prefixed. A payload
// the rule leaves alone comes back unchanged with a pad of zero, and that zero
// is what the caller signs and sends: the reader is told either way.
func padPollBody(payload []byte) ([]byte, int, error) {
	pad := padLenFor(len(payload))
	if pad == 0 {
		return payload, 0, nil
	}
	body := make([]byte, pad+len(payload))
	if _, err := rand.Read(body[:pad]); err != nil {
		return nil, 0, err
	}
	copy(body[pad:], payload)
	return body, pad, nil
}

// splitPollBody returns the frames a body carries, with the pad in front of
// them dropped. The length is one the caller already knows, because it is the
// one the signature vouched for: this never guesses from the bytes.
func splitPollBody(body []byte, padLen int) ([]byte, error) {
	if padLen < 0 || padLen > maxPaddingTotal {
		return nil, fmt.Errorf("tunnel: poll body declares a pad of %d, outside 0..%d", padLen, maxPaddingTotal)
	}
	if padLen > len(body) {
		return nil, fmt.Errorf("tunnel: poll body declares a pad of %d but carries %d bytes", padLen, len(body))
	}
	return body[padLen:], nil
}

// skipPollPad drops a body's leading padding, if it has any, and returns the
// reader its frames start at. The pad's length is a known one here, so this is
// a bounded copy and not a scan: the length came off the wire and the bound is
// what keeps a rewritten one from emptying the socket.
func skipPollPad(r io.Reader, padLen int) (io.Reader, error) {
	if padLen == 0 {
		return r, nil
	}
	if padLen < 0 || padLen > maxPaddingTotal {
		return nil, fmt.Errorf("tunnel: poll body declares a pad of %d, outside 0..%d", padLen, maxPaddingTotal)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return nil, fmt.Errorf("tunnel: poll body ended %d bytes into its pad: %w", padLen, err)
	}
	return r, nil
}
