package tunnel

import (
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
)

// The long-poll transport has no frame of its own: a poll body is the run of
// session frames the ring produced, shipped verbatim behind Content-Length. So
// the pad that shapes a poll body goes in front of that run, and X-Pad tells
// the reader how many bytes of it to drop.
//
// Front, not back. A leading pad can be skipped with a bounded read and the
// rest streamed straight into the ring, so neither end has to buffer a body to
// find where the padding ends — and the frame boundaries stay untouched, which
// they would not if the pad trailed, because the run has no length prefix of
// its own to say where it stops.

// padPollBody returns payload with padding in front so the whole body lands in
// the rule's band, plus the pad length to announce in X-Pad. A payload the rule
// leaves alone comes back unchanged, so the bulk path copies nothing.
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

// parsePollPad reads an X-Pad value. Absent means zero. Anything else has to be
// well formed: a body whose declared pad cannot be read is a protocol
// violation, and treating it as zero would feed that padding into the ring as
// payload — silent corruption rather than a clean failure.
func parsePollPad(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("tunnel: invalid %s %q", PadHeader, s)
	}
	if n > maxPaddingTotal {
		return 0, fmt.Errorf("tunnel: %s %d exceeds %d", PadHeader, n, maxPaddingTotal)
	}
	return n, nil
}

// skipPollPad drops a body's leading padding before it is read as frames. The
// bound from parsePollPad is what keeps a forged header from making us discard
// an unbounded prefix of the body.
func skipPollPad(r io.Reader, pad int) error {
	if pad == 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(pad))
	return err
}
