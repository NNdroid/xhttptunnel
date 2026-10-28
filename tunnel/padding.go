package tunnel

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Padding shapes the frames this process puts on the wire.
//
// Each side pads only what it sends, and every frame header carries its own pad
// length, so the two ends never have to agree on a rule: a mismatch changes the
// traffic shape, never the bytes an application receives. Padding is therefore
// local egress policy — one setting per process, not per session.
//
// Coverage follows the frame, not the transport. A tunnelled TCP/UDP session,
// the streaming envelope and the close marker are all framed, and the
// long-poll transport carries those same frames as its bodies: the session
// conn frames every write before it reaches the ring, so a poll POST or a poll
// response is a run of padded frames rather than raw payload. Nothing bypasses
// the frame layer, so nothing bypasses this rule.
//
// It is installed either imperatively with SetPadding or declaratively through
// ClientConfig.Padding / ServerConfig.Padding. The two routes reach the same
// process-wide policy, and a config that declares a rule different from one
// another config already declared is rejected: honouring both is impossible,
// and silently picking the later one would reshape the earlier instance's
// traffic without a word.
//
// # Syntax
//
// Whitespace is ignored and keywords are case-insensitive.
//
//	off | none             emit no padding at all
//	auto | default | ""    the built-in policy (400-600)
//	MIN-MAX                payloads shorter than MIN are padded so that
//	                       payload+pad lands uniformly in [MIN,MAX]; longer
//	                       payloads go out as they are
//	BELOW:MIN-MAX          the same, with an explicit threshold
//	RULE,RULE,...          several bands; the first matching one wins
//
// So "400-600" reads: anything under 400 bytes is padded up into 400..600, and
// anything at or above 400 is sent unpadded. Because the unpadded range starts
// at the band's own lower bound, the two halves overlap exactly: a 20-byte
// keystroke and a 480-byte record both leave a 480-byte frame.
//
// A band may set its threshold below its own lower bound, which is how the
// control channel is kept inside the same size distribution instead of being
// the only frames on the wire shorter than the band:
//
//	1:120-200,400:400-600   empty (keepalive/ack-only) frames 120..200,
//	                        everything else under 400 padded to 400..600
//
// Bands must be listed in increasing threshold order. For a band to be
// satisfiable its lower bound must be at least BELOW-1, otherwise the largest
// payload it admits would already exceed the target and the pad would go
// negative.
const (
	// DefaultPaddingSpec is what an empty or "auto" setting resolves to.
	// 400 is deliberately above the small-packet sizes that classifiers key
	// on (SSH keystrokes, TLS handshake records, DNS) and 600 is still one
	// MSS of tunnel payload, so the band costs no extra round trip.
	DefaultPaddingSpec = "400-600"
	// maxPaddingTotal bounds a band's upper bound, and it is the width of the
	// pad field rather than a buffer size: the pad length travels in the frame
	// header's two-byte field (writeSingleFrame and streamFrameStorage both
	// narrow it to uint16). A larger band would be truncated on the wire, and
	// the reader would then strip the wrong number of bytes and hand the
	// application padding as if it were payload. framePaddingBudget (90000) is
	// the per-frame scratch headroom, which covers this limit plus the header.
	maxPaddingTotal = 65535
	// maxPaddingBands keeps a typo from turning the lookup into a search.
	maxPaddingBands = 8
)

// paddingBand pads payloads shorter than below so that payload+pad lands
// uniformly in [min,max].
type paddingBand struct {
	below    int
	min, max int
}

// paddingPolicy is a compiled rule: bands in increasing threshold order, or no
// bands at all for "off". Compiled once at startup so the hot path allocates
// nothing and parses nothing.
type paddingPolicy struct {
	spec  string
	bands []paddingBand
}

var activePadding atomic.Pointer[paddingPolicy]

func init() {
	p, err := parsePaddingSpec(DefaultPaddingSpec)
	if err != nil {
		// Not reachable: the default is compiled into the binary and the test
		// suite pins it. Failing here beats shipping a silent no-op.
		panic("tunnel: built-in padding spec is invalid: " + err.Error())
	}
	activePadding.Store(p)
}

// SetPadding installs a process-wide padding rule. An empty spec, "auto" or
// "default" selects the built-in policy; "off" disables padding entirely.
// Invalid specs are rejected with the syntax, so a bad config fails at startup
// rather than turning every frame into a malformed one.
func SetPadding(spec string) error {
	p, err := parsePaddingSpec(spec)
	if err != nil {
		return err
	}
	activePadding.Store(p)
	return nil
}

// PaddingSpec reports the rule in force, normalised: "off", or the band list.
func PaddingSpec() string {
	return activePadding.Load().spec
}

// ValidatePadding checks a spec without installing it.
func ValidatePadding(spec string) error {
	_, err := parsePaddingSpec(spec)
	return err
}

// declaredPadding is the rule a ClientConfig or ServerConfig asked for, in
// normalised form. Padding is a process-wide egress policy, so two instances in
// one process cannot each have their own: the second declaration is refused
// rather than allowed to reshape the first instance's traffic behind its back.
// An imperative SetPadding is not recorded here — it is an explicit override
// and always wins.
var (
	declaredPaddingMu sync.Mutex
	declaredPadding   string
)

// installDeclaredPadding installs a rule that came from a config struct. Empty
// means "no opinion" and leaves whatever is in force alone, so a process that
// sets the policy once (SetPadding) does not have to repeat it in every config.
func installDeclaredPadding(component, spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	p, err := parsePaddingSpec(spec)
	if err != nil {
		return fmt.Errorf("tunnel: %s Padding: %w", component, err)
	}
	declaredPaddingMu.Lock()
	defer declaredPaddingMu.Unlock()
	if declaredPadding != "" && declaredPadding != p.spec {
		return fmt.Errorf("tunnel: %s asks for padding %q but this process already applies %q; padding shapes every frame the process emits, so a single rule must cover all of its clients and servers", component, p.spec, declaredPadding)
	}
	declaredPadding = p.spec
	activePadding.Store(p)
	return nil
}

// padLenFor returns how many padding bytes to append after a chunk of the given
// size. Zero means send it bare.
func padLenFor(chunkSize int) int {
	return activePadding.Load().padLen(chunkSize)
}

func (p *paddingPolicy) padLen(n int) int {
	if p == nil || n < 0 {
		return 0
	}
	for _, b := range p.bands {
		if n >= b.below {
			continue
		}
		target := b.min + rand.Intn(b.max-b.min+1)
		if target <= n {
			// Unreachable for a validated band; keep a bad spec from emitting
			// a negative pad, which would slice a frame buffer backwards. The
			// upper side is guaranteed by the parser too: a band's max is
			// capped at maxPaddingTotal, the width of the header's pad field.
			return 0
		}
		return target - n
	}
	return 0
}

func parsePaddingSpec(spec string) (*paddingPolicy, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	switch s {
	case "", "auto", "default":
		s = DefaultPaddingSpec
	case "off", "none":
		return &paddingPolicy{spec: "off"}, nil
	}

	parts := strings.Split(s, ",")
	if len(parts) > maxPaddingBands {
		return nil, fmt.Errorf("padding rule has %d bands, at most %d are allowed", len(parts), maxPaddingBands)
	}
	bands := make([]paddingBand, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("padding rule %q has an empty band", spec)
		}

		threshold := -1
		rangePart := part
		if i := strings.Index(part, ":"); i >= 0 {
			n, err := parsePaddingSize(part[:i])
			if err != nil {
				return nil, fmt.Errorf("padding rule %q: band %q has an unreadable threshold: %w", spec, part, err)
			}
			threshold = n
			rangePart = part[i+1:]
		}

		lo, hi, ok := strings.Cut(rangePart, "-")
		if !ok {
			return nil, fmt.Errorf("padding rule %q: band %q is not MIN-MAX (for example 400-600)", spec, part)
		}
		minTotal, err := parsePaddingSize(lo)
		if err != nil {
			return nil, fmt.Errorf("padding rule %q: band %q has an unreadable lower bound: %w", spec, part, err)
		}
		maxTotal, err := parsePaddingSize(hi)
		if err != nil {
			return nil, fmt.Errorf("padding rule %q: band %q has an unreadable upper bound: %w", spec, part, err)
		}
		if minTotal < 1 {
			return nil, fmt.Errorf("padding rule %q: band %q lower bound must be at least 1", spec, part)
		}
		if minTotal > maxTotal {
			return nil, fmt.Errorf("padding rule %q: band %q has an inverted range", spec, part)
		}
		if maxTotal > maxPaddingTotal {
			return nil, fmt.Errorf("padding rule %q: band %q upper bound %d exceeds %d, the width of the header's pad field; a longer pad would be truncated and the reader would mistake padding for payload", spec, part, maxTotal, maxPaddingTotal)
		}
		if threshold < 0 {
			// MIN-MAX shorthand: pad everything shorter than the lower bound,
			// so the unpadded range starts exactly where the band does.
			threshold = minTotal
		}
		if threshold < 1 {
			return nil, fmt.Errorf("padding rule %q: band %q threshold must be at least 1 (0 would never match)", spec, part)
		}
		if minTotal < threshold-1 {
			return nil, fmt.Errorf("padding rule %q: band %q lower bound %d is below threshold %d minus one, so its longest payload would already exceed the target and the pad would go negative", spec, part, minTotal, threshold)
		}
		if n := len(bands); n > 0 && threshold <= bands[n-1].below {
			return nil, fmt.Errorf("padding rule %q: band %q threshold %d must be greater than the previous band's %d; bands are matched in order", spec, part, threshold, bands[n-1].below)
		}
		bands = append(bands, paddingBand{below: threshold, min: minTotal, max: maxTotal})
	}
	// Label the rule from the compiled bands, not from the text: the shorthand
	// "400-600" and the explicit "400:400-600" are the same policy, and a log
	// line should never leave the threshold implicit.
	labels := make([]string, 0, len(bands))
	for _, b := range bands {
		labels = append(labels, fmt.Sprintf("%d:%d-%d", b.below, b.min, b.max))
	}
	return &paddingPolicy{spec: strings.Join(labels, ","), bands: bands}, nil
}

// parsePaddingSize accepts a positive decimal byte count. strconv.Atoi alone
// would take "+400" and "-400" as numbers, so the digits are checked first.
func parsePaddingSize(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q is not a byte count", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}
