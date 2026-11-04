package tunnel

import (
	"strings"
	"testing"
)

// TestEveryProtocolHeaderIsScrubbedOrResponseOnly is the completeness guard for
// the protocol header registry. Every header the protocol reads or writes must
// be accounted for: either it rides a request and is scrubbed before a request
// leaves the origin through the fallback proxy, or it is response-only and
// deliberately excluded. A header that is neither is a silent leak — it would
// reach the disguise site the fallback forwards to, carrying protocol state
// the camouflage depends on hiding.
//
// This test replaces the old x-http-tunnel- prefix catch-all: the header names
// are neutral on purpose now (see headers.go), so there is no namespace that
// can catch an unregistered header at runtime. The registry and this test are
// what close the class instead.
func TestEveryProtocolHeaderIsScrubbedOrResponseOnly(t *testing.T) {
	scrub := make(map[string]bool, len(tunnelRequestHeaders))
	for _, h := range tunnelRequestHeaders {
		scrub[h] = true
	}
	responseOnly := make(map[string]bool, len(responseOnlyHeaders))
	for _, h := range responseOnlyHeaders {
		responseOnly[h] = true
	}

	seen := make(map[string]bool, len(protocolHeaders))
	for _, h := range protocolHeaders {
		if h == "" {
			t.Error("protocolHeaders contains an empty header name")
			continue
		}
		if seen[h] {
			t.Errorf("protocolHeaders contains %q more than once", h)
		}
		seen[h] = true

		switch {
		case scrub[h]:
			// Request-borne and scrubbed. Good.
		case responseOnly[h]:
			// Response-only and deliberately excluded. Good.
		default:
			t.Errorf("protocol header %q is neither scrubbed nor declared response-only; "+
				"add it to tunnelRequestHeaders or responseOnlyHeaders", h)
		}
	}

	// Every scrub entry must come from the registry (plus the configurable
	// X-Auth-Token), so the registry is the single source of truth rather than
	// two lists that can drift.
	for _, h := range tunnelRequestHeaders {
		if h == "X-Auth-Token" {
			continue // operator-configurable, deliberately outside the registry
		}
		if !seen[h] {
			t.Errorf("tunnelRequestHeaders lists %q, which is not in protocolHeaders", h)
		}
	}
	for _, h := range responseOnlyHeaders {
		if !seen[h] {
			t.Errorf("responseOnlyHeaders lists %q, which is not in protocolHeaders", h)
		}
	}
}

// TestProtocolHeaderNamesAreNeutral pins the camouflage contract: no protocol
// header may carry a string that identifies it as this protocol. The old
// X-HTTP-Tunnel- prefix, X-XHTTP-Proto, and any mention of xhttp/tunnel/stream
// in a header name are what an observer would read to recognise the tunnel, so
// none may appear. The values of capabilities (CapPadBody, CapBrutalBw) are
// negotiated tokens and not header names, so they are out of scope here.
func TestProtocolHeaderNamesAreNeutral(t *testing.T) {
	// X-Auth-Token is operator-configurable (--token-header) and not part of
	// the registry, so the neutral-name contract is checked against the
	// registry only.
	for _, h := range protocolHeaders {
		lower := strings.ToLower(h)
		for _, marker := range []string{"tunnel", "xhttp", "http-tunnel", "stream", "x-xhttp"} {
			if strings.Contains(lower, marker) {
				t.Errorf("protocol header %q leaks a protocol marker %q", h, marker)
			}
		}
	}
}
