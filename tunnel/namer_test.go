package tunnel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDeriveHeaderNamerDeterministic pins that both ends derive the same names
// from the same PSK and session id — the property the whole feature rests on.
// A client and a server that agree on the secret must agree on every header
// name, or neither can read the other's request.
func TestDeriveHeaderNamerDeterministic(t *testing.T) {
	a := deriveHeaderNamer("shared-secret", "session-a")
	b := deriveHeaderNamer("shared-secret", "session-a")
	for i := 0; i < int(slotCount); i++ {
		if got, want := a.name(headerSlot(i)), b.name(headerSlot(i)); got != want {
			t.Fatalf("slot %d: %q vs %q", i, got, want)
		}
	}
}

// TestDeriveHeaderNamerModeGating pins the two modes: an empty PSK or an empty
// session id falls back to the constant names and the header-riding session id,
// while a full pair derives opaque names and moves the session id to the URL.
func TestDeriveHeaderNamerModeGating(t *testing.T) {
	def := deriveHeaderNamer("", "session-a")
	if def.sessionIDInURL {
		t.Fatal("an open tunnel must keep the session id in the X-Trace header")
	}
	if def.name(slotSessionID) != SessionIDHeader {
		t.Fatalf("default session-id name = %q, want %q", def.name(slotSessionID), SessionIDHeader)
	}
	if def.name(slotTarget) != TargetHeader {
		t.Fatalf("default target name = %q, want %q", def.name(slotTarget), TargetHeader)
	}

	noSID := deriveHeaderNamer("shared-secret", "")
	if noSID.sessionIDInURL {
		t.Fatal("an unknown session id cannot be salted, so names must stay constant")
	}

	der := deriveHeaderNamer("shared-secret", "session-a")
	if !der.sessionIDInURL {
		t.Fatal("a PSK session must move the session id to the URL")
	}
	if der.name(slotSessionID) == SessionIDHeader {
		t.Fatalf("derived session-id name equals the constant %q", SessionIDHeader)
	}
	if der.name(slotTarget) == TargetHeader {
		t.Fatalf("derived target name equals the constant %q", TargetHeader)
	}
}

// TestDeriveHeaderNamesAreDistinctAndValid pins that the 21 derived names are
// non-empty, mutually distinct, and well-formed header names.
func TestDeriveHeaderNamesAreDistinctAndValid(t *testing.T) {
	n := deriveHeaderNamer("shared-secret", "session-a")
	seen := map[string]bool{}
	for i := 0; i < int(slotCount); i++ {
		name := n.name(headerSlot(i))
		if name == "" {
			t.Fatalf("slot %d derived an empty name", i)
		}
		if !strings.HasPrefix(name, "X-") {
			t.Fatalf("slot %d derived %q, not an X- name", i, name)
		}
		// 8 bytes of HMAC, hex-encoded, plus the X- prefix.
		if len(name) != 2+derivedNameBytes*2 {
			t.Fatalf("slot %d derived %q of length %d, want %d", i, name, len(name), 2+derivedNameBytes*2)
		}
		if seen[name] {
			t.Fatalf("slot %d derived duplicate name %q", i, name)
		}
		seen[name] = true
	}
}

// TestDerivedNamesVaryPerSession pins the core property: an observer who learns
// one session's names learns nothing about the next session's, so a name-based
// detector cannot stay armed from one session to another.
func TestDerivedNamesVaryPerSession(t *testing.T) {
	first := deriveHeaderNamer("shared-secret", "session-a")
	second := deriveHeaderNamer("shared-secret", "session-b")
	for i := 0; i < int(slotCount); i++ {
		if first.name(headerSlot(i)) == second.name(headerSlot(i)) {
			t.Fatalf("slot %d did not change across sessions (%q)", i, first.name(headerSlot(i)))
		}
	}
}

// TestDerivedNamesRequireTheKey pins that a different PSK derives different
// names, so an observer guessing the key cannot produce the right names.
func TestDerivedNamesRequireTheKey(t *testing.T) {
	right := deriveHeaderNamer("real-secret", "session-a")
	wrong := deriveHeaderNamer("guess", "session-a")
	for i := 0; i < int(slotCount); i++ {
		if right.name(headerSlot(i)) == wrong.name(headerSlot(i)) {
			t.Fatalf("slot %d did not change with the key (%q)", i, right.name(headerSlot(i)))
		}
	}
}

// TestDerivedNamesAvoidConstantsAndStandardHeaders pins that a derived name
// never collides with a constant protocol name or a common web/header name, so
// an observer cannot map a derived name back to a protocol slot by looking for
// the X-Trace-shaped strings.
func TestDerivedNamesAvoidConstantsAndStandardHeaders(t *testing.T) {
	n := deriveHeaderNamer("shared-secret", "session-a")
	common := []string{
		"X-Trace", "X-Route", "X-Net", "X-Ver", "X-Pos", "X-Cursor",
		"X-Req-Id", "X-Req-Sig", "X-Body-Sig", "X-Resp-Sig", "X-Wait",
		"X-Features", "X-Offset", "X-Ingest", "X-Mode", "X-Mode-Accepted",
		"X-Resume", "X-Probe", "X-Sync", "X-Fresh", "X-Retries",
		"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "X-Request-Id",
		"X-Auth-Token", "Content-Type", "Cache-Control", "User-Agent",
	}
	for i := 0; i < int(slotCount); i++ {
		name := n.name(headerSlot(i))
		for _, c := range common {
			if name == c {
				t.Fatalf("slot %d derived %q, collides with %q", i, name, c)
			}
		}
	}
}

// TestHeaderNamerSessionIDFromRequest pins how each mode reads the session id
// back off a request: the URL salt in derived mode, the header in default mode.
func TestHeaderNamerSessionIDFromRequest(t *testing.T) {
	const sid = "session-1234"
	der := deriveHeaderNamer("psk", sid)
	req := httptest.NewRequest(http.MethodGet, "/stream?s="+sid, nil)
	if got := der.sessionIDFromRequest(req); got != sid {
		t.Fatalf("derived sessionIDFromRequest = %q, want %q", got, sid)
	}

	def := deriveHeaderNamer("", sid)
	req2 := httptest.NewRequest(http.MethodGet, "/stream", nil)
	req2.Header.Set(SessionIDHeader, sid)
	if got := def.sessionIDFromRequest(req2); got != sid {
		t.Fatalf("default sessionIDFromRequest = %q, want %q", got, sid)
	}
}

// TestRequestScrubNamesMatchesRegistry pins that the derived scrub list covers
// the same set as the constant registry minus the response-only headers (plus
// X-Auth-Token), and that in derived mode the session id contributes no name.
func TestRequestScrubNamesMatchesRegistry(t *testing.T) {
	def := deriveHeaderNamer("", "sid")
	gotDef := map[string]bool{}
	for _, h := range def.requestScrubNames() {
		gotDef[h] = true
	}
	scrub := map[string]bool{}
	for _, h := range tunnelRequestHeaders {
		scrub[h] = true
	}
	for h := range scrub {
		if !gotDef[h] {
			t.Fatalf("default scrub list missing %q", h)
		}
	}
	for h := range gotDef {
		if !scrub[h] {
			t.Fatalf("default scrub list has extra %q", h)
		}
	}

	der := deriveHeaderNamer("psk", "sid")
	for _, h := range der.requestScrubNames() {
		if h == SessionIDHeader {
			t.Fatalf("derived scrub list carries the constant session-id header %q", h)
		}
	}
	// The derived scrub list must include the derived session-id slot name? No:
	// in derived mode the session id is not a header, so no name for it. It
	// must include the other request-carrying derived names though.
	if len(der.requestScrubNames()) != len(def.requestScrubNames())-1 {
		t.Fatalf("derived scrub list has %d names, want %d (one fewer: session id is not a header)",
			len(der.requestScrubNames()), len(def.requestScrubNames())-1)
	}
}

// TestResponseOnlySlotsInStepWithRegistry pins responseOnlySlot against the
// responseOnlyHeaders registry, so the two lists cannot drift.
func TestResponseOnlySlotsInStepWithRegistry(t *testing.T) {
	def := deriveHeaderNamer("", "sid")
	registry := map[string]bool{}
	for _, h := range responseOnlyHeaders {
		registry[h] = true
	}
	for i := 0; i < int(slotCount); i++ {
		slot := headerSlot(i)
		name := def.name(slot)
		if responseOnlySlot(slot) != registry[name] {
			t.Fatalf("slot %d (%q): responseOnlySlot=%t but registry=%t", i, name, responseOnlySlot(slot), registry[name])
		}
	}
}

// TestDefaultNamerMatchesConstants pins that the shared default namer resolves
// every slot to its constant — the guarantee that keeps an open tunnel and a
// scrub of a constant request byte-identical to the pre-feature behaviour.
func TestDefaultNamerMatchesConstants(t *testing.T) {
	constants := []string{
		AuthNonceHeader, AuthMACHeader, AuthBodyMACHeader, AuthRespMACHeader,
		BwHeader, CapsHeader, PadHeader, PollTimeoutHeader, ProtoHeader,
		TargetHeader, NetworkHeader, SessionIDHeader, SeqHeader, AckHeader,
		RetryHeader, DownstreamHeader, StreamResumeHeader, StreamProbeWindowHeader,
		DownstreamAcceptedHeader, StreamUplinkSyncHeader, SessionCreatedHeader,
	}
	n := deriveHeaderNamer("", "sid")
	for i, want := range constants {
		if got := n.name(headerSlot(i)); got != want {
			t.Fatalf("slot %d = %q, want %q", i, got, want)
		}
	}
}

// TestScrubDerivedRequestRemovesDerivedNames drives a PSK-mode request through
// the disguise-site scrubber and asserts every derived protocol header is gone
// — the fallback-camouflage safety the derived mode depends on. A derived
// request that misses the tunnel path must not leak its per-session headers to
// the external site.
func TestScrubDerivedRequestRemovesDerivedNames(t *testing.T) {
	const psk = "scrub-derived-psk"
	const sid = "scrub-derived-session"
	namer := deriveHeaderNamer(psk, sid)

	req := httptest.NewRequest(http.MethodPost, "http://example.invalid/?s="+sid, strings.NewReader("frame bytes"))
	// Write a derived request-carrying header under every non-response-only,
	// non-session-id slot: in derived mode the session id rides the URL, so the
	// client never writes it as a header (and the scrubber correctly does not
	// delete a name that should not be there).
	for i := 0; i < int(slotCount); i++ {
		slot := headerSlot(i)
		if responseOnlySlot(slot) {
			continue
		}
		if slot == slotSessionID {
			continue
		}
		req.Header.Set(namer.name(slot), "probe")
	}
	req.Header.Set("X-Auth-Token", psk)
	req.Header.Set("User-Agent", "curl/8.0.0")

	scrubTunnelRequest(req, psk)

	// No request-carrying derived name survives.
	for i := 0; i < int(slotCount); i++ {
		slot := headerSlot(i)
		if responseOnlySlot(slot) {
			continue
		}
		if slot == slotSessionID {
			continue
		}
		if v := req.Header.Get(namer.name(slot)); v != "" {
			t.Fatalf("derived slot %d (%q) survived the scrub: %q", i, namer.name(slot), v)
		}
	}
	if req.Header.Get("X-Auth-Token") != "" {
		t.Fatal("X-Auth-Token survived the derived scrub")
	}
	// The ordinary web headers must survive, and the body must be emptied.
	if req.Header.Get("User-Agent") == "" {
		t.Fatal("ordinary headers must survive the scrub")
	}
	if req.ContentLength != 0 || req.Body == nil {
		t.Fatalf("scrubbed body not emptied: cl=%d", req.ContentLength)
	}
}
