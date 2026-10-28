package tunnel

import (
	"strings"
	"testing"
)

// snapshotPadding restores both halves of the padding state — the compiled
// policy and the declaration record — so a test that installs a rule through a
// config struct cannot leak into the next one.
func snapshotPadding(t *testing.T) {
	t.Helper()
	prevPolicy := activePadding.Load()
	declaredPaddingMu.Lock()
	prevDeclared := declaredPadding
	declaredPaddingMu.Unlock()
	t.Cleanup(func() {
		activePadding.Store(prevPolicy)
		declaredPaddingMu.Lock()
		declaredPadding = prevDeclared
		declaredPaddingMu.Unlock()
	})
}

// TestPaddingFromConfigApplies covers the declarative path: an embedder that
// builds a ClientConfig or ServerConfig struct should not have to remember a
// separate package-level call for one of its fields.
func TestPaddingFromConfigApplies(t *testing.T) {
	snapshotPadding(t)

	if _, err := NewClient(ClientConfig{ServerURL: "https://127.0.0.1:9/stream", Padding: "1:120-200,400:400-600"}); err != nil {
		t.Fatalf("NewClient with a padding rule: %v", err)
	}
	if got := PaddingSpec(); got != "1:120-200,400:400-600" {
		t.Fatalf("after NewClient the rule is %q, want the configured 1:120-200,400:400-600", got)
	}

	// A server declaring the same rule under another spelling is not a
	// conflict — the normalised band list is what counts.
	if _, err := NewServer(ServerConfig{Padding: "1:120-200 , 400:400-600"}); err != nil {
		t.Fatalf("NewServer restating the same rule: %v", err)
	}
	if got := PaddingSpec(); got != "1:120-200,400:400-600" {
		t.Fatalf("a restatement changed the rule to %q", got)
	}
}

// TestPaddingDeclarationConflictRejected is the reason the field is not simply
// a per-instance setting: padding is process-wide, so honouring two different
// rules is impossible. Saying so at construction beats letting the second
// instance silently reshape the first one's traffic.
func TestPaddingDeclarationConflictRejected(t *testing.T) {
	snapshotPadding(t)

	c := ClientConfig{ServerURL: "https://127.0.0.1:9/stream", Padding: "off"}
	if _, err := NewClient(c); err != nil {
		t.Fatalf("first declaration: %v", err)
	}

	c2 := c
	c2.Padding = "400-600"
	_, err := NewClient(c2)
	if err == nil {
		t.Fatal("NewClient accepted a padding rule that conflicts with the one in force")
	}
	for _, want := range []string{"\"400:400-600\"", "\"off\""} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("conflict error %q does not name %s", err.Error(), want)
		}
	}
	// The server constructor must refuse it too: the policy is shared.
	if _, err := NewServer(ServerConfig{Padding: "400-600"}); err == nil {
		t.Error("NewServer accepted a conflicting padding rule")
	}

	// The same rule expressed differently is the same policy, not a conflict.
	c3 := c
	c3.Padding = "none"
	if _, err := NewClient(c3); err != nil {
		t.Errorf("NewClient rejected an equivalent rule (none == off): %v", err)
	}
	if got := PaddingSpec(); got != "off" {
		t.Errorf("an equivalent restatement changed the rule to %q", got)
	}
}

// TestPaddingConfigEmptyKeepsPolicy leaves the imperative path intact: a
// process that calls SetPadding once and then builds instances without a rule
// keeps that rule instead of reverting to the built-in default.
func TestPaddingConfigEmptyKeepsPolicy(t *testing.T) {
	snapshotPadding(t)
	withPadding(t, "512:600-1199")

	if _, err := NewClient(ClientConfig{ServerURL: "https://127.0.0.1:9/stream"}); err != nil {
		t.Fatalf("NewClient without a padding rule: %v", err)
	}
	if got := PaddingSpec(); got != "512:600-1199" {
		t.Fatalf("an empty Padding field changed the rule to %q, want it left alone", got)
	}
}

// TestPaddingConfigRejectsInvalid keeps a typo from being discovered on the
// wire: both constructors must reject it naming the field they were given.
func TestPaddingConfigRejectsInvalid(t *testing.T) {
	snapshotPadding(t)

	_, err := NewClient(ClientConfig{ServerURL: "https://127.0.0.1:9/stream", Padding: "400:200-600"})
	if err == nil || !strings.Contains(err.Error(), "client Padding") {
		t.Errorf("NewClient accepted an unsatisfiable rule (err = %v)", err)
	}
	_, err = NewServer(ServerConfig{Padding: "padding"})
	if err == nil || !strings.Contains(err.Error(), "server Padding") {
		t.Errorf("NewServer accepted a malformed rule (err = %v)", err)
	}
	if got := PaddingSpec(); got != "400:400-600" {
		t.Errorf("a rejected rule was installed anyway: %q", got)
	}
}
