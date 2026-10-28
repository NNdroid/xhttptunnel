package tunnel

import (
	"strings"
	"testing"
)

// snapshotPadding restores every half of the padding state — the compiled
// policy, the declaration record and the override flag — so a test that
// installs a rule cannot leak into the next one.
func snapshotPadding(t *testing.T) {
	t.Helper()
	prevPolicy := activePadding.Load()
	declaredPaddingMu.Lock()
	prevDeclared := declaredPadding
	prevOverridden := paddingOverridden
	declaredPaddingMu.Unlock()
	t.Cleanup(func() {
		declaredPaddingMu.Lock()
		declaredPadding = prevDeclared
		paddingOverridden = prevOverridden
		declaredPaddingMu.Unlock()
		activePadding.Store(prevPolicy)
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

// TestPaddingOverrideBlocksDifferingDeclaration pins what "explicit override"
// means for the declarative route. SetPadding decides the rule for the process,
// so a config field asking for something else must fail rather than win
// silently — the alternative is a rule that depends on which of two unrelated
// lines of user code happened to run last.
func TestPaddingOverrideBlocksDifferingDeclaration(t *testing.T) {
	snapshotPadding(t)
	if err := SetPadding("off"); err != nil {
		t.Fatalf("SetPadding: %v", err)
	}

	_, err := NewClient(ClientConfig{ServerURL: "https://127.0.0.1:9/stream", Padding: "400-600"})
	if err == nil {
		t.Fatal("NewClient replaced a SetPadding override without saying so")
	}
	for _, want := range []string{"SetPadding", "\"400:400-600\"", "\"off\""} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err.Error(), want)
		}
	}
	if got := PaddingSpec(); got != "off" {
		t.Fatalf("the rejected declaration still changed the rule to %q", got)
	}

	// Restating the override is not a conflict: nothing changes.
	if _, err := NewClient(ClientConfig{ServerURL: "https://127.0.0.1:9/stream", Padding: "none"}); err != nil {
		t.Errorf("NewClient rejected a config that restates the override: %v", err)
	}
	if _, err := NewServer(ServerConfig{Padding: "off"}); err != nil {
		t.Errorf("NewServer rejected a config that restates the override: %v", err)
	}
}

// TestPaddingDeclarationMatchingTheRuleInForceIsAccepted is the other half of
// comparing against the rule in force rather than against a history of
// declarations: a client declared a rule, an explicit override then changed it,
// and a config that asks for the rule now in force is not a contradiction.
// Comparing with the declaration record alone reported a conflict about a rule
// the process had already stopped using.
func TestPaddingDeclarationMatchingTheRuleInForceIsAccepted(t *testing.T) {
	snapshotPadding(t)

	if _, err := NewClient(ClientConfig{ServerURL: "https://127.0.0.1:9/stream", Padding: "off"}); err != nil {
		t.Fatalf("first declaration: %v", err)
	}
	if err := SetPadding("400-600"); err != nil {
		t.Fatalf("override: %v", err)
	}
	if _, err := NewServer(ServerConfig{Padding: "400:400-600"}); err != nil {
		t.Fatalf("a config asking for the rule in force was rejected: %v", err)
	}
	// Asking for the retired rule now contradicts the override, and the error
	// must name the decision it contradicts.
	_, err := NewServer(ServerConfig{Padding: "off"})
	if err == nil {
		t.Fatal("a rule the override retired was accepted")
	}
	if !strings.Contains(err.Error(), "SetPadding") {
		t.Errorf("error %q blames the wrong decision", err.Error())
	}
}
