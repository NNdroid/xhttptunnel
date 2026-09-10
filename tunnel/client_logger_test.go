package tunnel

import (
	"testing"

	"go.uber.org/zap"
)

// TestNewClientWiresConfigLogger guarantees ClientConfig.Logger takes
// effect: the field was once silently ignored by NewClient (c.log stayed
// nil and lg() fell back to the package logger), so embedder-injected
// loggers never received a single line.
func TestNewClientWiresConfigLogger(t *testing.T) {
	injected := zap.NewNop()
	c, err := NewClient(ClientConfig{
		ServerURL: "https://cdn.example.com:8443/stream",
		PSK:       "token",
		Logger:    injected,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.lg() != injected {
		t.Fatal("Client.lg() did not return the injected config logger")
	}
	if c.dialCfg.lg() != injected {
		t.Fatal("DialConfig.lg() did not return the injected config logger")
	}
}
