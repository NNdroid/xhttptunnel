package tunnel

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

// captureStdout runs fn and returns whatever it printed to stdout, along with
// fn's own return value. The reader must run in its own goroutine: the QR code
// is large enough to fill the pipe buffer and block fn().
func captureStdout(fn func() string) (string, string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", "", err
	}
	done := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(r)
		done <- out
	}()
	os.Stdout = w
	got := fn()
	_ = w.Close()
	os.Stdout = old
	out := <-done
	return string(out), got, nil
}

// TestShareURIProfileShape pins the fields the Stun importer consumes. A
// "tcp://" prefix in sshAddr produces a node that imports cleanly but never
// connects, so the QR looks correct while being unusable; a missing SNI breaks
// the client's TLS handshake to the origin right after the scan; and the
// certificate pin must reach the importer too, otherwise the node trusts
// whatever certificate it is offered.
func TestShareURIProfileShape(t *testing.T) {
	_, uri, err := captureStdout(func() string {
		return GenerateXHTTPTunnelURI("1.2.3.4", "9443", "/custom",
			"tcp://192.168.1.10:22", "top-secret", "www.sushiwei.com", "AA:BB:CC:DD", "Node", "123456", true)
	})
	if err != nil {
		t.Fatal(err)
	}

	plain, err := decryptStunURI(uri, "123456")
	if err != nil {
		t.Fatalf("decrypt share URI: %v", err)
	}
	var prof StunProfile
	if err := json.Unmarshal([]byte(plain), &prof); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if prof.SSHAddr != "192.168.1.10:22" {
		t.Errorf("sshAddr = %q, want the bare address %q", prof.SSHAddr, "192.168.1.10:22")
	}
	if prof.CustomHost != "www.sushiwei.com" || prof.ServerName != "www.sushiwei.com" {
		t.Errorf("SNI = customHost %q / serverName %q, want www.sushiwei.com", prof.CustomHost, prof.ServerName)
	}
	if prof.ProxyAddr != "1.2.3.4:9443" {
		t.Errorf("proxyAddr = %q, want 1.2.3.4:9443", prof.ProxyAddr)
	}
	if prof.Fingerprint != "AA:BB:CC:DD" {
		t.Errorf("fingerprint = %q, want the pin handed to the generator", prof.Fingerprint)
	}

	// The plaintext protocol URI printed alongside carries the same pin, so a
	// node imported from either form verifies the same certificate.
	out, _, _ := captureStdout(func() string {
		return GenerateXHTTPTunnelURI("1.2.3.4", "9443", "/custom",
			"tcp://192.168.1.10:22", "top-secret", "www.sushiwei.com", "AA:BB:CC:DD", "Node", "123456", true)
	})
	if !strings.Contains(out, "fp=AA%3ABB%3ACC%3ADD") {
		t.Error("the plaintext xhttp:// URI does not carry the fp pin")
	}
}

// TestShareURIWithoutPin checks the default path: with no pin there is no
// fingerprint field value and no fp parameter, so an importer sees an ordinary
// node rather than a pin it cannot satisfy.
func TestShareURIWithoutPin(t *testing.T) {
	out, uri, err := captureStdout(func() string {
		return GenerateXHTTPTunnelURI("1.2.3.4", "9443", "/custom",
			"192.168.1.10:22", "top-secret", "www.sushiwei.com", "", "Node", "123456", true)
	})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptStunURI(uri, "123456")
	if err != nil {
		t.Fatalf("decrypt share URI: %v", err)
	}
	var prof StunProfile
	if err := json.Unmarshal([]byte(plain), &prof); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if prof.Fingerprint != "" {
		t.Errorf("fingerprint = %q, want empty", prof.Fingerprint)
	}
	if strings.Contains(out, "fp=") {
		t.Error("an unpinned share URI must not advertise an fp parameter")
	}
	if !strings.Contains(out, "no certificate pin") {
		t.Error("an unpinned share URI should say so, so the operator is not misled")
	}
}

// TestStripTargetScheme checks the scheme removal itself, including the case
// where the prefix is uppercase or the string is not a scheme at all.
func TestStripTargetScheme(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"tcp://127.0.0.1:22", "127.0.0.1:22"},
		{"TCP://127.0.0.1:22", "127.0.0.1:22"},
		{"udp://[::1]:53", "[::1]:53"},
		{"udp://:53", ":53"},
		{"127.0.0.1:22", "127.0.0.1:22"},
		{"[::1]:22", "[::1]:22"},
		{"", ""},
		{"tcp://", "tcp://"}, // nothing after the prefix is not an address
		{"http://1.2.3.4:80", "http://1.2.3.4:80"},
	} {
		if got := stripTargetScheme(tc.in); got != tc.want {
			t.Errorf("stripTargetScheme(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// decodeTerminalQR reverses renderTerminalQR: it parses the ANSI escape codes
// around each '▀' glyph and rebuilds the module grid (true = dark module),
// returning the same shape as qrcode.Bitmap().
func decodeTerminalQR(rendered string) ([][]bool, error) {
	const (
		fgBlack = "\x1b[30m"
		fgWhite = "\x1b[97m"
		bgBlack = "\x1b[40m"
		bgWhite = "\x1b[47m"
	)
	lines := strings.Split(strings.TrimPrefix(rendered, "\n"), "\n")
	var grid [][]bool
	for _, line := range lines {
		line = strings.TrimPrefix(line, "  ")
		if line == "" {
			continue
		}
		var fgRow, bgRow []bool
		fgDark, bgDark := false, false // false = white (light module)
		for i := 0; i < len(line); {
			switch {
			case strings.HasPrefix(line[i:], fgBlack):
				fgDark = true
				i += len(fgBlack)
			case strings.HasPrefix(line[i:], fgWhite):
				fgDark = false
				i += len(fgWhite)
			case strings.HasPrefix(line[i:], bgBlack):
				bgDark = true
				i += len(bgBlack)
			case strings.HasPrefix(line[i:], bgWhite):
				bgDark = false
				i += len(bgWhite)
			case strings.HasPrefix(line[i:], "\x1b[0m"):
				i += len("\x1b[0m")
			case strings.HasPrefix(line[i:], "▀"):
				fgRow = append(fgRow, fgDark) // upper half = top module
				bgRow = append(bgRow, bgDark) // lower half = bottom module
				i += len("▀")
			default:
				i++
			}
		}
		if len(fgRow) > 0 {
			grid = append(grid, fgRow, bgRow)
		}
	}
	return grid, nil
}

// TestRenderTerminalQR verifies the ANSI rendering maps every module to the
// correct color pair: dark module -> black, light module -> white, with the
// foreground carrying the top module and the background the bottom module.
// An inverted or shifted mapping produces QR codes many scanners cannot read.
func TestRenderTerminalQR(t *testing.T) {
	payload := "stun://AAAA-long-test-payload-with-stable-structure-0123456789"
	rendered, err := renderTerminalQR(payload)
	if err != nil {
		t.Fatalf("renderTerminalQR failed: %v", err)
	}

	wantQR, err := qrcode.New(payload, qrcode.Low)
	if err != nil {
		t.Fatalf("qrcode.New failed: %v", err)
	}
	want := wantQR.Bitmap()
	// Mirror the renderer's documented padding: an odd-height grid gets one
	// trailing light row (extra quiet zone below the bottom border).
	if len(want)%2 == 1 {
		want = append(want, make([]bool, len(want[0])))
	}
	got, err := decodeTerminalQR(rendered)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("row count mismatch: got %d want %d", len(got), len(want))
	}
	for y := range want {
		if len(got[y]) != len(want[y]) {
			t.Fatalf("row %d length mismatch: got %d want %d", y, len(got[y]), len(want[y]))
		}
		for x := range want[y] {
			if got[y][x] != want[y][x] {
				t.Fatalf("module mismatch at (%d,%d): got dark=%v want dark=%v", y, x, got[y][x], want[y][x])
			}
		}
	}
}

// TestPrintTerminalQRFallbackTooLarge ensures oversized payloads fall back to
// the plain-text rendering instead of panicking or emitting a broken QR.
func TestPrintTerminalQRFallbackTooLarge(t *testing.T) {
	huge := strings.Repeat("a", 100000) // exceeds QR version-40 capacity
	s, err := renderTerminalQR(huge)
	if err == nil {
		t.Fatalf("expected error for oversized payload, got %d bytes of QR", len(s))
	}
}
