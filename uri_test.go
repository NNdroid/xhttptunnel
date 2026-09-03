package main

import (
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

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
