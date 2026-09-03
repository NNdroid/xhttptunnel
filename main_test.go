package main

import (
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// init sets up a Nop logger so benchmarks are not slowed down by log spam.
func init() {
	logger = zap.NewNop()
	zap.ReplaceGlobals(logger)

	// If sendBuf were initialized inside main() in main.go, it could be nil
	// during tests and panic; initialize it here as a safety net.
	if sendBuf.New == nil {
		sendBuf = sync.Pool{
			New: func() interface{} {
				b := make([]byte, 262144) // default 256KB
				return &b
			},
		}
	}
}

// ==========================================
// 1. Unit tests (core logic correctness)
// ==========================================

func TestReliableBuffer_Logic(t *testing.T) {
	rb := newReliableBuffer(1024)

	// 1. Write data
	rb.Write([]byte("hello world"))

	// 2. GetSlice the data (not yet acknowledged)
	// Pass ackedSeq=0, dispatchSeq=0, maxLen=5
	data, seq, _ := rb.GetSlice(0, 0, 5)
	if string(data) != "hello" || seq != 0 {
		t.Fatalf("Expected 'hello' at seq 0, got %q at %d", data, seq)
	}

	// 3. Simulate the peer acknowledging the first 5 bytes (Ack = 5, i.e. 'hello')
	// The sliding window should advance; the next GetSlice should return ' world'
	// Pass ackedSeq=5, dispatchSeq=5, maxLen=100
	data2, seq2, _ := rb.GetSlice(5, 5, 100)
	if string(data2) != " world" || seq2 != 5 { // mind the leading space
		t.Fatalf("Expected ' world' at seq 5, got %q at %d", data2, seq2)
	}

	// 4. Simulate an out-of-range Ack that empties the buffer
	// Pass ackedSeq=11, dispatchSeq=11, maxLen=100
	rb.GetSlice(11, 11, 100)
	if rb.Len() != 0 {
		t.Fatalf("Buffer should be empty, len is %d", rb.Len())
	}
}

func TestMeekVirtualConn_PutReadData(t *testing.T) {
	vc := newMeekVirtualConn("test-session", nil, nil)

	// Test normal in-order arrival
	ack := vc.PutReadData(0, []byte("part1-"))
	if ack != 6 || vc.readBuf.String() != "part1-" {
		t.Fatalf("Failed normal seq")
	}

	// Test out-of-order / retransmitted arrival (Seq is still 0, should be silently dropped, Ack unchanged)
	ack2 := vc.PutReadData(0, []byte("part1-"))
	if ack2 != 6 || vc.readBuf.String() != "part1-" {
		t.Fatalf("Failed to drop duplicated packet")
	}

	// Test subsequent packet arrival
	vc.PutReadData(6, []byte("part2"))
	if vc.readBuf.String() != "part1-part2" {
		t.Fatalf("Failed combined packet")
	}
}

func TestGetClientIP(t *testing.T) {
	// Proxy headers are spoofable, so by default (trustProxyHeaders=false)
	// getClientIP must ignore them and fall back to RemoteAddr.
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = false }()

	// Default (secure): CF-Connecting-IP present but not trusted.
	r1, _ := http.NewRequest("GET", "http://example.com", nil)
	r1.RemoteAddr = "1.2.3.4:5678"
	r1.Header.Set("CF-Connecting-IP", "114.114.114.114")
	if ip := getClientIP(r1); ip != "1.2.3.4:5678" {
		t.Errorf("untrusted: CF-Connecting-IP leaked, got %s", ip)
	}

	// Trusted mode: headers are honoured.
	trustProxyHeaders = true
	if ip := getClientIP(r1); ip != "114.114.114.114" {
		t.Errorf("trusted: expected 114.114.114.114, got %s", ip)
	}

	// Case: X-Forwarded-For with multiple IPs
	r2, _ := http.NewRequest("GET", "http://example.com", nil)
	r2.RemoteAddr = "1.2.3.4:5678"
	r2.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.1")
	if ip := getClientIP(r2); ip != "8.8.8.8" {
		t.Errorf("trusted: expected 8.8.8.8, got %s", ip)
	}

	// Case: X-Real-IP
	r3, _ := http.NewRequest("GET", "http://example.com", nil)
	r3.RemoteAddr = "1.2.3.4:5678"
	r3.Header.Set("X-Real-IP", "1.1.1.1")
	if ip := getClientIP(r3); ip != "1.1.1.1" {
		t.Errorf("trusted: expected 1.1.1.1, got %s", ip)
	}

	// Case: no proxy headers -> RemoteAddr even when trusted.
	r4, _ := http.NewRequest("GET", "http://example.com", nil)
	r4.RemoteAddr = "192.168.1.100:12345"
	if ip := getClientIP(r4); ip != "192.168.1.100:12345" {
		t.Errorf("expected 192.168.1.100:12345, got %s", ip)
	}
}

func TestRedactAuth(t *testing.T) {
	// The Proxy-Authorization header carries the shared PSK in cleartext, so a
	// debug log must never contain it verbatim — logs get pasted into bug
	// reports and shipped to collectors. Only the shape may survive.
	cases := []struct {
		name, in, want string
	}{
		{"absent", "", "-"},
		{"bearer", "Bearer s3cr3t-token", "Bearer <12 bytes>"},
		{"raw-token-no-scheme", "s3cr3t", "<6 bytes>"},
		{"scheme-empty-token", "Bearer ", "Bearer <0 bytes>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactAuth(tc.in); got != tc.want {
				t.Fatalf("redactAuth(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// Belt and braces: whatever the shape, the secret itself must not appear.
	const secret = "super-secret-psk-value"
	if strings.Contains(redactAuth("Bearer "+secret), secret) {
		t.Fatal("redactAuth leaked the credential into the log line")
	}
}

// ==========================================
// Benchmarks: ring buffer stress performance
// Run with: go test -bench=BenchmarkReliableBuffer -benchmem -v
// ==========================================

// BenchmarkReliableBuffer_WriteOnly tests pure write throughput (no reads).
func BenchmarkReliableBuffer_WriteOnly(b *testing.B) {
	rb := newReliableBuffer(10 * 1024 * 1024) // 10MB buffer
	payload := make([]byte, 4096)             // 4KB payload
	rand.Read(payload)

	b.SetBytes(4096)
	b.ReportAllocs() // enable allocation tracking
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Manually drain before the buffer fills up, simulating an instant peer ACK
		if rb.Len() >= rb.maxSize-4096 {
			rb.mu.Lock()
			rb.tail = rb.head
			rb.count = 0
			rb.mu.Unlock()
		}
		_, _ = rb.Write(payload)
	}
}

// BenchmarkReliableBuffer_Sequential_1KB simulates frequent small packets (SSH keystrokes, heartbeats).
func BenchmarkReliableBuffer_Sequential_1KB(b *testing.B) {
	rb := newReliableBuffer(4 * 1024 * 1024) // 4MB
	payload := make([]byte, 1024)            // 1KB small packet
	b.SetBytes(1024)
	b.ReportAllocs()
	b.ResetTimer()

	var ack uint64 = 0
	var dispatch uint64 = 0

	for i := 0; i < b.N; i++ {
		// 1. Write
		n, _ := rb.Write(payload)

		// 2. Read and advance the Ack
		slice, nextSeq, bufPtr := rb.GetSlice(ack, dispatch, 1024)

		ack += uint64(n)
		dispatch = nextSeq

		// Return the buffer to the pool (mirrors production behavior)
		if bufPtr != nil {
			// Replace with your real pool if your pool variable has a different name
			sendBuf.Put(bufPtr)
		}

		_ = slice // prevent the compiler from optimizing it away
	}
}

// BenchmarkReliableBuffer_Sequential_512KB simulates bulk transfers (SFTP downloads, video streaming).
func BenchmarkReliableBuffer_Sequential_512KB(b *testing.B) {
	rb := newReliableBuffer(4 * 1024 * 1024) // 4MB
	payload := make([]byte, 512*1024)        // 512KB large packet
	b.SetBytes(512 * 1024)
	b.ReportAllocs()
	b.ResetTimer()

	var ack uint64 = 0
	var dispatch uint64 = 0

	for i := 0; i < b.N; i++ {
		n, _ := rb.Write(payload)

		slice, nextSeq, bufPtr := rb.GetSlice(ack, dispatch, 512*1024)

		ack += uint64(n)
		dispatch = nextSeq

		if bufPtr != nil {
			sendBuf.Put(bufPtr)
		}
		_ = slice
	}
}

// BenchmarkReliableBuffer_Wraparound stress test: ring-copy performance across the array boundary.
func BenchmarkReliableBuffer_Wraparound(b *testing.B) {
	// Critical: the buffer (2MB) must be more than twice the payload (1.6MB)
	// to avoid a single-threaded deadlock.
	rb := newReliableBuffer(2 * 1024 * 1024)
	payload := make([]byte, 800*1024) // 800KB Payload

	b.SetBytes(800 * 1024)
	b.ReportAllocs()
	b.ResetTimer()

	var ack uint64 = 0
	var dispatch uint64 = 0

	for i := 0; i < b.N; i++ {
		// 1. Write 800KB
		n, _ := rb.Write(payload)

		// 2. Read out and clear the previous round's data
		slice, nextSeq, bufPtr := rb.GetSlice(ack, dispatch, 800*1024)

		// 3. Advance the acknowledgment number
		ack += uint64(n)
		dispatch = nextSeq

		// 4. Return the buffer to the pool safely
		if bufPtr != nil {
			sendBuf.Put(bufPtr)
		}
		_ = slice
	}
}
