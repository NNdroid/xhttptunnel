package tunnel

import "testing"

// benchStreamFrameStorage isolates the downlink frame-scratch allocation that
// the HTTP/3 writer path pays per frame. A nil scratch allocates a fresh ~257
// KiB buffer every call; a rotated pool that remembers each result reuses it.
func benchStreamFrameStorage(b *testing.B, rotate bool) {
	const length = 256 * 1024
	const pad = 64
	var pool = [3][]byte{}
	idx := 0
	b.SetBytes(int64(length + pad))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var scratch []byte
		if rotate {
			scratch = pool[idx]
			idx = (idx + 1) % len(pool)
		}
		buf := streamFrameStorage(scratch, uint64(i), 0, length, pad)
		if len(buf) < 22+pad+length {
			b.Fatal("short frame")
		}
		if rotate {
			pool[(idx+len(pool)-1)%len(pool)] = buf
		}
	}
}

func BenchmarkStreamFrameStorage_Allocate(b *testing.B) { benchStreamFrameStorage(b, false) }
func BenchmarkStreamFrameStorage_Rotate3(b *testing.B)  { benchStreamFrameStorage(b, true) }
