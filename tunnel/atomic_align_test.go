//go:build 386 || arm || mips || mipsle || ppc

package tunnel

import (
	"sync/atomic"
	"testing"
	"unsafe"
)

// TestAtomicFieldAlignment guards against the "unaligned 64-bit atomic
// operation" trap that fires on 32-bit targets (386/arm/...). A 64-bit field
// reached via sync/atomic.Load/Store/AddUint64 panics unless it sits on an
// 8-byte boundary; inside a large struct that is NOT guaranteed, so the
// fields below are either atomic.Int64 (compiler-enforced alignment) or, for
// the exported RequestCount, the first field of the struct (the Go memory
// model guarantees the first word of an allocated struct is 8-byte aligned).
//
// If this test fails, a field was moved out of alignment — restore it.
func TestAtomicFieldAlignment_32bit(t *testing.T) {
	var vc meekVirtualConn
	var xl XHTTPListener
	var at ActiveTracker

	check := func(name string, offset uintptr) {
		if offset%8 != 0 {
			t.Errorf("%s at offset %d is not 8-byte aligned (mod8=%d) — 64-bit atomic ops will trap on 32-bit targets",
				name, offset, offset%8)
		}
	}

	check("meekVirtualConn.lastActive", unsafe.Offsetof(vc.lastActive))
	check("XHTTPListener.RequestCount", unsafe.Offsetof(xl.RequestCount))
	check("ActiveTracker.n", unsafe.Offsetof(at.n))
	// udpSession is a function-local type; mirror it so it stays in sync with
	// the real definition's field order.
	type udpSessionMirror struct {
		lastActive atomic.Int64
		conn       interface{ Read([]byte) (int, error) }
	}
	var us udpSessionMirror
	check("udpSession.lastActive", unsafe.Offsetof(us.lastActive))
}
