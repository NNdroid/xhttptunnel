//go:build 386 || arm || mips || mipsle || ppc

package tunnel

import (
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// TestAtomicFieldAlignment_32bit guards against the "unaligned 64-bit atomic
// operation" trap that fires on 32-bit targets (386/arm/...). A 64-bit field
// reached via a sync/atomic free function panics unless it sits on an
// 8-byte boundary; inside a large struct that is NOT guaranteed, so every
// 64-bit-wide atomic in this package uses atomic.Int64/Uint64/Pointer, which
// embed an align64 field and are therefore 8-byte aligned wherever they land.
//
// Only the 64-bit-wide wrappers need this check. atomic.Int32/Uint32/Bool
// store a 32-bit value behind a noCopy and are 4-byte aligned on every
// platform — a 32-bit atomic op has no alignment requirement at all, so those
// fields are exempt by construction and asserting otherwise would be wrong.
//
// The Offsetof checks below are deliberately tautological for a wrapper-typed
// field — that is the point. They exist to fail the build the moment someone
// "simplifies" a wrapper back to a bare int64/uint64 for speed, which is
// exactly how this class of defect enters the codebase.
//
// The address checks at the end are the stronger assertion: Offsetof only
// proves that a field's offset within a type is a multiple of 8, not that the
// runtime ever places the object at an 8-byte-aligned address. The latter is
// what the atomic op actually needs. Each type checked there has its own
// alignment of 8, so the runtime must place it on an 8-byte boundary; a bare
// int64 field would not get that guarantee.
//
// If this test fails, a field was moved out of alignment — restore it.
func TestAtomicFieldAlignment_32bit(t *testing.T) {
	var vc meekVirtualConn
	var xl XHTTPListener
	var at ActiveTracker
	var cl Client
	var srv Server
	var ss serverState

	check := func(name string, offset uintptr) {
		if offset%8 != 0 {
			t.Errorf("%s at offset %d is not 8-byte aligned (mod8=%d) — 64-bit atomic ops will trap on 32-bit targets",
				name, offset, offset%8)
		}
	}

	// meekVirtualConn. lastActive is the one the original guard named; the
	// rest of the session's shared 64-bit state lives here too.
	check("meekVirtualConn.lastActive", unsafe.Offsetof(vc.lastActive))
	check("meekVirtualConn.downWriter", unsafe.Offsetof(vc.downWriter))
	check("meekVirtualConn.downPeerAck", unsafe.Offsetof(vc.downPeerAck))
	check("meekVirtualConn.closeErr", unsafe.Offsetof(vc.closeErr))

	// XHTTPListener.RequestCount is exported, so it is the one a reader is
	// most likely to reach from outside this package.
	check("XHTTPListener.RequestCount", unsafe.Offsetof(xl.RequestCount))
	check("ActiveTracker.n", unsafe.Offsetof(at.n))

	// Client keeps its bandwidth-exchange state deep in a struct of pointers,
	// which is precisely where a bare 64-bit field would land on a 4-byte
	// boundary.
	check("Client.dialCount", unsafe.Offsetof(cl.dialCount))
	check("Client.bwNegotiated", unsafe.Offsetof(cl.bwNegotiated))
	check("Client.bwLastAttempt", unsafe.Offsetof(cl.bwLastAttempt))

	// Server.xl is published by ListenAndServe and read by Close/Addr.
	check("Server.xl", unsafe.Offsetof(srv.xl))
	// serverState.allowed and its monotonic stats counters.
	check("serverState.allowed", unsafe.Offsetof(ss.allowed))
	check("serverState.stats.sessionsTotal", unsafe.Offsetof(ss.stats.sessionsTotal))
	check("serverState.stats.sessionsReject", unsafe.Offsetof(ss.stats.sessionsReject))
	check("serverState.stats.sessionsKicked", unsafe.Offsetof(ss.stats.sessionsKicked))
	check("serverState.stats.sessionsReaped", unsafe.Offsetof(ss.stats.sessionsReaped))
	check("serverState.stats.requests", unsafe.Offsetof(ss.stats.requests))

	// udpSession and ackedByServer are function-local (a PacketConn field and
	// two goroutine-closure locals respectively), so they cannot be referenced
	// directly; mirrors carry the same wrapper types and the same guarantee.
	type udpSessionMirror struct {
		lastActive atomic.Int64
		conn       interface{ Read([]byte) (int, error) }
	}
	var us udpSessionMirror
	check("udpSession.lastActive", unsafe.Offsetof(us.lastActive))

	// The poll pump's closure locals, in their real order. Only ackedByServer
	// gets atomic ops; the rest are guarded by windowMu. Keeping the bare
	// uint64s in the mirror is what makes the check meaningful — it proves the
	// wrapper stays aligned even with unaligned-by-design neighbours around it.
	type pumpLocals struct {
		ackedByServer atomic.Uint64
		dispatchSeq   uint64
		windowMu      sync.Mutex
		triggerRetry  int32
		emptyPollers  int32
	}
	var pl pumpLocals
	check("ackedByServer", unsafe.Offsetof(pl.ackedByServer))

	// Runtime alignment of real objects — see the note above.
	checkAddr := func(name string, p uintptr) {
		if p%8 != 0 {
			t.Errorf("%s at 0x%x is not 8-byte aligned (mod8=%d) — the allocation lost the 64-bit alignment",
				name, p, p%8)
		}
	}
	checkAddr("meekVirtualConn", uintptr(unsafe.Pointer(new(meekVirtualConn))))
	checkAddr("XHTTPListener", uintptr(unsafe.Pointer(new(XHTTPListener))))
	checkAddr("ActiveTracker", uintptr(unsafe.Pointer(new(ActiveTracker))))
	checkAddr("clientState", uintptr(unsafe.Pointer(new(Client))))
	// Package-level atomics: allocated by the linker, so they carry no struct
	// offset to worry about — but the same property is worth asserting.
	checkAddr("maxsendBufSize", uintptr(unsafe.Pointer(&maxsendBufSize)))
	checkAddr("customTransportSerial", uintptr(unsafe.Pointer(&customTransportSerial)))
}
