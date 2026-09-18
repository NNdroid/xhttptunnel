//go:build !linux

package tunnel

// TCP Brutal is a Linux kernel module, so no other platform has anything to
// configure.
//
// This is a compile-time no-op rather than a runtime GOOS check for two
// reasons. First, golang.org/x/sys does not compile for GOOS=windows at all,
// and the published release matrix ships three Windows targets, so a runtime
// branch would not build. Second, a build tag keeps the option out of the
// binary entirely instead of carrying dead code, which matters on the 32-bit
// targets where code size is a real budget.
//
// The feature degrades by design: a configured-but-unavailable brutal logs one
// warning and the tunnel keeps working uncapped.

var defaultBrutalOps brutalOps = brutalStubOps{}

// brutalAvailable is false on every non-Linux platform, so the per-connection
// hook is never installed and the dial path stays exactly as fast as before.
func brutalAvailable() bool { return false }

type brutalStubOps struct{}

func (brutalStubOps) setCongestion(fd uintptr) error { return errBrutalUnsupported }

func (brutalStubOps) getCongestion(fd uintptr) (string, error) {
	return "", errBrutalUnsupported
}

func (brutalStubOps) setParams(fd uintptr, data []byte) error { return errBrutalUnsupported }
