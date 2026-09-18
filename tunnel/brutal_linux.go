//go:build linux

package tunnel

import (
	"errors"

	"golang.org/x/sys/unix"
)

// brutalLinuxOps is the production implementation of brutalOps.
//
// TCP Brutal is a Linux kernel module, so this is the only platform with a
// real implementation; everything else is a compiled-in no-op, see
// brutal_other.go.
//
// The calls go through SetsockoptString and GetsockoptString because the
// pinned x/sys version has no raw-byte sockopt helper. SetsockoptString passes
// a pointer and a length straight to setsockopt, so it carries the packed
// binary struct just as well as it carries the algorithm name "brutal" — the
// kernel reads exactly len(data) bytes.
type brutalLinuxOps struct{}

var defaultBrutalOps brutalOps = brutalLinuxOps{}

// brutalAvailable reports whether this platform can configure brutal at all.
// Checked once at startup: it decides whether a configured-but-impossible
// feature is warned about, and whether the per-connection hook is installed.
func brutalAvailable() bool { return true }

func (brutalLinuxOps) setCongestion(fd uintptr) error {
	return normaliseSockoptErr(unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"))
}

func (brutalLinuxOps) getCongestion(fd uintptr) (string, error) {
	algo, err := unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	if err != nil {
		return "", normaliseSockoptErr(err)
	}
	return algo, nil
}

func (brutalLinuxOps) setParams(fd uintptr, data []byte) error {
	return normaliseSockoptErr(unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, brutalParamsOpt, string(data)))
}

// normaliseSockoptErr maps kernel errno values onto the sentinels enableBrutal
// switches on. Keeping the mapping here means enableBrutal never imports the
// syscall package, which is what lets its tests compile on every platform.
func normaliseSockoptErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.EPERM):
		return errLocked
	case errors.Is(err, unix.ENOPROTOOPT), errors.Is(err, unix.EINVAL):
		// ENOPROTOOPT comes back from a plain TCP socket that has no module
		// loaded; EINVAL when the kernel has never heard of the algorithm name.
		return errNoModule
	}
	return err
}
