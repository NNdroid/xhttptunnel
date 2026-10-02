package tunnel

import (
	"fmt"
	"sync/atomic"
)

const defaultWindowBytes = 4 << 20

func windowBytes(mb int) (int, error) {
	if mb == 0 {
		return defaultWindowBytes, nil
	}
	if mb < 1 || mb > 64 {
		return 0, fmt.Errorf("window_size_mb must be 0 or 1-64")
	}
	return mb << 20, nil
}

// Admission reserves the configured send window and conservative receive
// capacity (bytes.Buffer can retain more than its logical length), plus frame
// scratch. This bounds admitted tunnel buffers, not total process RSS/TLS/QUIC.
func bufferReservation(window int) int64 {
	// Use the largest permitted chunk so later SetChunkSizeKB calls cannot
	// increase an admitted session's scratch capacity beyond its reservation.
	maxFrame := chunkSizeBytes(900) + framePaddingBudget
	return int64(window) + 2*maxReassemblyBytes + maxOutOfOrderBytes + 12*int64(maxFrame)
}

// ValidateBufferLimits checks window sizes and server admission feasibility
// without creating a Client, Server, listener or transport. A zero budget
// preserves admission by session count alone.
func ValidateBufferLimits(windowSizeMB, bufferBudgetMB int) error {
	window, err := windowBytes(windowSizeMB)
	if err != nil {
		return err
	}
	if bufferBudgetMB < 0 || bufferBudgetMB > 65536 {
		return fmt.Errorf("buffer_budget_mb must be 0-65536")
	}
	if bufferBudgetMB > 0 && int64(bufferBudgetMB)<<20 < bufferReservation(window) {
		return fmt.Errorf("buffer_budget_mb cannot fit one session at this window size")
	}
	return nil
}

type bufferBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *bufferBudget) reserve(n int64) bool {
	if b == nil {
		return true
	}
	for {
		used := b.used.Load()
		if n > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}
