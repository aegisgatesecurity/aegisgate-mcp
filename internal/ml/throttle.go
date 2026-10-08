// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// ML Inference Throttle — token bucket rate limiter for ML detection.
//
// Prevents the standalone MCP server from being used as a high-throughput
// ML detection API by capping inferences per minute, per second (burst),
// and concurrent inferences. When the cap is hit, ML gracefully degrades:
// detection is skipped (falling back to L1/L2 heuristics) and the event
// is logged/metered.
//
// Default caps (single-server envelope):
//   - 100 inferences / minute
//   - 10 inferences / second (burst)
//   - 4 concurrent inferences
//
// These caps are above the normal operating envelope for a single MCP
// server with 25 sessions and 60 RPM. They only become visible at
// automated/scaled workloads — which is when users should upgrade to
// AegisGate Platform for organization-wide ML threat detection.
// =========================================================================

package ml

import (
	"sync"
	"time"
)

// ThrottleConfig controls ML inference rate limits.
type ThrottleConfig struct {
	MaxPerMinute   int // Max inferences per rolling 60s window (0 = unlimited)
	MaxBurstPerSec int // Max inferences per rolling 1s window (0 = unlimited)
	MaxConcurrent  int // Max concurrent inferences (0 = unlimited)
}

// DefaultThrottleConfig returns the standalone product defaults.
// These are designed for a single MCP server and become a natural
// upgrade prompt to AegisGate Platform at scale.
func DefaultThrottleConfig() ThrottleConfig {
	return ThrottleConfig{
		MaxPerMinute:   100,
		MaxBurstPerSec: 10,
		MaxConcurrent:  4,
	}
}

// ThrottleStats holds runtime throttle statistics.
type ThrottleStats struct {
	TotalAllowed    int64
	TotalThrottled  int64
	CurrentInFlight int
}

// Throttle is a token-bucket + concurrency limiter for ML inferences.
type Throttle struct {
	mu sync.Mutex

	maxPerMinute   int
	maxBurstPerSec int
	maxConcurrent  int

	// Rolling window counters
	minuteWindow []time.Time // timestamps within last 60s
	secondWindow []time.Time // timestamps within last 1s

	// Concurrency
	inFlight int

	// Stats
	totalAllowed   int64
	totalThrottled int64
}

// NewThrottle creates a new ML inference throttle with the given config.
func NewThrottle(cfg ThrottleConfig) *Throttle {
	return &Throttle{
		maxPerMinute:   cfg.MaxPerMinute,
		maxBurstPerSec: cfg.MaxBurstPerSec,
		maxConcurrent:  cfg.MaxConcurrent,
	}
}

// Allow checks whether an inference is allowed under the throttle.
// Returns true if allowed, false if throttled. When allowed, the
// caller MUST call Release() when the inference is complete.
func (t *Throttle) Allow(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Prune expired entries from rolling windows
	t.pruneWindows(now)

	// Check concurrent limit
	if t.maxConcurrent > 0 && t.inFlight >= t.maxConcurrent {
		t.totalThrottled++
		return false
	}

	// Check per-minute limit
	if t.maxPerMinute > 0 && len(t.minuteWindow) >= t.maxPerMinute {
		t.totalThrottled++
		return false
	}

	// Check per-second burst limit
	if t.maxBurstPerSec > 0 && len(t.secondWindow) >= t.maxBurstPerSec {
		t.totalThrottled++
		return false
	}

	// Allow — record timestamp and increment
	t.minuteWindow = append(t.minuteWindow, now)
	t.secondWindow = append(t.secondWindow, now)
	t.inFlight++
	t.totalAllowed++
	return true
}

// Release marks a concurrent inference as complete.
func (t *Throttle) Release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.inFlight > 0 {
		t.inFlight--
	}
}

// Stats returns current throttle statistics.
func (t *Throttle) Stats() ThrottleStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return ThrottleStats{
		TotalAllowed:    t.totalAllowed,
		TotalThrottled:  t.totalThrottled,
		CurrentInFlight: t.inFlight,
	}
}

// pruneWindows removes timestamps older than the window boundaries.
func (t *Throttle) pruneWindows(now time.Time) {
	minuteCutoff := now.Add(-60 * time.Second)
	secondCutoff := now.Add(-1 * time.Second)

	// Prune minute window
	idx := 0
	for ; idx < len(t.minuteWindow); idx++ {
		if t.minuteWindow[idx].After(minuteCutoff) {
			break
		}
	}
	t.minuteWindow = t.minuteWindow[idx:]

	// Prune second window
	idx = 0
	for ; idx < len(t.secondWindow); idx++ {
		if t.secondWindow[idx].After(secondCutoff) {
			break
		}
	}
	t.secondWindow = t.secondWindow[idx:]
}
