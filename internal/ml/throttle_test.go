// SPDX-License-Identifier: Apache-2.0
package ml

import (
	"testing"
	"time"
)

func TestThrottle_AllowsUnderLimit(t *testing.T) {
	throttle := NewThrottle(DefaultThrottleConfig())
	now := time.Now()

	for i := 0; i < 10; i++ {
		if !throttle.Allow(now) {
			t.Fatalf("inference %d should be allowed, got throttled", i)
		}
		throttle.Release()
	}

	stats := throttle.Stats()
	if stats.TotalAllowed != 10 {
		t.Errorf("expected 10 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalThrottled != 0 {
		t.Errorf("expected 0 throttled, got %d", stats.TotalThrottled)
	}
}

func TestThrottle_ThrottlesAtPerMinuteLimit(t *testing.T) {
	cfg := ThrottleConfig{MaxPerMinute: 5, MaxBurstPerSec: 0, MaxConcurrent: 0}
	throttle := NewThrottle(cfg)
	now := time.Now()

	for i := 0; i < 5; i++ {
		if !throttle.Allow(now) {
			t.Fatalf("inference %d should be allowed", i)
		}
		throttle.Release()
	}

	// 6th should be throttled
	if throttle.Allow(now) {
		t.Fatal("6th inference should be throttled")
	}
	throttle.Release()

	stats := throttle.Stats()
	if stats.TotalAllowed != 5 {
		t.Errorf("expected 5 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalThrottled != 1 {
		t.Errorf("expected 1 throttled, got %d", stats.TotalThrottled)
	}
}

func TestThrottle_ThrottlesAtBurstLimit(t *testing.T) {
	cfg := ThrottleConfig{MaxPerMinute: 0, MaxBurstPerSec: 3, MaxConcurrent: 0}
	throttle := NewThrottle(cfg)
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !throttle.Allow(now) {
			t.Fatalf("inference %d should be allowed", i)
		}
		throttle.Release()
	}

	// 4th in same second should be throttled
	if throttle.Allow(now) {
		t.Fatal("4th inference in same second should be throttled")
	}
	throttle.Release()

	// After 1.1 seconds, should be allowed again
	later := now.Add(1100 * time.Millisecond)
	if !throttle.Allow(later) {
		t.Fatal("inference after 1.1s should be allowed")
	}
	throttle.Release()
}

func TestThrottle_ThrottlesAtConcurrentLimit(t *testing.T) {
	cfg := ThrottleConfig{MaxPerMinute: 0, MaxBurstPerSec: 0, MaxConcurrent: 2}
	throttle := NewThrottle(cfg)
	now := time.Now()

	// Start 2 concurrent (don't release)
	if !throttle.Allow(now) {
		t.Fatal("1st concurrent should be allowed")
	}
	if !throttle.Allow(now) {
		t.Fatal("2nd concurrent should be allowed")
	}

	// 3rd concurrent should be throttled
	if throttle.Allow(now) {
		t.Fatal("3rd concurrent should be throttled")
	}

	// Release one
	throttle.Release()

	// Now should be allowed
	if !throttle.Allow(now) {
		t.Fatal("inference after release should be allowed")
	}
	throttle.Release()
	throttle.Release()
}

func TestThrottle_WindowExpiry(t *testing.T) {
	cfg := ThrottleConfig{MaxPerMinute: 3, MaxBurstPerSec: 0, MaxConcurrent: 0}
	throttle := NewThrottle(cfg)
	now := time.Now()

	// Use 3 inferences
	for i := 0; i < 3; i++ {
		throttle.Allow(now)
		throttle.Release()
	}

	// Throttled at same time
	if throttle.Allow(now) {
		t.Fatal("4th inference should be throttled")
	}
	throttle.Release()

	// After 61 seconds, window should have expired
	later := now.Add(61 * time.Second)
	if !throttle.Allow(later) {
		t.Fatal("inference after 61s should be allowed (window expired)")
	}
	throttle.Release()
}

func TestThrottle_UnlimitedConfig(t *testing.T) {
	cfg := ThrottleConfig{MaxPerMinute: 0, MaxBurstPerSec: 0, MaxConcurrent: 0}
	throttle := NewThrottle(cfg)
	now := time.Now()

	for i := 0; i < 1000; i++ {
		if !throttle.Allow(now) {
			t.Fatalf("inference %d should be allowed with unlimited config", i)
		}
		throttle.Release()
	}

	stats := throttle.Stats()
	if stats.TotalAllowed != 1000 {
		t.Errorf("expected 1000 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalThrottled != 0 {
		t.Errorf("expected 0 throttled, got %d", stats.TotalThrottled)
	}
}

func TestThrottle_StatsAccuracy(t *testing.T) {
	cfg := ThrottleConfig{MaxPerMinute: 10, MaxBurstPerSec: 5, MaxConcurrent: 2}
	throttle := NewThrottle(cfg)
	now := time.Now()

	// 2 concurrent
	throttle.Allow(now)
	throttle.Allow(now)

	// 3rd concurrent throttled
	throttle.Allow(now)

	stats := throttle.Stats()
	if stats.TotalAllowed != 2 {
		t.Errorf("expected 2 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalThrottled != 1 {
		t.Errorf("expected 1 throttled, got %d", stats.TotalThrottled)
	}
	if stats.CurrentInFlight != 2 {
		t.Errorf("expected 2 in-flight, got %d", stats.CurrentInFlight)
	}

	throttle.Release()
	stats = throttle.Stats()
	if stats.CurrentInFlight != 1 {
		t.Errorf("expected 1 in-flight after release, got %d", stats.CurrentInFlight)
	}
}
