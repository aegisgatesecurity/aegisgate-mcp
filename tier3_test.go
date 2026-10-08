//go:build load

package mcpsecurity

import (
	"encoding/json"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConnectionChurn validates the server's ability to handle rapid
// connect/disconnect cycles without leaking connections or sessions.
//
// Unlike a connection flood test (which holds many connections open
// simultaneously), this test repeatedly opens a connection, performs a
// full initialize handshake, and immediately closes it — 500 times in
// sequence. This exercises the cleanup / teardown path on every cycle
// and verifies that ConnectionCount() returns to zero after all churn
// completes. A high churn rate (connections/sec) indicates that the
// accept/close lifecycle is efficient and not accumulating deferred work.
func TestConnectionChurn(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.MaxConnections = 1000
	cfg.MaxSessions = 500

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const cycles = 500

	start := time.Now()

	for i := 0; i < cycles; i++ {
		churnOnce(t, addr, "test-bearer-token")
	}

	elapsed := time.Since(start)

	// Allow time for the server's goroutines to clean up closed connections.
	time.Sleep(100 * time.Millisecond)

	// After all churn cycles, every connection should have been cleaned up.
	if got := srv.server.ConnectionCount(); got != 0 {
		t.Errorf("expected ConnectionCount()==0 after churn, got %d", got)
	}

	rate := float64(cycles) / elapsed.Seconds()
	t.Logf("Connection churn: %d cycles in %v (%.0f connections/sec)", cycles, elapsed, rate)
}

// churnOnce performs a single dial → initialize → close cycle synchronously.
func churnOnce(t *testing.T, addr, token string) {
	conn, enc, dec, initResp := dialAndInitialize(t, addr, token)
	if initResp == nil {
		t.Fatal("initialize returned nil response during churn")
	}
	_ = enc
	_ = dec
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close churn connection: %v", err)
	}
}

// TestMixedWorkload validates server behaviour under a realistic blend
// of request types rather than a single uniform workload.
//
// Ten concurrent connections are maintained for 3 seconds. Each
// connection randomly sends one of three request types according to a
// fixed distribution:
//
//	70 %  tools/call  (ping)
//	20 %  tools/list
//	10 %  initialize
//
// Success and error counts are tracked per request type with atomic
// counters. After all connections finish the test asserts that no
// errors occurred and logs a per-type breakdown. This catches issues
// that only surface when the server multiplexes different request
// handlers concurrently (e.g. shared state contention, response
// encoding bugs that are type-specific).
func TestMixedWorkload(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.DemoTools = true
	cfg.MaxSessions = 100000   // very high — re-initialize creates sessions
	cfg.RateLimitRPM = 0       // disable rate limiting for mixed workload
	cfg.MaxToolsPerSession = 0 // disable per-session tool count limit

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const (
		numConns = 10
		duration = 3 * time.Second
	)

	// Atomic counters per request type.
	var pingSuccess, pingError int64
	var listSuccess, listError int64
	var initSuccess, initError int64

	var wg sync.WaitGroup
	deadline := time.Now().Add(duration)

	for c := 0; c < numConns; c++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, enc, dec, initResp := dialAndInitialize(t, addr, "test-bearer-token")
			if initResp == nil {
				atomic.AddInt64(&initError, 1)
				t.Errorf("conn %d: initial initialize failed", connID)
				conn.Close()
				return
			}
			defer conn.Close()

			atomic.AddInt64(&initSuccess, 1)
			id := 1

			for time.Now().Before(deadline) {
				roll := rand.Float64() // 0.0 – 1.0
				var resp JSONRPCResponse

				switch {
				case roll < 0.70:
					// tools/call ping — 70 %
					callParams, _ := json.Marshal(map[string]interface{}{
						"name":      "ping",
						"arguments": map[string]interface{}{},
					})
					req := &JSONRPCRequest{
						JSONRPC: JSONRPCVersion,
						Method:  "tools/call",
						Params:  callParams,
						ID:      id,
					}
					if err := enc.Encode(req); err != nil {
						atomic.AddInt64(&pingError, 1)
						return
					}
					if err := dec.Decode(&resp); err != nil {
						atomic.AddInt64(&pingError, 1)
						return
					}
					if resp.Error != nil {
						atomic.AddInt64(&pingError, 1)
					} else {
						atomic.AddInt64(&pingSuccess, 1)
					}

				case roll < 0.90:
					// tools/list — 20 %
					req := &JSONRPCRequest{
						JSONRPC: JSONRPCVersion,
						Method:  "tools/list",
						ID:      id,
					}
					if err := enc.Encode(req); err != nil {
						atomic.AddInt64(&listError, 1)
						return
					}
					if err := dec.Decode(&resp); err != nil {
						atomic.AddInt64(&listError, 1)
						return
					}
					if resp.Error != nil {
						atomic.AddInt64(&listError, 1)
					} else {
						atomic.AddInt64(&listSuccess, 1)
					}

				default:
					// initialize — 10 %
					initParams, _ := json.Marshal(map[string]interface{}{
						"protocolVersion": ProtocolVersion,
						"clientInfo":      map[string]interface{}{"name": "mixed", "version": "1.0"},
						"auth":            map[string]interface{}{"token": "test-bearer-token"},
					})
					req := &JSONRPCRequest{
						JSONRPC: JSONRPCVersion,
						Method:  "initialize",
						Params:  initParams,
						ID:      id,
					}
					if err := enc.Encode(req); err != nil {
						atomic.AddInt64(&initError, 1)
						return
					}
					if err := dec.Decode(&resp); err != nil {
						atomic.AddInt64(&initError, 1)
						return
					}
					if resp.Error != nil {
						atomic.AddInt64(&initError, 1)
					} else {
						atomic.AddInt64(&initSuccess, 1)
					}
				}

				id++
			}
		}(c)
	}

	wg.Wait()

	// Aggregate and verify.
	totalPing := atomic.LoadInt64(&pingSuccess) + atomic.LoadInt64(&pingError)
	totalList := atomic.LoadInt64(&listSuccess) + atomic.LoadInt64(&listError)
	totalInit := atomic.LoadInt64(&initSuccess) + atomic.LoadInt64(&initError)

	if pingErr := atomic.LoadInt64(&pingError); pingErr > 0 {
		t.Errorf("ping errors: %d / %d", pingErr, totalPing)
	}
	if listErr := atomic.LoadInt64(&listError); listErr > 0 {
		t.Errorf("tools/list errors: %d / %d", listErr, totalList)
	}
	if initErr := atomic.LoadInt64(&initError); initErr > 0 {
		t.Errorf("initialize errors: %d / %d", initErr, totalInit)
	}

	t.Logf("Mixed workload breakdown (10 conns × 3 s):")
	t.Logf("  tools/call  (ping): %d success, %d error", atomic.LoadInt64(&pingSuccess), atomic.LoadInt64(&pingError))
	t.Logf("  tools/list:         %d success, %d error", atomic.LoadInt64(&listSuccess), atomic.LoadInt64(&listError))
	t.Logf("  initialize:         %d success, %d error", atomic.LoadInt64(&initSuccess), atomic.LoadInt64(&initError))
	t.Logf("  total:              %d requests", totalPing+totalList+totalInit)
}

// TestMemoryProfile validates that the server does not leak excessive
// heap memory under sustained load.
//
// Twenty concurrent connections each send 100 ping (tools/call)
// requests — 2 000 requests total. runtime.MemStats is captured
// before and after the workload, with an explicit runtime.GC() call
// before the "after" snapshot so that only reachable (potentially
// leaked) allocations are measured.
//
// The test reports:
//   - heap allocated before / after and the delta
//   - GC cycle count before / after
//   - average bytes allocated per request
//
// A delta exceeding 10 MB for 2 000 requests would indicate a likely
// memory leak or unbounded cache growth.
func TestMemoryProfile(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.DemoTools = true
	cfg.MaxSessions = 500
	cfg.RateLimitRPM = 0       // disable rate limiting for memory profiling
	cfg.MaxToolsPerSession = 0 // disable per-session tool count limit

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const (
		numConns      = 20
		reqsPerConn   = 100
		totalRequests = numConns * reqsPerConn
	)

	// --- before snapshot ---------------------------------------------------
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var wg sync.WaitGroup

	for c := 0; c < numConns; c++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, enc, dec, initResp := dialAndInitialize(t, addr, "test-bearer-token")
			if initResp == nil {
				t.Errorf("conn %d: initialize failed", connID)
				return
			}
			defer conn.Close()

			for i := 0; i < reqsPerConn; i++ {
				resp, err := callPing(enc, dec, i)
				if err != nil {
					t.Errorf("conn %d: ping %d error: %v", connID, i, err)
					return
				}
				if resp.Error != nil {
					t.Errorf("conn %d: ping %d server error: %v", connID, i, resp.Error)
					return
				}
			}
		}(c)
	}

	wg.Wait()

	// --- after snapshot ----------------------------------------------------
	// Force GC so only retained (live) allocations remain on the heap.
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heapBefore := int64(before.HeapAlloc)
	heapAfter := int64(after.HeapAlloc)
	heapDelta := heapAfter - heapBefore
	allocsPerReq := float64(after.TotalAlloc-before.TotalAlloc) / float64(totalRequests)

	t.Logf("Memory profile (20 conns × 100 pings = %d requests):", totalRequests)
	t.Logf("  heap before:   %s", humanBytes(heapBefore))
	t.Logf("  heap after:    %s", humanBytes(heapAfter))
	t.Logf("  heap delta:    %s", humanBytes(heapDelta))
	t.Logf("  GC before:     %d", before.NumGC)
	t.Logf("  GC after:      %d", after.NumGC)
	t.Logf("  allocs/req:    %.0f bytes", allocsPerReq)

	const maxDeltaMB = 10
	if heapDelta > maxDeltaMB*1024*1024 {
		t.Errorf("heap delta %s exceeds %d MB — possible memory leak", humanBytes(heapDelta), maxDeltaMB)
	}
}

// humanBytes formats a byte count into a human-readable string.
func humanBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
	)
	switch {
	case b >= MB:
		return formatFloat(float64(b)/float64(MB), "MB")
	case b >= KB:
		return formatFloat(float64(b)/float64(KB), "KB")
	default:
		return formatFloat(float64(b), "B")
	}
}

// formatFloat returns a string with one decimal place followed by the unit.
func formatFloat(v float64, unit string) string {
	// Use a simple formatting approach that avoids importing fmt.
	whole := int64(v)
	frac := int64((v - float64(whole)) * 10)
	if frac < 0 {
		frac = -frac
	}
	itoa := func(n int64) string {
		if n == 0 {
			return "0"
		}
		neg := n < 0
		if neg {
			n = -n
		}
		var buf [20]byte
		i := len(buf)
		for n > 0 {
			i--
			buf[i] = byte('0' + n%10)
			n /= 10
		}
		s := string(buf[i:])
		if neg {
			return "-" + s
		}
		return s
	}
	return itoa(whole) + "." + itoa(frac) + " " + unit
}
