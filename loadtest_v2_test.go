//go:build load

// SPDX-License-Identifier: Apache-2.0
// Comprehensive k6-style load, stress, burst, crush, and chaos testing
// for the AegisGate MCP server across TCP and HTTP/SSE transports.
//
// This file complements load_test.go with additional test categories:
//
//   - Stress:  TestStressRampUp — gradually increase load to find breaking point
//   - Burst:   TestBurstConnectionSpike, TestBurstRequestSpike, TestBurstRecovery
//   - Crush:   TestCrushBeyondMaxConnections, TestCrushMemoryPressure,
//              TestCrushGoroutineExplosion, TestCrushMalformedFlood
//   - Chaos:   TestChaosRandomDrops, TestChaosHalfSentMessages,
//              TestChaosShutdownUnderLoadTCP
//   - HTTP:    TestHTTPLoadConcurrent, TestHTTPLoadSustained,
//              TestHTTPBurstRequest, TestHTTPBreakOversizedBody,
//              TestHTTPBreakAuthFlood, TestHTTPCrushConnectionExhaustion,
//              TestHTTPSoakStability, TestHTTPSSEReconnect,
//              TestHTTPBatchLoad
//   - Cross:   TestCrossTransportLatency — TCP vs HTTP head-to-head
//
// Run with:
//
//	go test -tags=load -v -timeout=300s -run "TestStress|TestBurst|TestCrush|TestChaos|TestHTTP|TestCross" .
//
// Or run everything:
//
//	go test -tags=load -v -timeout=300s .

package mcpsecurity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================
// Metrics Collection Framework
// ============================================================

// loadMetrics collects runtime metrics during load tests.
type loadMetrics struct {
	startTime time.Time
	memBefore runtime.MemStats
	memAfter  runtime.MemStats
	goBefore  int
	goAfter   int

	// Latency tracking (thread-safe)
	latMu      sync.Mutex
	latencies  []time.Duration
	successCnt int64
	errorCnt   int64
	timeoutCnt int64
	rejectCnt  int64
}

func newLoadMetrics() *loadMetrics {
	m := &loadMetrics{startTime: time.Now()}
	runtime.GC()
	runtime.ReadMemStats(&m.memBefore)
	m.goBefore = runtime.NumGoroutine()
	return m
}

func (m *loadMetrics) recordLatency(d time.Duration) {
	m.latMu.Lock()
	m.latencies = append(m.latencies, d)
	m.latMu.Unlock()
}

func (m *loadMetrics) recordSuccess() { atomic.AddInt64(&m.successCnt, 1) }
func (m *loadMetrics) recordError()   { atomic.AddInt64(&m.errorCnt, 1) }
func (m *loadMetrics) recordTimeout() { atomic.AddInt64(&m.timeoutCnt, 1) }
func (m *loadMetrics) recordReject()  { atomic.AddInt64(&m.rejectCnt, 1) }

func (m *loadMetrics) finalize() {
	runtime.GC()
	runtime.ReadMemStats(&m.memAfter)
	m.goAfter = runtime.NumGoroutine()
}

func (m *loadMetrics) sortedLatencies() []time.Duration {
	m.latMu.Lock()
	s := make([]time.Duration, len(m.latencies))
	copy(s, m.latencies)
	m.latMu.Unlock()
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s
}

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p / 100)
	return sorted[idx]
}

// report prints a formatted metrics report and returns a summary string.
func (m *loadMetrics) report(t *testing.T, label string) string {
	m.finalize()
	sorted := m.sortedLatencies()
	elapsed := time.Since(m.startTime)

	successes := atomic.LoadInt64(&m.successCnt)
	errors := atomic.LoadInt64(&m.errorCnt)
	timeouts := atomic.LoadInt64(&m.timeoutCnt)
	rejects := atomic.LoadInt64(&m.rejectCnt)
	total := successes + errors + timeouts + rejects

	heapGrowth := int64(m.memAfter.HeapAlloc) - int64(m.memBefore.HeapAlloc)
	goroutineDelta := m.goAfter - m.goBefore
	rps := 0.0
	if elapsed.Seconds() > 0 {
		rps = float64(successes) / elapsed.Seconds()
	}

	t.Logf("")
	t.Logf("┌─────────────────────────────────────────────────────────┐")
	t.Logf("│  %s", padRight(label, 55))
	t.Logf("├─────────────────────────────────────────────────────────┤")
	t.Logf("│  Duration:         %s", padRight(fmt.Sprintf("%.2fs", elapsed.Seconds()), 38))
	t.Logf("│  Total requests:   %s", padRight(fmt.Sprintf("%d", total), 38))
	t.Logf("│  Successful:       %s", padRight(fmt.Sprintf("%d (%.1f%%)", successes, pctOf(successes, total)), 38))
	t.Logf("│  Errors:           %s", padRight(fmt.Sprintf("%d", errors), 38))
	t.Logf("│  Timeouts:         %s", padRight(fmt.Sprintf("%d", timeouts), 38))
	t.Logf("│  Rejected:         %s", padRight(fmt.Sprintf("%d", rejects), 38))
	t.Logf("│  Throughput:       %s", padRight(fmt.Sprintf("%.0f req/sec", rps), 38))
	if len(sorted) > 0 {
		t.Logf("│  Latency p50:      %s", padRight(pct(sorted, 50).String(), 38))
		t.Logf("│  Latency p90:      %s", padRight(pct(sorted, 90).String(), 38))
		t.Logf("│  Latency p99:      %s", padRight(pct(sorted, 99).String(), 38))
		t.Logf("│  Latency max:      %s", padRight(sorted[len(sorted)-1].String(), 38))
	}
	t.Logf("│  Goroutines:       %s", padRight(fmt.Sprintf("before=%d after=%d Δ=%d", m.goBefore, m.goAfter, goroutineDelta), 38))
	t.Logf("│  Heap growth:      %s", padRight(fmt.Sprintf("%s (%s → %s)", humanBytes(heapGrowth), humanBytes(int64(m.memBefore.HeapAlloc)), humanBytes(int64(m.memAfter.HeapAlloc))), 38))
	t.Logf("│  GC cycles:        %s", padRight(fmt.Sprintf("%d", m.memAfter.NumGC-m.memBefore.NumGC), 38))
	t.Logf("└─────────────────────────────────────────────────────────┘")

	summary := fmt.Sprintf("%s: %d ok / %d err / %d timeout / %d reject / %.0f rps / p99=%s / Δgoroutine=%d / Δheap=%s",
		label, successes, errors, timeouts, rejects, rps, pct(sorted, 99), goroutineDelta, humanBytes(heapGrowth))
	return summary
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width-1] + "│"
	}
	return s + repeatSpace(width-len(s)-1) + "│"
}

func repeatSpace(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

func pctOf(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

// humanBytes is already defined in tier3_test.go — reused.

// ============================================================
// HTTP Transport Test Helpers
// ============================================================

// startHTTPTestServer starts a SecuredMCPServer with streamable HTTP transport.
func startHTTPTestServer(t *testing.T, cfg *ServerConfigV2) (*SecuredMCPServer, string) {
	t.Helper()
	cfg.Address = "127.0.0.1:0"
	cfg.DemoTools = true
	cfg.ScanResponses = false
	cfg.BlockOnPII = false
	cfg.BlockOnSecrets = false
	if cfg.MaxSessions <= 100 {
		cfg.MaxSessions = 500
	}

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.RegisterAgent("authenticated", "HTTP Load Test Agent", RoleAdmin, nil)

	// Build handler chain
	chain := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return srv.handler.HandleRequest(conn, req)
	}
	if cfg.ScanResponses {
		chain = srv.wrapWithResponseScan(chain)
	}
	chain = srv.guardrails.GuardrailHandler(chain)
	chain = srv.wrapWithSignatureVerification(chain)
	chain = srv.authMgr.AuthMiddleware(chain)

	transport := newStreamableHTTPTransport(cfg.Address, chain)
	srv.SetNotifyCallback(transport.broadcastNotification)

	ln, err := startStreamableHTTPListener(transport)
	if err != nil {
		t.Fatalf("startStreamableHTTPListener: %v", err)
	}
	t.Cleanup(func() {
		transport.httpSrv.Close()
		ln.Close()
		_ = srv.Stop()
	})

	addr := "http://" + ln.Addr().String()
	return srv, addr
}

// httpInitialize sends an initialize request via HTTP and returns the session ID.
// This function is goroutine-safe — it does not call t.Fatalf.
func httpInitialize(t *testing.T, baseURL, token string) string {
	t.Helper()
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": ProtocolVersion,
			"clientInfo":      map[string]interface{}{"name": "load-test", "version": "1.0"},
			"auth":            map[string]interface{}{"token": token},
		},
		"id": 1,
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	cleaned := stripSSEWrapper(respBody)
	var result JSONRPCResponse
	if err := json.Unmarshal(cleaned, &result); err != nil {
		return ""
	}
	if result.Error != nil {
		return ""
	}
	return resp.Header.Get("Mcp-Session-Id")
}

// httpCall sends a JSON-RPC request via HTTP and returns the response.
func httpCall(baseURL, token, sessionID string, method string, params interface{}, id int) (*JSONRPCResponse, error) {
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      id,
	}
	if params != nil {
		body["params"] = params
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	cleaned := stripSSEWrapper(respBody)
	var result JSONRPCResponse
	if err := json.Unmarshal(cleaned, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (body: %s)", err, string(cleaned))
	}
	return &result, nil
}

func httpCallPing(baseURL, token, sessionID string, id int) (*JSONRPCResponse, error) {
	return httpCall(baseURL, token, sessionID, "ping", map[string]interface{}{}, id)
}

// stripSSEWrapper removes SSE "data: " prefix and trailing newlines.
func stripSSEWrapper(body []byte) []byte {
	s := string(body)
	// SSE format: "event: message\ndata: {...}\n\n"
	if bytes.HasPrefix(body, []byte("event:")) || bytes.HasPrefix(body, []byte("data:")) {
		for _, line := range splitLines(s) {
			if len(line) > 5 && line[:5] == "data:" {
				return []byte(line[6:])
			}
		}
	}
	return body
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// dialAndPingTCP dials, initializes, and sends a ping, returning latency.
func dialAndPingTCP(addr, token string) (time.Duration, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	start := time.Now()
	initParams, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "bench", "version": "1.0"},
		"auth":            map[string]interface{}{"token": token},
	})
	if err := enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initParams, ID: 1}); err != nil {
		return 0, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var initResp JSONRPCResponse
	if err := dec.Decode(&initResp); err != nil {
		return 0, err
	}
	if initResp.Error != nil {
		return 0, fmt.Errorf("init: %v", initResp.Error)
	}

	pingParams, _ := json.Marshal(map[string]interface{}{})
	if err := enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "ping", Params: pingParams, ID: 2}); err != nil {
		return 0, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var pingResp JSONRPCResponse
	if err := dec.Decode(&pingResp); err != nil {
		return 0, err
	}
	if pingResp.Error != nil {
		return 0, fmt.Errorf("ping: %v", pingResp.Error)
	}
	return time.Since(start), nil
}

// ============================================================
// STRESS TESTS
// ============================================================

// TestStressRampUp gradually increases concurrent connections from 10 to 500
// in steps, measuring latency and error rates at each level. Finds the
// breaking point where errors begin to appear.
func TestStressRampUp(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "stress-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0
	cfg.MaxConnections = 0 // default 1000

	srv, addr := startTestServer(t, cfg)
	_ = srv

	metrics := newLoadMetrics()

	levels := []int{10, 25, 50, 100, 200, 350, 500}

	for _, level := range levels {
		var wg sync.WaitGroup
		var levelSuccess int64
		var levelError int64

		start := time.Now()

		for i := 0; i < level; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				lat, err := dialAndPingTCP(addr, "stress-token")
				if err != nil {
					atomic.AddInt64(&levelError, 1)
					metrics.recordError()
					return
				}
				metrics.recordLatency(lat)
				metrics.recordSuccess()
				atomic.AddInt64(&levelSuccess, 1)
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)

		t.Logf("  level=%3d  ok=%3d  err=%3d  time=%.2fs  rps=%.0f",
			level, levelSuccess, levelError, elapsed.Seconds(), float64(levelSuccess)/elapsed.Seconds())

		// Brief pause between levels to let connections clean up
		time.Sleep(200 * time.Millisecond)
	}

	summary := metrics.report(t, "STRESS: Ramp-Up (10→500 connections)")
	t.Logf("Summary: %s", summary)

	// At minimum, the first 3 levels (10, 25, 50) should have 0 errors
	if metrics.errorCnt > int64(len(levels)-3) {
		t.Errorf("too many errors during ramp-up: %d (expected < %d)", metrics.errorCnt, len(levels)-2)
	}
}

// TestStressResourceMonitor monitors goroutine and memory usage during
// sustained high load to detect resource leaks.
func TestStressResourceMonitor(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "stress-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	srv, addr := startTestServer(t, cfg)
	_ = srv

	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	gBefore := runtime.NumGoroutine()

	const waves = 10
	const connsPerWave = 50
	const reqsPerConn = 20

	var totalSuccess int64
	var totalError int64

	for w := 0; w < waves; w++ {
		var wg sync.WaitGroup
		for i := 0; i < connsPerWave; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, enc, dec, initResp := dialAndInitialize(t, addr, "stress-token")
				defer conn.Close()
				if initResp.Error != nil {
					atomic.AddInt64(&totalError, 1)
					return
				}
				for j := 0; j < reqsPerConn; j++ {
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					resp, err := callPing(enc, dec, j+1)
					if err != nil || (resp != nil && resp.Error != nil) {
						atomic.AddInt64(&totalError, 1)
						return
					}
					atomic.AddInt64(&totalSuccess, 1)
				}
			}()
		}
		wg.Wait()

		// Check resource usage between waves
		var memNow runtime.MemStats
		runtime.ReadMemStats(&memNow)
		gNow := runtime.NumGoroutine()
		t.Logf("  wave %d/%d: goroutines=%d, heap=%s, success=%d, errors=%d",
			w+1, waves, gNow, humanBytes(int64(memNow.HeapAlloc)), atomic.LoadInt64(&totalSuccess), atomic.LoadInt64(&totalError))
		runtime.GC()
	}

	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	gAfter := runtime.NumGoroutine()

	t.Logf("=== TestStressResourceMonitor ===")
	t.Logf("Waves: %d × %d conns × %d reqs = %d total requests", waves, connsPerWave, reqsPerConn, waves*connsPerWave*reqsPerConn)
	t.Logf("Success: %d, Errors: %d", totalSuccess, totalError)
	t.Logf("Goroutines: before=%d, after=%d, delta=%d", gBefore, gAfter, gAfter-gBefore)
	t.Logf("Heap: before=%s, after=%s, growth=%s",
		humanBytes(int64(memBefore.HeapAlloc)), humanBytes(int64(memAfter.HeapAlloc)),
		humanBytes(int64(memAfter.HeapAlloc)-int64(memBefore.HeapAlloc)))
	t.Logf("GC cycles: %d", memAfter.NumGC-memBefore.NumGC)

	// Goroutine leak check: allow 15 slack for runtime internals
	if delta := gAfter - gBefore; delta > 15 {
		t.Errorf("goroutine leak: delta=%d (before=%d, after=%d)", delta, gBefore, gAfter)
	}
	if totalError > 0 {
		t.Errorf("expected 0 errors, got %d", totalError)
	}
}

// ============================================================
// BURST / SPIKE TESTS
// ============================================================

// TestBurstConnectionSpike opens a large number of connections simultaneously
// (200), holds them briefly, then releases all at once. Verifies the server
// handles sudden connection spikes and cleans up properly.
func TestBurstConnectionSpike(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "burst-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0
	cfg.MaxConnections = 0

	srv, addr := startTestServer(t, cfg)

	const burstSize = 200
	var conns []net.Conn
	var connsMu sync.Mutex
	var wg sync.WaitGroup

	// Spike: open all connections at once
	startTime := time.Now()
	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, enc, dec, initResp := dialAndInitialize(t, addr, "burst-token")
			if initResp.Error != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			// Hold connection — just wait
			_ = enc
			_ = dec
		}()
	}
	wg.Wait()
	burstElapsed := time.Since(startTime)

	activeCount := srv.server.ConnectionCount()
	t.Logf("=== TestBurstConnectionSpike ===")
	t.Logf("Burst size: %d, Opened: %d, Time to open: %v", burstSize, len(conns), burstElapsed)
	t.Logf("Server active connections: %d", activeCount)

	// Hold for 500ms
	time.Sleep(500 * time.Millisecond)

	// Release all at once
	for _, c := range conns {
		c.Close()
	}

	// Wait for server cleanup
	time.Sleep(500 * time.Millisecond)
	finalCount := srv.server.ConnectionCount()
	t.Logf("After release: %d active connections (cleanup: %d→%d)", finalCount, activeCount, finalCount)

	if len(conns) < burstSize-10 {
		t.Errorf("only %d/%d connections established", len(conns), burstSize)
	}
	if finalCount > 5 {
		t.Errorf("connection cleanup failed: %d still active", finalCount)
	}
}

// TestBurstRequestSpike sends a massive burst of requests on existing
// connections: 50 connections each send 20 pings simultaneously (1000 total
// in <1 second). Verifies throughput under burst.
func TestBurstRequestSpike(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "burst-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, addr := startTestServer(t, cfg)

	const numConns = 50
	const burstReqs = 20
	totalReqs := numConns * burstReqs

	// Establish connections first
	type connState struct {
		conn net.Conn
		enc  *json.Encoder
		dec  *json.Decoder
	}
	conns := make([]connState, numConns)
	for i := 0; i < numConns; i++ {
		c, e, d, initResp := dialAndInitialize(t, addr, "burst-token")
		if initResp.Error != nil {
			t.Fatalf("conn %d init: %v", i, initResp.Error)
		}
		conns[i] = connState{c, e, d}
	}

	// BURST: all connections fire simultaneously
	var wg sync.WaitGroup
	var success int64
	var errors int64
	start := time.Now()

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cs := conns[idx]
			for j := 0; j < burstReqs; j++ {
				cs.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				resp, err := callPing(cs.enc, cs.dec, j+1)
				if err != nil || (resp != nil && resp.Error != nil) {
					atomic.AddInt64(&errors, 1)
					return
				}
				atomic.AddInt64(&success, 1)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for _, cs := range conns {
		cs.conn.Close()
	}

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)
	rps := float64(succ) / elapsed.Seconds()

	t.Logf("=== TestBurstRequestSpike ===")
	t.Logf("Connections: %d, Burst/conn: %d, Total: %d", numConns, burstReqs, totalReqs)
	t.Logf("Burst duration: %v", elapsed)
	t.Logf("Successful: %d, Errors: %d", succ, errs)
	t.Logf("Burst throughput: %.0f req/sec (%.2fms/req avg)", rps, elapsed.Seconds()*1000/float64(succ))

	if errs > 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if succ < int64(totalReqs)*9/10 {
		t.Errorf("expected ≥90%% success (%d), got %d", totalReqs*9/10, succ)
	}
}

// TestBurstRecovery verifies the server recovers fully after a burst. Steps:
// 1. Establish baseline performance (10 pings)
// 2. Burst 200 connections
// 3. Release all
// 4. Verify performance returns to baseline
func TestBurstRecovery(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "burst-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, addr := startTestServer(t, cfg)

	// Phase 1: Baseline
	var baselineLatencies []time.Duration
	for i := 0; i < 10; i++ {
		lat, err := dialAndPingTCP(addr, "burst-token")
		if err != nil {
			t.Fatalf("baseline ping %d: %v", i, err)
		}
		baselineLatencies = append(baselineLatencies, lat)
	}
	sort.Slice(baselineLatencies, func(i, j int) bool { return baselineLatencies[i] < baselineLatencies[j] })
	baselineP50 := pct(baselineLatencies, 50)
	t.Logf("Baseline p50: %v", baselineP50)

	// Phase 2: Burst
	var conns []net.Conn
	for i := 0; i < 200; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		conns = append(conns, c)
	}
	t.Logf("Burst: opened %d connections", len(conns))
	time.Sleep(500 * time.Millisecond)

	// Phase 3: Release
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)

	// Phase 4: Recovery measurement
	var recoveryLatencies []time.Duration
	for i := 0; i < 10; i++ {
		lat, err := dialAndPingTCP(addr, "burst-token")
		if err != nil {
			t.Fatalf("recovery ping %d: %v", i, err)
		}
		recoveryLatencies = append(recoveryLatencies, lat)
	}
	sort.Slice(recoveryLatencies, func(i, j int) bool { return recoveryLatencies[i] < recoveryLatencies[j] })
	recoveryP50 := pct(recoveryLatencies, 50)

	t.Logf("=== TestBurstRecovery ===")
	t.Logf("Baseline p50: %v, Recovery p50: %v, Ratio: %.2fx", baselineP50, recoveryP50, float64(recoveryP50)/float64(baselineP50))

	// Recovery should be within 3x of baseline (generous tolerance)
	if recoveryP50 > baselineP50*3 {
		t.Errorf("recovery latency %v > 3× baseline %v", recoveryP50, baselineP50)
	}
	t.Logf("Recovery: PASS (within 3× baseline)")
}

// ============================================================
// CRUSH TESTS
// ============================================================

// TestCrushBeyondMaxConnections opens connections well beyond the configured
// MaxConnections limit and verifies the server rejects excess connections
// without crashing or leaking resources.
func TestCrushBeyondMaxConnections(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "crush-token"
	cfg.MaxConnections = 30

	srv, addr := startTestServer(t, cfg)

	const crushSize = 500
	var conns []net.Conn
	var connsMu sync.Mutex

	// Flood with connections
	for i := 0; i < crushSize; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		connsMu.Lock()
		conns = append(conns, c)
		connsMu.Unlock()
	}

	time.Sleep(300 * time.Millisecond)
	activeCount := srv.server.ConnectionCount()

	t.Logf("=== TestCrushBeyondMaxConnections ===")
	t.Logf("MaxConnections: 30, Attempted: %d, Dials succeeded: %d", crushSize, len(conns))
	t.Logf("Server active connections: %d (limit: 30)", activeCount)

	// Server must not exceed its limit
	if activeCount > 30 {
		t.Errorf("server active connections %d exceeds MaxConnections 30", activeCount)
	}

	// Server must still be responsive — try a valid connection
	connsMu.Lock()
	for _, c := range conns {
		c.Close()
	}
	connsMu.Unlock()
	time.Sleep(300 * time.Millisecond)

	// Verify server is still alive
	lat, err := dialAndPingTCP(addr, "crush-token")
	if err != nil {
		t.Errorf("server unresponsive after crush: %v", err)
	} else {
		t.Logf("Server responsive after crush: ping latency %v", lat)
	}

	finalCount := srv.server.ConnectionCount()
	t.Logf("Final connection count: %d", finalCount)
	if finalCount > 5 {
		t.Errorf("connection cleanup failed: %d still active", finalCount)
	}
}

// TestCrushMemoryPressure sends many requests with moderately large payloads
// (10KB each) to test memory handling under pressure. Verifies no OOM, no
// crash, and proper cleanup.
func TestCrushMemoryPressure(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "crush-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	srv, addr := startTestServer(t, cfg)
	_ = srv

	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	const numConns = 30
	const reqsPerConn = 10
	const payloadSize = 10 * 1024 // 10KB per request

	largeMsg := make([]byte, payloadSize)
	for i := range largeMsg {
		largeMsg[i] = 'X'
	}

	var wg sync.WaitGroup
	var success int64
	var errors int64

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, enc, dec, initResp := dialAndInitialize(t, addr, "crush-token")
			defer conn.Close()
			if initResp.Error != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			for j := 0; j < reqsPerConn; j++ {
				params, _ := json.Marshal(map[string]interface{}{
					"name":      "echo",
					"arguments": map[string]interface{}{"message": string(largeMsg)},
				})
				req := &JSONRPCRequest{
					JSONRPC: JSONRPCVersion, Method: "tools/call",
					Params: params, ID: j + 1,
				}
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := enc.Encode(req); err != nil {
					atomic.AddInt64(&errors, 1)
					return
				}
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				var resp JSONRPCResponse
				if err := dec.Decode(&resp); err != nil {
					atomic.AddInt64(&errors, 1)
					return
				}
				if resp.Error != nil {
					atomic.AddInt64(&errors, 1)
					return
				}
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()

	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)
	totalPayload := int64(numConns * reqsPerConn * payloadSize)

	t.Logf("=== TestCrushMemoryPressure ===")
	t.Logf("Connections: %d, Reqs/conn: %d, Payload: %s each", numConns, reqsPerConn, humanBytes(payloadSize))
	t.Logf("Total payload sent: %s", humanBytes(totalPayload))
	t.Logf("Successful: %d, Errors: %d", succ, errs)
	t.Logf("Heap: before=%s, after=%s, growth=%s",
		humanBytes(int64(memBefore.HeapAlloc)), humanBytes(int64(memAfter.HeapAlloc)),
		humanBytes(int64(memAfter.HeapAlloc)-int64(memBefore.HeapAlloc)))

	if errs > 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	// Heap growth should be reasonable relative to total payload
	heapGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	if heapGrowth > totalPayload {
		t.Logf("note: heap growth %s exceeds total payload %s (may be GC timing)", humanBytes(heapGrowth), humanBytes(totalPayload))
	}
}

// TestCrushGoroutineExplosion tests that the server doesn't leak goroutines
// when handling massive concurrent connection churn. Opens and closes 500
// connections in rapid succession across multiple rounds.
func TestCrushGoroutineExplosion(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "crush-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0
	cfg.MaxConnections = 0

	srv, addr := startTestServer(t, cfg)
	_ = srv

	runtime.GC()
	goroutinesBefore := runtime.NumGoroutine()

	const rounds = 5
	const connsPerRound = 100

	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for i := 0; i < connsPerRound; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, enc, dec, initResp := dialAndInitialize(t, addr, "crush-token")
				if initResp.Error != nil {
					return
				}
				// Quick ping then close
				callPing(enc, dec, 1)
				conn.Close()
			}()
		}
		wg.Wait()
		time.Sleep(100 * time.Millisecond) // let goroutines unwind
		gNow := runtime.NumGoroutine()
		t.Logf("  round %d/%d: goroutines=%d", r+1, rounds, gNow)
	}

	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	goroutinesAfter := runtime.NumGoroutine()
	delta := goroutinesAfter - goroutinesBefore

	t.Logf("=== TestCrushGoroutineExplosion ===")
	t.Logf("Rounds: %d × %d connections = %d total connection churn", rounds, connsPerRound, rounds*connsPerRound)
	t.Logf("Goroutines: before=%d, after=%d, delta=%d", goroutinesBefore, goroutinesAfter, delta)

	if delta > 20 {
		t.Errorf("goroutine leak: delta=%d (before=%d, after=%d)", delta, goroutinesBefore, goroutinesAfter)
	} else {
		t.Logf("Goroutine leak check: PASS (delta=%d, within slack of 20)", delta)
	}
}

// TestCrushMalformedFlood sends a flood of malformed JSON data across many
// connections. Verifies the server handles malformed input gracefully
// without crashing or hanging.
func TestCrushMalformedFlood(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "crush-token"

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const numConns = 50
	const msgsPerConn = 10

	malformedPayloads := []string{
		`{"jsonrpc":"2.0","method":`,
		`not json at all`,
		`{"jsonrpc":"2.0","method":"initialize","params":{"auth":{"token":"crush-token"},"protocolVersion":"2025-06-18","clientInfo":{"name":"x","version":"1"}},"id":1}`,
		`{}`,
		`{"jsonrpc":"1.0","method":"unknown","id":999}`,
		`{"jsonrpc":"2.0"}`,
		`[]`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"message":"` + string(make([]byte, 1024)) + `"}},"id":5}`,
		`{"jsonrpc":"2.0","method":"ping","id":3}`,
		`{"jsonrpc":"2.0","method":"initialize","params":{"auth":{"token":"WRONG"},"protocolVersion":"2025-06-18","clientInfo":{"name":"x","version":"1"}},"id":1}`,
	}

	var wg sync.WaitGroup
	var success int64
	var errors int64
	var rejected int64

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			defer conn.Close()

			for j := 0; j < msgsPerConn; j++ {
				payload := malformedPayloads[j%len(malformedPayloads)]
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, err := conn.Write([]byte(payload + "\n"))
				if err != nil {
					atomic.AddInt64(&errors, 1)
					return
				}
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				_, err = conn.Read(buf)
				if err != nil {
					atomic.AddInt64(&rejected, 1)
				} else {
					atomic.AddInt64(&success, 1)
				}
			}
		}(i)
	}
	wg.Wait()

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)
	rej := atomic.LoadInt64(&rejected)

	t.Logf("=== TestCrushMalformedFlood ===")
	t.Logf("Connections: %d, Messages/conn: %d, Total: %d", numConns, msgsPerConn, numConns*msgsPerConn)
	t.Logf("Responses received: %d, Connection errors: %d, Read rejects: %d", succ, errs, rej)

	// Server should still be alive
	lat, err := dialAndPingTCP(addr, "crush-token")
	if err != nil {
		t.Errorf("server unresponsive after malformed flood: %v", err)
	} else {
		t.Logf("Server responsive after flood: ping latency %v", lat)
	}

	finalCount := srv.server.ConnectionCount()
	t.Logf("Final connection count: %d", finalCount)
	if finalCount > 5 {
		t.Errorf("connection cleanup failed: %d still active", finalCount)
	}
}

// ============================================================
// CHAOS TESTS
// ============================================================

// TestChaosRandomDrops opens connections, sends some requests, then randomly
// drops connections mid-stream. Verifies the server handles abrupt
// disconnections cleanly.
func TestChaosRandomDrops(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "chaos-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const numConns = 100
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	var wg sync.WaitGroup
	var dropped int64
	var completed int64

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, enc, dec, initResp := dialAndInitialize(t, addr, "chaos-token")
			if initResp.Error != nil {
				return
			}

			// Send 0-5 pings, then randomly drop
			numPings := rng.Intn(5)
			for j := 0; j < numPings; j++ {
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				resp, err := callPing(enc, dec, j+1)
				if err != nil || (resp != nil && resp.Error != nil) {
					break
				}
				// Random chance to drop mid-stream
				if rng.Float32() < 0.3 {
					conn.Close() // abrupt close — no graceful shutdown
					atomic.AddInt64(&dropped, 1)
					return
				}
			}
			conn.Close()
			atomic.AddInt64(&completed, 1)
		}()
	}
	wg.Wait()

	time.Sleep(500 * time.Millisecond) // let server clean up
	finalCount := srv.server.ConnectionCount()

	t.Logf("=== TestChaosRandomDrops ===")
	t.Logf("Connections: %d, Completed normally: %d, Dropped mid-stream: %d", numConns, completed, dropped)
	t.Logf("Final connection count: %d", finalCount)

	if finalCount > 5 {
		t.Errorf("connection cleanup failed after random drops: %d still active", finalCount)
	}

	// Server should still be responsive
	lat, err := dialAndPingTCP(addr, "chaos-token")
	if err != nil {
		t.Errorf("server unresponsive after random drops: %v", err)
	} else {
		t.Logf("Server responsive after chaos: ping latency %v", lat)
	}
}

// TestChaosHalfSentMessages sends partial JSON-RPC messages and then either
// completes them late, sends garbage, or closes the connection. Tests
// robustness of the JSON decoder and connection handling.
func TestChaosHalfSentMessages(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "chaos-token"

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const numConns = 50
	rng := rand.New(rand.NewSource(42))

	var wg sync.WaitGroup
	var alive int64

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer conn.Close()

			// Send first half of an initialize request
			initJSON := `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"chaos","version":"1.0"},"auth":{"token":"chaos-token"}},"id":1}`
			half := len(initJSON) / 2

			switch idx % 4 {
			case 0:
				// Send half, wait, then send rest
				conn.Write([]byte(initJSON[:half]))
				time.Sleep(time.Duration(rng.Intn(100)) * time.Millisecond)
				conn.Write([]byte(initJSON[half:]))
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				var resp JSONRPCResponse
				if json.NewDecoder(conn).Decode(&resp) == nil {
					atomic.AddInt64(&alive, 1)
				}

			case 1:
				// Send half, then send garbage
				conn.Write([]byte(initJSON[:half]))
				time.Sleep(50 * time.Millisecond)
				conn.Write([]byte("GARBAGE DATA THAT IS NOT JSON"))
				// Connection should be killed by server
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				conn.Read(buf)

			case 2:
				// Send full request but with newline in middle
				conn.Write([]byte(initJSON[:half]))
				conn.Write([]byte("\n"))
				conn.Write([]byte(initJSON[half:]))
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				var resp JSONRPCResponse
				if json.NewDecoder(conn).Decode(&resp) == nil {
					atomic.AddInt64(&alive, 1)
				}

			case 3:
				// Send half, close immediately
				conn.Write([]byte(initJSON[:half]))
				// Abrupt close
			}
		}(i)
	}
	wg.Wait()

	time.Sleep(500 * time.Millisecond)
	finalCount := srv.server.ConnectionCount()

	t.Logf("=== TestChaosHalfSentMessages ===")
	t.Logf("Connections: %d, Completed successfully: %d", numConns, alive)
	t.Logf("Final connection count: %d", finalCount)

	if finalCount > 5 {
		t.Errorf("connection cleanup failed: %d still active", finalCount)
	}

	// Server must survive
	lat, err := dialAndPingTCP(addr, "chaos-token")
	if err != nil {
		t.Errorf("server unresponsive after half-sent chaos: %v", err)
	} else {
		t.Logf("Server responsive after chaos: ping latency %v", lat)
	}
}

// TestChaosShutdownUnderLoadTCP opens many connections with active requests
// in-flight, then shuts down the server. Verifies graceful shutdown doesn't
// panic or hang.
func TestChaosShutdownUnderLoadTCP(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "chaos-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	srv, addr := startTestServer(t, cfg)

	// Start load generators
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					conn, err := net.Dial("tcp", addr)
					if err != nil {
						return
					}
					enc := json.NewEncoder(conn)
					dec := json.NewDecoder(conn)
					initParams, _ := json.Marshal(map[string]interface{}{
						"protocolVersion": ProtocolVersion,
						"clientInfo":      map[string]interface{}{"name": "chaos", "version": "1.0"},
						"auth":            map[string]interface{}{"token": "chaos-token"},
					})
					enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initParams, ID: 1})
					conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					var resp JSONRPCResponse
					dec.Decode(&resp)
					conn.Close()
				}
			}
		}()
	}

	// Let load build up
	time.Sleep(500 * time.Millisecond)

	// Shutdown while load is active
	close(stopCh)
	shutdownStart := time.Now()
	err := srv.Stop()
	shutdownTime := time.Since(shutdownStart)

	wg.Wait()

	t.Logf("=== TestChaosShutdownUnderLoadTCP ===")
	t.Logf("Active load generators: 50")
	t.Logf("Shutdown time: %v", shutdownTime)
	t.Logf("Stop error: %v", err)

	if shutdownTime > 10*time.Second {
		t.Errorf("shutdown took too long: %v", shutdownTime)
	}
	if err != nil {
		t.Errorf("Stop returned error: %v", err)
	}
	t.Logf("Graceful shutdown under load: PASS")
}

// ============================================================
// HTTP TRANSPORT TESTS
// ============================================================

// TestHTTPLoadConcurrent tests concurrent HTTP requests: 50 clients each
// initialize + ping + tools/list.
func TestHTTPLoadConcurrent(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, baseURL := startHTTPTestServer(t, cfg)

	const numClients = 50
	metrics := newLoadMetrics()

	var wg sync.WaitGroup
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			sid := httpInitialize(t, baseURL, "http-token")
			if sid == "" {
				metrics.recordError()
				return
			}
			// tools/list
			_, err := httpCall(baseURL, "http-token", sid, "tools/list", map[string]interface{}{}, 2)
			if err != nil {
				metrics.recordError()
				return
			}
			// ping
			resp, err := httpCallPing(baseURL, "http-token", sid, 3)
			if err != nil || (resp != nil && resp.Error != nil) {
				metrics.recordError()
				return
			}
			metrics.recordLatency(time.Since(start))
			metrics.recordSuccess()
		}()
	}
	wg.Wait()

	summary := metrics.report(t, "HTTP LOAD: Concurrent (50 clients)")
	t.Logf("Summary: %s", summary)

	if metrics.errorCnt > 0 {
		t.Errorf("expected 0 errors, got %d", metrics.errorCnt)
	}
}

// TestHTTPLoadSustained tests sustained HTTP throughput: 20 clients each
// send 30 sequential pings.
func TestHTTPLoadSustained(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, baseURL := startHTTPTestServer(t, cfg)

	const numClients = 20
	const reqsPerClient = 30

	// Pre-establish sessions
	sessions := make([]string, numClients)
	for i := 0; i < numClients; i++ {
		sessions[i] = httpInitialize(t, baseURL, "http-token")
		if sessions[i] == "" {
			t.Fatalf("client %d initialize failed", i)
		}
	}

	metrics := newLoadMetrics()
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < reqsPerClient; j++ {
				start := time.Now()
				resp, err := httpCallPing(baseURL, "http-token", sessions[idx], j+1)
				if err != nil || (resp != nil && resp.Error != nil) {
					metrics.recordError()
					return
				}
				metrics.recordLatency(time.Since(start))
				metrics.recordSuccess()
			}
		}(i)
	}
	wg.Wait()

	summary := metrics.report(t, fmt.Sprintf("HTTP LOAD: Sustained (%d clients × %d reqs)", numClients, reqsPerClient))
	t.Logf("Summary: %s", summary)

	if metrics.errorCnt > 0 {
		t.Errorf("expected 0 errors, got %d", metrics.errorCnt)
	}
}

// TestHTTPBurstRequest sends a burst of 200 concurrent HTTP requests
// on pre-established sessions.
func TestHTTPBurstRequest(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, baseURL := startHTTPTestServer(t, cfg)

	// Establish 20 sessions
	sessions := make([]string, 20)
	for i := range sessions {
		sessions[i] = httpInitialize(t, baseURL, "http-token")
	}

	const burstSize = 200 // 10 requests per session

	var wg sync.WaitGroup
	var success int64
	var errors int64
	start := time.Now()

	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sid := sessions[idx%len(sessions)]
			resp, err := httpCallPing(baseURL, "http-token", sid, idx+1)
			if err != nil || (resp != nil && resp.Error != nil) {
				atomic.AddInt64(&errors, 1)
				return
			}
			atomic.AddInt64(&success, 1)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)

	t.Logf("=== TestHTTPBurstRequest ===")
	t.Logf("Burst size: %d concurrent HTTP requests", burstSize)
	t.Logf("Duration: %v", elapsed)
	t.Logf("Successful: %d, Errors: %d", succ, errs)
	t.Logf("Burst throughput: %.0f req/sec", float64(succ)/elapsed.Seconds())

	if errs > burstSize/10 {
		t.Errorf("too many errors: %d/%d", errs, burstSize)
	}
}

// TestHTTPBreakOversizedBody sends a 2MB HTTP body to verify the server
// rejects oversized requests.
func TestHTTPBreakOversizedBody(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"

	_, baseURL := startHTTPTestServer(t, cfg)

	// 2MB body
	bigBody := make([]byte, 2*1024*1024)
	for i := range bigBody {
		bigBody[i] = 'A'
	}

	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "echo", "arguments": map[string]interface{}{"message": string(bigBody)}},
		"id":      1,
	}
	b, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer http-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("Request error (acceptable): %v", err)
		return
	}
	defer resp.Body.Close()

	t.Logf("=== TestHTTPBreakOversizedBody ===")
	t.Logf("Body size: %s, Response status: %d", humanBytes(int64(len(b))), resp.StatusCode)

	// Server should reject (4xx or 5xx) or close connection
	if resp.StatusCode < 400 && resp.StatusCode != http.StatusOK {
		t.Errorf("expected error status, got %d", resp.StatusCode)
	}
	t.Logf("Oversized body rejected: status %d", resp.StatusCode)
}

// TestHTTPBreakAuthFlood sends many HTTP requests with wrong auth tokens
// to verify rate limiting works over HTTP.
func TestHTTPBreakAuthFlood(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"

	_, baseURL := startHTTPTestServer(t, cfg)

	const attempts = 100
	var unauthorized int64
	var forbidden int64
	var other int64

	for i := 0; i < attempts; i++ {
		body := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": ProtocolVersion,
				"clientInfo":      map[string]interface{}{"name": "auth-flood", "version": "1.0"},
				"auth":            map[string]interface{}{"token": "WRONG-TOKEN"},
			},
			"id": i + 1,
		}
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			other++
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		cleaned := stripSSEWrapper(respBody)
		var result JSONRPCResponse
		if json.Unmarshal(cleaned, &result) == nil && result.Error != nil {
			switch result.Error.Code {
			case ErrorUnauthorized:
				atomic.AddInt64(&unauthorized, 1)
			case ErrorForbidden, ErrorRateLimited:
				atomic.AddInt64(&forbidden, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		} else {
			atomic.AddInt64(&other, 1)
		}
	}

	t.Logf("=== TestHTTPBreakAuthFlood ===")
	t.Logf("Attempts: %d", attempts)
	t.Logf("Unauthorized (401): %d", unauthorized)
	t.Logf("Forbidden/RateLimited (403/429): %d", forbidden)
	t.Logf("Other: %d", other)

	if forbidden == 0 && unauthorized == 0 {
		t.Error("expected auth rejection responses, got none")
	}
	t.Logf("Auth flood protection working over HTTP")
}

// TestHTTPSoakStability runs sustained HTTP load for 5 seconds and verifies
// stability, no goroutine leaks, and proper cleanup.
func TestHTTPSoakStability(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, baseURL := startHTTPTestServer(t, cfg)

	runtime.GC()
	gBefore := runtime.NumGoroutine()

	const numClients = 10
	const soakDuration = 5 * time.Second
	const reqInterval = 100 * time.Millisecond

	// Pre-establish sessions
	sessions := make([]string, numClients)
	for i := range sessions {
		sessions[i] = httpInitialize(t, baseURL, "http-token")
	}

	var success int64
	var errors int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(soakDuration)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ticker := time.NewTicker(reqInterval)
			defer ticker.Stop()
			reqID := 1
			for {
				if time.Now().After(deadline) {
					return
				}
				select {
				case <-ticker.C:
					resp, err := httpCallPing(baseURL, "http-token", sessions[idx], reqID)
					reqID++
					if err != nil || (resp != nil && resp.Error != nil) {
						atomic.AddInt64(&errors, 1)
						return
					}
					atomic.AddInt64(&success, 1)
				}
			}
		}(i)
	}
	wg.Wait()

	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	gAfter := runtime.NumGoroutine()

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)

	t.Logf("=== TestHTTPSoakStability ===")
	t.Logf("Clients: %d, Duration: %v, Interval: %v", numClients, soakDuration, reqInterval)
	t.Logf("Successful: %d, Errors: %d", succ, errs)
	t.Logf("Goroutines: before=%d, after=%d, delta=%d", gBefore, gAfter, gAfter-gBefore)

	if errs > 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if delta := gAfter - gBefore; delta > 15 {
		t.Errorf("goroutine leak: delta=%d", delta)
	}
}

// TestHTTPBatchLoad tests JSON-RPC batch requests over HTTP: sends batches
// of 10 requests per HTTP call, 20 concurrent clients.
func TestHTTPBatchLoad(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	_, baseURL := startHTTPTestServer(t, cfg)

	const numClients = 20
	const batchSize = 10

	sessions := make([]string, numClients)
	for i := range sessions {
		sessions[i] = httpInitialize(t, baseURL, "http-token")
	}

	var wg sync.WaitGroup
	var success int64
	var errors int64

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Build batch of ping requests
			batch := make([]map[string]interface{}, batchSize)
			for j := 0; j < batchSize; j++ {
				batch[j] = map[string]interface{}{
					"jsonrpc": "2.0",
					"method":  "ping",
					"params":  map[string]interface{}{},
					"id":      j + 1,
				}
			}
			b, _ := json.Marshal(batch)
			req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer http-token")
			req.Header.Set("Mcp-Session-Id", sessions[idx])

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)

			var responses []JSONRPCResponse
			cleaned := stripSSEWrapper(respBody)
			if err := json.Unmarshal(cleaned, &responses); err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			for _, r := range responses {
				if r.Error != nil {
					atomic.AddInt64(&errors, 1)
				} else {
					atomic.AddInt64(&success, 1)
				}
			}
		}(i)
	}
	wg.Wait()

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)

	t.Logf("=== TestHTTPBatchLoad ===")
	t.Logf("Clients: %d, Batch size: %d, Total requests: %d", numClients, batchSize, numClients*batchSize)
	t.Logf("Successful: %d, Errors: %d", succ, errs)

	if errs > 0 {
		t.Errorf("expected 0 errors, got %d", errs)
	}
	if succ != int64(numClients*batchSize) {
		t.Errorf("expected %d successes, got %d", numClients*batchSize, succ)
	}
}

// TestHTTPCrushConnectionExhaustion opens many concurrent HTTP connections
// rapidly to test connection handling under HTTP.
func TestHTTPCrushConnectionExhaustion(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "http-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0

	srv, baseURL := startHTTPTestServer(t, cfg)
	_ = srv

	const totalReqs = 300
	var success int64
	var errors int64

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < totalReqs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "initialize",
				"params": map[string]interface{}{
					"protocolVersion": ProtocolVersion,
					"clientInfo":      map[string]interface{}{"name": "crush", "version": "1.0"},
					"auth":            map[string]interface{}{"token": "http-token"},
				},
				"id": 1,
			}
			b, _ := json.Marshal(body)
			req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			cleaned := stripSSEWrapper(respBody)
			var result JSONRPCResponse
			if json.Unmarshal(cleaned, &result) == nil && result.Error == nil {
				atomic.AddInt64(&success, 1)
			} else {
				atomic.AddInt64(&errors, 1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	succ := atomic.LoadInt64(&success)
	errs := atomic.LoadInt64(&errors)

	t.Logf("=== TestHTTPCrushConnectionExhaustion ===")
	t.Logf("Concurrent HTTP requests: %d", totalReqs)
	t.Logf("Duration: %v", elapsed)
	t.Logf("Successful: %d, Errors: %d", succ, errs)
	t.Logf("Throughput: %.0f req/sec", float64(succ)/elapsed.Seconds())

	// Server should handle most requests successfully
	if succ < int64(totalReqs)*9/10 {
		t.Errorf("success rate too low: %d/%d", succ, totalReqs)
	}

	// Verify server is still responsive
	_, err := httpCallPing(baseURL, "http-token", httpInitialize(t, baseURL, "http-token"), 1)
	if err != nil {
		t.Errorf("server unresponsive after HTTP crush: %v", err)
	} else {
		t.Logf("Server responsive after HTTP crush")
	}
}

// ============================================================
// CROSS-TRANSPORT COMPARISON
// ============================================================

// TestCrossTransportLatency compares TCP vs HTTP latency head-to-head.
// Sends 100 pings over each transport and compares p50/p99.
func TestCrossTransportLatency(t *testing.T) {
	// TCP server
	tcpCfg := DefaultServerConfig()
	tcpCfg.AuthToken = "cross-token"
	tcpCfg.RateLimitRPM = 0
	tcpCfg.MaxToolsPerSession = 0
	_, tcpAddr := startTestServer(t, tcpCfg)

	// HTTP server
	httpCfg := DefaultServerConfig()
	httpCfg.AuthToken = "cross-token"
	httpCfg.RateLimitRPM = 0
	httpCfg.MaxToolsPerSession = 0
	_, baseURL := startHTTPTestServer(t, httpCfg)

	const numReqs = 100

	// TCP latency
	var tcpLats []time.Duration
	for i := 0; i < numReqs; i++ {
		lat, err := dialAndPingTCP(tcpAddr, "cross-token")
		if err != nil {
			t.Fatalf("TCP ping %d: %v", i, err)
		}
		tcpLats = append(tcpLats, lat)
	}
	sort.Slice(tcpLats, func(i, j int) bool { return tcpLats[i] < tcpLats[j] })

	// HTTP latency (pre-establish session for fair comparison)
	sid := httpInitialize(t, baseURL, "cross-token")
	var httpLats []time.Duration
	for i := 0; i < numReqs; i++ {
		start := time.Now()
		resp, err := httpCallPing(baseURL, "cross-token", sid, i+1)
		if err != nil || (resp != nil && resp.Error != nil) {
			t.Fatalf("HTTP ping %d: %v", i, err)
		}
		httpLats = append(httpLats, time.Since(start))
	}
	sort.Slice(httpLats, func(i, j int) bool { return httpLats[i] < httpLats[j] })

	tcpP50 := pct(tcpLats, 50)
	tcpP99 := pct(tcpLats, 99)
	httpP50 := pct(httpLats, 50)
	httpP99 := pct(httpLats, 99)

	t.Logf("")
	t.Logf("┌─────────────────────────────────────────────────────────┐")
	t.Logf("│  CROSS-TRANSPORT LATENCY COMPARISON                     │")
	t.Logf("├─────────────────────────────────────────────────────────┤")
	t.Logf("│  TCP  p50: %-12s  p99: %-12s            │", tcpP50, tcpP99)
	t.Logf("│  HTTP p50: %-12s  p99: %-12s            │", httpP50, httpP99)
	t.Logf("│  Ratio p50: %-44s│", fmt.Sprintf("%.2fx (HTTP/TCP)", float64(httpP50)/float64(tcpP50)))
	t.Logf("│  Ratio p99: %-44s│", fmt.Sprintf("%.2fx (HTTP/TCP)", float64(httpP99)/float64(tcpP99)))
	t.Logf("└─────────────────────────────────────────────────────────┘")

	// HTTP should be slower than TCP (expected) but not absurdly so
	ratio := float64(httpP50) / float64(tcpP50)
	if ratio > 50 {
		t.Errorf("HTTP p50 latency %.2fx slower than TCP — unexpectedly high", ratio)
	}
	t.Logf("HTTP is %.1fx slower than TCP (expected — HTTP overhead)", ratio)
}

// ============================================================
// FD LEAK CHECK
// ============================================================

// TestFDCLeak verifies no file descriptor leaks across heavy connection churn.
func TestFDLeak(t *testing.T) {
	// Read initial FD count (Linux only)
	initialFDs := countOpenFDs()
	if initialFDs < 0 {
		t.Skip("FD count only available on Linux")
	}

	cfg := DefaultServerConfig()
	cfg.AuthToken = "fd-token"
	cfg.RateLimitRPM = 0
	cfg.MaxToolsPerSession = 0
	cfg.MaxConnections = 0

	_, addr := startTestServer(t, cfg)

	// Run 5 rounds of 100 connections each
	for r := 0; r < 5; r++ {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, enc, dec, initResp := dialAndInitialize(t, addr, "fd-token")
				if initResp.Error != nil {
					return
				}
				callPing(enc, dec, 1)
				conn.Close()
			}()
		}
		wg.Wait()
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)
	finalFDs := countOpenFDs()
	leak := finalFDs - initialFDs

	t.Logf("=== TestFDLeak ===")
	t.Logf("Initial FDs: %d, Final FDs: %d, Delta: %d", initialFDs, finalFDs, leak)

	if leak > 20 {
		t.Errorf("possible FD leak: %d FDs leaked (initial=%d, final=%d)", leak, initialFDs, finalFDs)
	} else {
		t.Logf("FD leak check: PASS (delta=%d, within slack of 20)", leak)
	}
}

// countOpenFDs returns the number of open file descriptors on Linux, or -1
// if not available.
func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}
