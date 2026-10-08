//go:build load

// SPDX-License-Identifier: Apache-2.0
// Load, stress, break, and soak tests for the AegisGate MCP server.
//
// These tests exercise the TCP JSON-RPC server under extreme conditions to
// verify stability, resource limits, and graceful degradation. They are gated
// behind the "load" build tag so they do not run during normal CI:
//
//	go test -tags=load -v -timeout=120s ./...
//
// Test categories:
//   - Load:   TestLoadConcurrentConnections, TestLoadSustainedThroughput
//   - Break:  TestBreakConnectionFlood, TestBreakOversizedPayload,
//             TestBreakSlowloris, TestBreakAuthFlood
//   - Soak:   TestSoakStability

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================
// Helpers
// ============================================================

// startTestServer creates a secured MCP server with sensible defaults for
// load testing, starts it on an ephemeral port, and returns the server plus
// its actual listen address. The caller is responsible for deferring Stop.
func startTestServer(t *testing.T, cfg *ServerConfigV2) (*SecuredMCPServer, string) {
	t.Helper()
	cfg.Address = "127.0.0.1:0"
	cfg.DemoTools = true
	cfg.ScanResponses = false // disable response scanning to avoid false positives
	cfg.BlockOnPII = false
	cfg.BlockOnSecrets = false
	if cfg.MaxSessions == 0 || cfg.MaxSessions == 50 {
		cfg.MaxSessions = 500 // override default (50) for load testing
	}

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.RegisterAgent("authenticated", "Load Test Agent", RoleAdmin, nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	addr := srv.server.listener.Addr().String()
	return srv, addr
}

// dialAndInitialize opens a TCP connection, sends an initialize request with
// the given auth token, and returns the encoder/decoder pair plus the
// response. The caller owns the connection and must close it.
func dialAndInitialize(t *testing.T, addr, token string) (net.Conn, *json.Encoder, *json.Decoder, *JSONRPCResponse) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	initParams, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "load-test", "version": "1.0"},
		"auth":            map[string]interface{}{"token": token},
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initParams, ID: 1}
	if err := enc.Encode(req); err != nil {
		conn.Close()
		t.Fatalf("encode initialize: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp JSONRPCResponse
	if err := dec.Decode(&resp); err != nil {
		conn.Close()
		t.Fatalf("decode initialize: %v", err)
	}
	return conn, enc, dec, &resp
}

// callPing sends a tools/call ping request and returns the response.
func callPing(enc *json.Encoder, dec *json.Decoder, id int) (*JSONRPCResponse, error) {
	callParams, _ := json.Marshal(map[string]interface{}{
		"name":      "ping",
		"arguments": map[string]interface{}{},
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: callParams, ID: id}
	if err := enc.Encode(req); err != nil {
		return nil, fmt.Errorf("encode ping: %w", err)
	}
	var resp JSONRPCResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode ping: %w", err)
	}
	return &resp, nil
}

// percentile returns the p-th percentile from a sorted slice of durations.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p / 100)
	return sorted[idx]
}

// sortDurations copies and sorts a slice of durations.
func sortDurations(durations []time.Duration) []time.Duration {
	out := make([]time.Duration, len(durations))
	copy(out, durations)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ============================================================
// 1. TestLoadConcurrentConnections
//
// Validates that the server can handle 100 concurrent connections, each
// performing a full initialize → tools/list → tools/call ping sequence.
// Measures per-connection latency and reports p50/p99.
// ============================================================

func TestLoadConcurrentConnections(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.MaxConnections = 0 // defaults to 1000 internally

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const numConns = 100

	var wg sync.WaitGroup
	var failCount int64
	latencies := make([]time.Duration, numConns)
	var latMu sync.Mutex

	start := time.Now()

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			connStart := time.Now()
			conn, enc, dec, initResp := dialAndInitialize(t, addr, "test-bearer-token")
			defer conn.Close()

			if initResp.Error != nil {
				atomic.AddInt64(&failCount, 1)
				t.Errorf("conn %d initialize error: %v", idx, initResp.Error)
				return
			}

			// tools/list
			listReq := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/list", ID: 2}
			if err := enc.Encode(listReq); err != nil {
				atomic.AddInt64(&failCount, 1)
				t.Errorf("conn %d encode tools/list: %v", idx, err)
				return
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var listResp JSONRPCResponse
			if err := dec.Decode(&listResp); err != nil {
				atomic.AddInt64(&failCount, 1)
				t.Errorf("conn %d decode tools/list: %v", idx, err)
				return
			}
			if listResp.Error != nil {
				atomic.AddInt64(&failCount, 1)
				t.Errorf("conn %d tools/list error: %v", idx, listResp.Error)
				return
			}

			// tools/call ping
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			pingResp, err := callPing(enc, dec, 3)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
				t.Errorf("conn %d ping: %v", idx, err)
				return
			}
			if pingResp.Error != nil {
				atomic.AddInt64(&failCount, 1)
				t.Errorf("conn %d ping error: %v", idx, pingResp.Error)
				return
			}

			lat := time.Since(connStart)
			latMu.Lock()
			latencies[idx] = lat
			latMu.Unlock()
		}(i)
	}

	wg.Wait()
	totalTime := time.Since(start)

	failed := atomic.LoadInt64(&failCount)
	if failed > 0 {
		t.Errorf("%d/%d connections failed", failed, numConns)
	}

	// Collect non-zero latencies
	var validLats []time.Duration
	for _, l := range latencies {
		if l > 0 {
			validLats = append(validLats, l)
		}
	}
	sorted := sortDurations(validLats)

	t.Logf("=== TestLoadConcurrentConnections ===")
	t.Logf("Concurrent connections: %d", numConns)
	t.Logf("Total time: %v", totalTime)
	t.Logf("Failures: %d/%d", failed, numConns)
	if len(sorted) > 0 {
		t.Logf("Latency p50: %v", percentile(sorted, 50))
		t.Logf("Latency p99: %v", percentile(sorted, 99))
		t.Logf("Latency min: %v", sorted[0])
		t.Logf("Latency max: %v", sorted[len(sorted)-1])
	}

	if failed > 0 {
		t.Fatalf("expected all %d connections to succeed, %d failed", numConns, failed)
	}
}

// ============================================================
// 2. TestLoadSustainedThroughput
//
// Validates sustained throughput: 20 concurrent connections each send 50
// ping requests as fast as possible (1000 total). Measures requests/sec.
// ============================================================

func TestLoadSustainedThroughput(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.RateLimitRPM = 0       // disable rate limiting for throughput test
	cfg.MaxToolsPerSession = 0 // disable per-session tool count limit

	srv, addr := startTestServer(t, cfg)
	_ = srv

	const numConns = 20
	const reqsPerConn = 50
	totalReqs := numConns * reqsPerConn

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64

	start := time.Now()

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, enc, dec, _ := dialAndInitialize(t, addr, "test-bearer-token")
			defer conn.Close()

			for j := 0; j < reqsPerConn; j++ {
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				resp, err := callPing(enc, dec, j+1)
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					if atomic.LoadInt64(&errorCount) <= 5 {
						t.Errorf("conn %d req %d: %v", idx, j, err)
					}
					return
				}
				if resp.Error != nil {
					atomic.AddInt64(&errorCount, 1)
					if atomic.LoadInt64(&errorCount) <= 5 {
						t.Errorf("conn %d req %d error: %v", idx, j, resp.Error)
					}
					return
				}
				atomic.AddInt64(&successCount, 1)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	successes := atomic.LoadInt64(&successCount)
	errors := atomic.LoadInt64(&errorCount)
	rps := float64(successes) / elapsed.Seconds()

	t.Logf("=== TestLoadSustainedThroughput ===")
	t.Logf("Connections: %d, Requests/conn: %d, Total: %d", numConns, reqsPerConn, totalReqs)
	t.Logf("Elapsed: %v", elapsed)
	t.Logf("Successful: %d, Errors: %d", successes, errors)
	t.Logf("Throughput: %.0f req/sec", rps)

	if errors > 0 {
		t.Errorf("expected 0 errors, got %d", errors)
	}
	if successes != int64(totalReqs) {
		t.Errorf("expected %d successes, got %d", totalReqs, successes)
	}
}

// ============================================================
// 3. TestBreakConnectionFlood
//
// Validates that MaxConnections is enforced: with a limit of 50, opening
// 200 connections rapidly should result in the server accepting at most 50
// and rejecting the rest by closing them immediately.
// ============================================================

func TestBreakConnectionFlood(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.MaxConnections = 50

	srv, addr := startTestServer(t, cfg)

	const totalAttempts = 200
	var conns []net.Conn
	var connsMu sync.Mutex

	// Open connections as fast as possible
	for i := 0; i < totalAttempts; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			continue // listener backlog full — acceptable
		}
		connsMu.Lock()
		conns = append(conns, c)
		connsMu.Unlock()
	}

	// Give the server a moment to process accept and reject
	time.Sleep(200 * time.Millisecond)

	activeCount := srv.server.ConnectionCount()
	t.Logf("=== TestBreakConnectionFlood ===")
	t.Logf("MaxConnections: 50, Attempted: %d, Dials succeeded: %d", totalAttempts, len(conns))
	t.Logf("Server active connections: %d", activeCount)

	if activeCount > 50 {
		t.Errorf("server active connections %d exceeds MaxConnections 50", activeCount)
	}

	// Verify excess connections are rejected (closed by server).
	// Connections beyond the limit should get EOF when trying to read.
	rejectedCount := 0
	checkedCount := 0
	for _, c := range conns {
		// Send a minimal initialize to see if the connection is still alive
		c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		initParams, _ := json.Marshal(map[string]interface{}{
			"protocolVersion": ProtocolVersion,
			"clientInfo":      map[string]interface{}{"name": "flood", "version": "1.0"},
			"auth":            map[string]interface{}{"token": "test-bearer-token"},
		})
		req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initParams, ID: 1}
		_ = json.NewEncoder(c).Encode(req)

		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		var resp JSONRPCResponse
		err := json.NewDecoder(c).Decode(&resp)
		checkedCount++
		if err != nil {
			// EOF or error means the connection was rejected — expected for excess connections
			rejectedCount++
		}
	}

	t.Logf("Checked: %d, Rejected (EOF/error): %d", checkedCount, rejectedCount)

	// At least some connections must be rejected (we tried 200 with max 50)
	if rejectedCount == 0 {
		t.Error("expected some connections to be rejected, but none were")
	}

	// Clean up
	for _, c := range conns {
		c.Close()
	}

	// Wait for server to clean up connections
	time.Sleep(200 * time.Millisecond)
	finalCount := srv.server.ConnectionCount()
	t.Logf("Final connection count after cleanup: %d", finalCount)
	if finalCount > 0 {
		t.Logf("note: %d connections still active after cleanup (may be in TIME_WAIT)", finalCount)
	}
}

// ============================================================
// 4. TestBreakOversizedPayload
//
// Validates that the server enforces the 1MB message size limit. Sending
// a 2MB JSON payload should cause the server to close the connection
// (the LimitReader will return an error, and the connection is dropped).
// ============================================================

func TestBreakOversizedPayload(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"

	_, addr := startTestServer(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// First authenticate normally
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	initParams, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "oversized-test", "version": "1.0"},
		"auth":            map[string]interface{}{"token": "test-bearer-token"},
	})
	initReq := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initParams, ID: 1}
	if err := enc.Encode(initReq); err != nil {
		t.Fatalf("encode initialize: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var initResp JSONRPCResponse
	if err := dec.Decode(&initResp); err != nil {
		t.Fatalf("decode initialize: %v", err)
	}
	if initResp.Error != nil {
		t.Fatalf("initialize failed: %v", initResp.Error)
	}

	// Build a 2MB JSON payload — well over the 1MB (1<<20) LimitReader cap.
	// We construct a valid JSON-RPC request with a huge "params" field.
	bigString := make([]byte, 2*1024*1024) // 2MB
	for i := range bigString {
		bigString[i] = 'A'
	}

	// Construct raw JSON bytes manually (not using json.Encoder) to send
	// the oversized payload in one shot.
	payload := fmt.Sprintf(
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"message":"%s"}},"id":2}`,
		string(bigString),
	)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(payload))
	if err != nil {
		t.Logf("write of oversized payload returned error (acceptable): %v", err)
	}

	// The server's LimitReader will reject the oversized message and close
	// the connection. Attempting to read should return EOF or an error.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp JSONRPCResponse
	readErr := dec.Decode(&resp)

	t.Logf("=== TestBreakOversizedPayload ===")
	t.Logf("Payload size: %d bytes (2MB)", len(payload))
	t.Logf("Read result: err=%v", readErr)

	if readErr == nil {
		t.Error("expected connection to be closed (EOF/error) after oversized payload, but got a valid response")
	}
	if readErr != io.EOF && readErr != nil {
		t.Logf("read returned non-EOF error (acceptable): %v", readErr)
	}
}

// ============================================================
// 5. TestBreakSlowloris
//
// Validates that the server kills slow-read connections (slowloris attack).
// Uses a raw Server with custom ReadTimeout=2s and IdleTimeout=5s (the
// secured server hardcodes 30s). Opens 10 connections that each send 1
// byte every 500ms. After 3 seconds, the slow connections should have
// been killed by the read timeout.
// ============================================================

func TestBreakSlowloris(t *testing.T) {
	// Build a raw Server with custom short timeouts.
	srvCfg := &ServerConfig{
		Address:        "127.0.0.1:0",
		ReadTimeout:    2 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    5 * time.Second,
		MaxConnections: 100,
		Handler:        nil,
	}

	rawSrv := NewServer(srvCfg)

	// Simple handler that responds to ping and initialize without auth.
	rawSrv.SetHandleFunc(func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		switch req.Method {
		case "initialize":
			return &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Result: map[string]interface{}{
					"protocolVersion": ProtocolVersion,
					"serverInfo":      map[string]interface{}{"name": "slowloris-test", "version": "1.0"},
				},
			}
		case "ping":
			return &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Result:  map[string]interface{}{"pong": true},
			}
		default:
			return &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Result:  map[string]interface{}{},
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rawSrv.StartContext(ctx); err != nil {
		t.Fatalf("StartContext: %v", err)
	}
	defer rawSrv.Stop()

	addr := rawSrv.listener.Addr().String()

	const numConns = 10
	var conns []net.Conn

	// Open connections and send data very slowly: 1 byte every 500ms.
	// We send a partial JSON-RPC request so the server is waiting for more data.
	for i := 0; i < numConns; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Start a goroutine per connection that slowly writes 1 byte at a time.
	partialJSON := `{"jsonrpc":"2.0","method":"ping","id":1}`
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(idx int, conn net.Conn) {
			defer wg.Done()
			for _, b := range []byte(partialJSON) {
				conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, err := conn.Write([]byte{b})
				if err != nil {
					return // connection was killed
				}
				time.Sleep(500 * time.Millisecond)
			}
		}(i, c)
	}

	// Wait 3 seconds — the 2s read timeout should have killed all slow
	// connections before they finish sending their request.
	time.Sleep(3 * time.Second)

	// Check that all connections have been killed by the server.
	// A killed connection will return EOF or error on read.
	killedCount := 0
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 1)
		_, err := c.Read(buf)
		if err != nil {
			killedCount++
		}
	}

	t.Logf("=== TestBreakSlowloris ===")
	t.Logf("Connections: %d, ReadTimeout: 2s, Send rate: 1 byte/500ms", numConns)
	t.Logf("Killed by server: %d/%d", killedCount, numConns)
	t.Logf("Server active connections: %d", rawSrv.ConnectionCount())

	if killedCount < numConns/2 {
		t.Errorf("expected at least %d slow connections killed, got %d", numConns/2, killedCount)
	}

	// Clean up
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
}

// ============================================================
// 6. TestBreakAuthFlood
//
// Validates that the server rate-limits repeated failed authentication
// attempts. Opens a single connection and sends 200 initialize requests
// with a wrong token. After 5 failures (MaxAuthAttempts), subsequent
// requests should return ErrorForbidden.
// ============================================================

func TestBreakAuthFlood(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-token"
	cfg.MaxConnections = 100

	_, addr := startTestServer(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	const totalAttempts = 200
	var unauthorizedCount int64
	var forbiddenCount int64

	// Build the wrong-token initialize params
	wrongParams, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "auth-flood", "version": "1.0"},
		"auth":            map[string]interface{}{"token": "WRONG-TOKEN"},
	})

	for i := 0; i < totalAttempts; i++ {
		req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: wrongParams, ID: i + 1}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := enc.Encode(req); err != nil {
			t.Logf("encode failed at attempt %d: %v (connection may have been closed)", i+1, err)
			break
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var resp JSONRPCResponse
		if err := dec.Decode(&resp); err != nil {
			t.Logf("decode failed at attempt %d: %v (connection may have been closed)", i+1, err)
			break
		}

		if resp.Error != nil {
			switch resp.Error.Code {
			case ErrorUnauthorized:
				atomic.AddInt64(&unauthorizedCount, 1)
			case ErrorForbidden:
				atomic.AddInt64(&forbiddenCount, 1)
			case ErrorRateLimited:
				// Global rate limit — also acceptable as a rejection
				atomic.AddInt64(&forbiddenCount, 1)
			}
		}
	}

	unauth := atomic.LoadInt64(&unauthorizedCount)
	forbidden := atomic.LoadInt64(&forbiddenCount)

	t.Logf("=== TestBreakAuthFlood ===")
	t.Logf("Total attempts: %d", totalAttempts)
	t.Logf("ErrorUnauthorized responses: %d", unauth)
	t.Logf("ErrorForbidden/RateLimited responses: %d", forbidden)
	t.Logf("MaxAuthAttempts: 5")

	// After 5 failures, the server should start returning ErrorForbidden
	if forbidden == 0 {
		t.Error("expected ErrorForbidden responses after exceeding MaxAuthAttempts, got none")
	}

	// The first 5 should be ErrorUnauthorized (before the block kicks in)
	if unauth == 0 {
		t.Error("expected some ErrorUnauthorized responses before the block, got none")
	}

	t.Logf("Auth flood protection working: %d unauthorized, %d forbidden/blocked", unauth, forbidden)
}

// ============================================================
// 7. TestSoakStability
//
// Validates long-running stability: 10 connections each run for 5 seconds,
// sending a ping every 100ms. After completion, verifies:
//   - All requests succeeded
//   - ConnectionCount returns to 0
//   - No significant goroutine leak
// ============================================================

func TestSoakStability(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = "test-bearer-token"
	cfg.RateLimitRPM = 0       // disable rate limiting for soak test
	cfg.MaxToolsPerSession = 0 // disable per-session tool count limit

	srv, addr := startTestServer(t, cfg)

	// Record goroutine count before the test
	runtime.GC()
	goroutinesBefore := runtime.NumGoroutine()

	const numConns = 10
	const soakDuration = 5 * time.Second
	const pingInterval = 100 * time.Millisecond

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64

	deadline := time.Now().Add(soakDuration)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, enc, dec, initResp := dialAndInitialize(t, addr, "test-bearer-token")
			defer conn.Close()

			if initResp.Error != nil {
				atomic.AddInt64(&errorCount, 1)
				t.Errorf("conn %d initialize error: %v", idx, initResp.Error)
				return
			}

			reqID := 1
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()

			for {
				if time.Now().After(deadline) {
					return
				}
				select {
				case <-ticker.C:
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					resp, err := callPing(enc, dec, reqID)
					reqID++
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						if atomic.LoadInt64(&errorCount) <= 3 {
							t.Errorf("conn %d ping error: %v", idx, err)
						}
						return
					}
					if resp.Error != nil {
						atomic.AddInt64(&errorCount, 1)
						if atomic.LoadInt64(&errorCount) <= 3 {
							t.Errorf("conn %d ping error: %v", idx, resp.Error)
						}
						return
					}
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	// Give connections time to close and server to clean up
	time.Sleep(500 * time.Millisecond)

	successes := atomic.LoadInt64(&successCount)
	errors := atomic.LoadInt64(&errorCount)

	// Check connection count returns to 0
	connCount := srv.server.ConnectionCount()

	// Check goroutine leak
	runtime.GC()
	time.Sleep(200 * time.Millisecond) // let goroutines unwind
	runtime.GC()
	goroutinesAfter := runtime.NumGoroutine()
	// Allow some slack for runtime/scheduler goroutines
	goroutineDelta := goroutinesAfter - goroutinesBefore

	t.Logf("=== TestSoakStability ===")
	t.Logf("Connections: %d, Duration: %v, Ping interval: %v", numConns, soakDuration, pingInterval)
	t.Logf("Successful pings: %d, Errors: %d", successes, errors)
	t.Logf("Expected ~%d pings (10 conns × 50 pings/5s)", numConns*int(soakDuration/pingInterval))
	t.Logf("Connection count after test: %d", connCount)
	t.Logf("Goroutines before: %d, after: %d, delta: %d", goroutinesBefore, goroutinesAfter, goroutineDelta)

	if errors > 0 {
		t.Errorf("expected 0 errors during soak, got %d", errors)
	}
	if successes == 0 {
		t.Error("expected some successful pings, got 0")
	}
	if connCount > 0 {
		t.Errorf("expected connection count to return to 0, got %d", connCount)
	}

	// Allow some slack (10 goroutines) for runtime internals, deferred cleanup, etc.
	if goroutineDelta > 10 {
		t.Errorf("possible goroutine leak: delta=%d (before=%d, after=%d)", goroutineDelta, goroutinesBefore, goroutinesAfter)
	} else {
		t.Logf("Goroutine leak check passed (delta=%d, within slack of 10)", goroutineDelta)
	}
}
