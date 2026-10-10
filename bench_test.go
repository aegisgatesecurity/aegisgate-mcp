// SPDX-License-Identifier: Apache-2.0
// Benchmark tests for performance regression tracking.
//
// Run with: go test -bench=. -benchmem -benchtime=5s ./...
// Compare across releases: go test -bench=. -count=5 ./... | benchstat old.txt new.txt
//
// These benchmarks measure the hot-path components of the MCP security
// gateway to detect performance regressions during development.

package mcpsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// fastNano returns the current monotonic time in nanoseconds. Uses
// time.Now().UnixNano() for portability across all platforms.
func fastNano() int64 {
	return time.Now().UnixNano()
}

// ============================================================
// BenchmarkHandleRequest — core request dispatch
// ============================================================

// BenchmarkPing measures the cost of a full ping request through the
// handler, including JSON-RPC dispatch and response construction.
// This is the baseline for all other benchmarks — any regression here
// affects every request the server processes.
func BenchmarkPing(b *testing.B) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Authorizer = nil
	handler.Registry.Register("ping", "ping tool", 10, nil)
	handler.Registry.RegisterHandler("ping", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "pong", nil
	})

	conn := &Connection{ID: "bench", Session: &Session{ID: "bench"}}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		params, _ := json.Marshal(map[string]interface{}{"name": "ping", "arguments": map[string]interface{}{}})
		req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: i}
		_ = handler.HandleRequest(conn, req)
	}
}

// BenchmarkInitialize measures the cost of an initialize request,
// including clientInfo parsing and capability advertisement.
func BenchmarkInitialize(b *testing.B) {
	handler := NewRequestHandler(nil, nil, nil)

	conn := &Connection{ID: "bench", Session: &Session{ID: "bench"}}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		params, _ := json.Marshal(map[string]interface{}{
			"protocolVersion": ProtocolVersion,
			"clientInfo":      map[string]interface{}{"name": "bench", "version": "1.0"},
		})
		req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: params, ID: i}
		_ = handler.HandleRequest(conn, req)
	}
}

// BenchmarkToolsList measures the cost of listing registered tools.
func BenchmarkToolsList(b *testing.B) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Registry.Register("tool1", "Tool 1", 10, nil)
	handler.Registry.Register("tool2", "Tool 2", 20, nil)
	handler.Registry.Register("tool3", "Tool 3", 30, nil)

	conn := &Connection{ID: "bench", Session: &Session{ID: "bench"}}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/list", ID: i}
		_ = handler.HandleRequest(conn, req)
	}
}

// ============================================================
// BenchmarkAuthMiddleware — auth layer overhead
// ============================================================

// BenchmarkAuthMiddleware measures the overhead of the auth middleware
// on a successful bearer token authentication path.
func BenchmarkAuthMiddleware(b *testing.B) {
	authCfg := &AuthConfig{
		BearerToken:     "bench-token",
		MaxAuthAttempts: 5,
	}
	authMgr := NewAuthManager(authCfg)

	handler := NewRequestHandler(nil, nil, nil)
	handler.Authorizer = nil
	handler.Registry.Register("ping", "ping", 10, nil)
	handler.Registry.RegisterHandler("ping", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "pong", nil
	})

	inner := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return handler.HandleRequest(conn, req)
	}
	wrapped := authMgr.AuthMiddleware(inner)

	// Pre-authenticate the connection
	conn := &Connection{ID: "bench", Session: &Session{ID: "bench"}}
	initParams, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "bench", "version": "1.0"},
		"auth":            map[string]interface{}{"token": "bench-token"},
	})
	initReq := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initParams, ID: 1}
	wrapped(conn, initReq)

	// Now benchmark subsequent requests (auth state already set)
	callParams, _ := json.Marshal(map[string]interface{}{"name": "ping", "arguments": map[string]interface{}{}})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: callParams, ID: i + 2}
		_ = wrapped(conn, req)
	}
}

// ============================================================
// BenchmarkResponseScan — scanner overhead
// ============================================================

// BenchmarkResponseScanShort measures scanner overhead on a short
// response ("pong" — 4 bytes). This is the common case.
func BenchmarkResponseScanShort(b *testing.B) {
	scanner := NewContentScanner()
	text := "pong"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		scanner.ScanResponse(text, true, true, true, true)
	}
}

// BenchmarkResponseScanMedium measures scanner overhead on a medium
// response (~500 bytes — typical tool output).
func BenchmarkResponseScanMedium(b *testing.B) {
	scanner := NewContentScanner()
	// Build a ~500 byte response with no security findings
	text := "Device status report: all systems operational. "
	for len(text) < 500 {
		text += "Sensor reading: nominal. Pressure: 14.7 psi. Temperature: 72F. "
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		scanner.ScanResponse(text, true, true, true, true)
	}
}

// BenchmarkResponseScanLarge measures scanner overhead on a large
// response (~4KB — database query or log dump).
func BenchmarkResponseScanLarge(b *testing.B) {
	scanner := NewContentScanner()
	text := "Query results: "
	for len(text) < 4096 {
		text += "id=12345 status=active timestamp=2026-01-01T00:00:00Z value=42.0 "
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		scanner.ScanResponse(text, true, true, true, true)
	}
}

// ============================================================
// BenchmarkAuditLog — audit logging overhead
// ============================================================

// BenchmarkAuditLog measures the cost of writing a single audit entry
// to the in-memory log, including hash chain computation.
func BenchmarkAuditLog(b *testing.B) {
	logger, err := NewAuditLogger("", 100000)
	if err != nil {
		b.Fatalf("NewAuditLogger: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		action := &AuditAction{
			ID:        "bench-action",
			Type:      "tool_success",
			SessionID: "bench-session",
			AgentID:   "bench-agent",
			ToolName:  "ping",
			Allowed:   true,
			RiskScore: 10,
		}
		logger.LogAction(ctx, action)
	}
}

// ============================================================
// BenchmarkJSONEncode — JSON serialization overhead
// ============================================================

// BenchmarkJSONEncodeResponse measures the cost of JSON-encoding a
// JSONRPCResponse. This happens on every request.
func BenchmarkJSONEncodeResponse(b *testing.B) {
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Result: CallToolResult{
			Content: []ContentBlock{{Type: "text", Text: "pong"}},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(resp)
	}
}

// BenchmarkJSONDecodeRequest measures the cost of JSON-decoding a
// JSONRPCRequest from raw bytes.
func BenchmarkJSONDecodeRequest(b *testing.B) {
	params, _ := json.Marshal(map[string]interface{}{"name": "ping", "arguments": map[string]interface{}{}})
	data, _ := json.Marshal(&JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		Params:  params,
		ID:      1,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var req JSONRPCRequest
		_ = json.Unmarshal(data, &req)
	}
}

// ============================================================
// HTTP Transport Benchmarks
// ============================================================

// BenchmarkHTTPPing measures the cost of a ping request over the
// Streamable HTTP transport, including HTTP request/response overhead.
func BenchmarkHTTPPing(b *testing.B) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.DemoTools = true
	cfg.ScanResponses = false
	cfg.BlockOnPII = false
	cfg.BlockOnSecrets = false

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		b.Fatalf("NewSecuredMCPServer: %v", err)
	}
	defer srv.Stop()

	// Use httptest to create a test HTTP server with the handler chain
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		conn := &Connection{ID: "bench", Session: &Session{ID: "bench"}}
		body, _ := io.ReadAll(r.Body)
		var req JSONRPCRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := srv.server.handleFunc(conn, &req)
		if resp != nil {
			data, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		}
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	pingReq, _ := json.Marshal(&JSONRPCRequest{
		JSONRPC: JSONRPCVersion, Method: "ping", ID: 1,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(pingReq))
		if err != nil {
			b.Fatalf("POST: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkMiddlewareChain measures the cost of a tools/call request
// through the full middleware chain (auth → sig → guardrails → scan → handler).
// This is the most realistic benchmark for production request overhead.
func BenchmarkMiddlewareChain(b *testing.B) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = "bench-token"
	cfg.DemoTools = true
	cfg.ScanResponses = true
	cfg.BlockOnPII = false
	cfg.BlockOnSecrets = false

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		b.Fatalf("NewSecuredMCPServer: %v", err)
	}
	defer srv.Stop()

	conn := &Connection{ID: "bench", Session: &Session{ID: "bench"}}
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "ping",
		"arguments": map[string]interface{}{},
	})
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 1,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srv.handler.HandleRequest(conn, req)
	}
}

// ============================================================
// Concurrent Throughput — RunParallel
// ============================================================

// BenchmarkMiddlewareChainParallel measures throughput under concurrent
// load using b.RunParallel. Each goroutine creates its own Connection
// and issues tools/call requests through the full middleware chain.
// This reveals contention on shared resources (audit log, rate limiter,
// scanner pool) that the single-goroutine benchmark cannot detect.
//
// Throughput = b.N / elapsed, reported via b.ReportMetric as ops/sec.
func BenchmarkMiddlewareChainParallel(b *testing.B) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = "bench-token"
	cfg.DemoTools = true
	cfg.ScanResponses = true
	cfg.BlockOnPII = false
	cfg.BlockOnSecrets = false
	cfg.RateLimitRPM = 0 // disable rate limiting for pure throughput

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		b.Fatalf("NewSecuredMCPServer: %v", err)
	}
	defer srv.Stop()

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "ping",
		"arguments": map[string]interface{}{},
	})

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine gets its own connection to avoid false sharing
		conn := &Connection{
			ID:      "parallel",
			Session: &Session{ID: "parallel"},
		}
		req := &JSONRPCRequest{
			JSONRPC: JSONRPCVersion,
			Method:  "tools/call",
			Params:  params,
			ID:      1,
		}
		for pb.Next() {
			srv.handler.HandleRequest(conn, req)
		}
	})
}

// ============================================================
// Latency Percentiles — p50 / p99
// ============================================================

// BenchmarkMiddlewareChainLatency measures per-request latency through
// the full middleware chain and reports p50, p99, min, and max via
// b.ReportMetric. Unlike the load_test.go suite (gated behind
// -tags=load), this runs as a standard benchmark in CI.
//
// Metrics reported:
//   - p50_ns: median latency in nanoseconds
//   - p99_ns: 99th percentile latency in nanoseconds
//   - min_ns: minimum latency
//   - max_ns: maximum latency
func BenchmarkMiddlewareChainLatency(b *testing.B) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = "bench-token"
	cfg.DemoTools = true
	cfg.ScanResponses = true
	cfg.BlockOnPII = false
	cfg.BlockOnSecrets = false

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		b.Fatalf("NewSecuredMCPServer: %v", err)
	}
	defer srv.Stop()

	conn := &Connection{ID: "latency", Session: &Session{ID: "latency"}}
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "ping",
		"arguments": map[string]interface{}{},
	})
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 1,
	}

	// Warm up to stabilize caches
	for i := 0; i < 100; i++ {
		srv.handler.HandleRequest(conn, req)
	}

	latencies := make([]int64, b.N)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		start := fastNano()
		srv.handler.HandleRequest(conn, req)
		latencies[i] = fastNano() - start
	}
	b.StopTimer()

	// Sort a copy to compute percentiles
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	p50 := sorted[len(sorted)/2]
	p99 := sorted[(len(sorted)*99)/100]
	minLat := sorted[0]
	maxLat := sorted[len(sorted)-1]

	b.ReportMetric(float64(p50), "p50_ns")
	b.ReportMetric(float64(p99), "p99_ns")
	b.ReportMetric(float64(minLat), "min_ns")
	b.ReportMetric(float64(maxLat), "max_ns")
}
