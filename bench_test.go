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
	"context"
	"encoding/json"
	"testing"
)

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
