// SPDX-License-Identifier: Apache-2.0

package mcpsecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Item 8: Resources and Prompts
// ============================================================

func TestResourcesList(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "resources/list", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/list failed: %v", resp)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", resp.Result)
	}
	resources, ok := result["resources"].([]interface{})
	if !ok {
		t.Fatal("missing resources field")
	}
	if len(resources) != 0 {
		t.Errorf("expected empty resources, got %d", len(resources))
	}
}

func TestResourcesRead(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "resources/read", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Error("expected error for resources/read with no resources")
	}
}

func TestResourcesSubscribe(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "resources/subscribe", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/subscribe failed: %v", resp)
	}
}

func TestResourcesUnsubscribe(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "resources/unsubscribe", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/unsubscribe failed: %v", resp)
	}
}

func TestPromptsList(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "prompts/list", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("prompts/list failed: %v", resp)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", resp.Result)
	}
	prompts, ok := result["prompts"].([]interface{})
	if !ok {
		t.Fatal("missing prompts field")
	}
	if len(prompts) != 0 {
		t.Errorf("expected empty prompts, got %d", len(prompts))
	}
}

func TestPromptsGet(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "prompts/get", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Error("expected error for prompts/get with no prompts")
	}
}

// ============================================================
// Item 9: Logging setLevel
// ============================================================

func TestLoggingSetLevel(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	params, _ := json.Marshal(map[string]interface{}{"level": "debug"})
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "logging/setLevel",
		Params:  params,
		ID:      1,
	}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("logging/setLevel failed: %v", resp)
	}
	if currentLogLevel != "debug" {
		t.Errorf("expected log level 'debug', got %q", currentLogLevel)
	}
}

func TestLoggingSetLevelNoParams(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "logging/setLevel", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("logging/setLevel with no params should succeed: %v", resp)
	}
}

// ============================================================
// Item 10: Completion
// ============================================================

func TestCompletionComplete(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "completion/complete", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("completion/complete failed: %v", resp)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", resp.Result)
	}
	completion, ok := result["completion"].(map[string]interface{})
	if !ok {
		t.Fatal("missing completion field")
	}
	if _, ok := completion["values"]; !ok {
		t.Error("missing values field in completion")
	}
}

// ============================================================
// Item 11: Prometheus metrics endpoint
// ============================================================

func TestPrometheusMetrics(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.DemoTools = true
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	defer srv.Stop()

	hs := newHealthServer("127.0.0.1:0", srv)

	// Use httptest to hit the handler directly
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	hs.handlePrometheus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "aegisgate_mcp_up 1") {
		t.Error("missing aegisgate_mcp_up metric")
	}
	if !strings.Contains(body, "aegisgate_mcp_tools_registered") {
		t.Error("missing tools_registered metric")
	}
	if !strings.Contains(body, "aegisgate_mcp_active_sessions") {
		t.Error("missing active_sessions metric")
	}
	if !strings.Contains(body, "aegisgate_mcp_policy_rules") {
		t.Error("missing policy_rules metric")
	}
}

func TestPrometheusMetricsNilServer(t *testing.T) {
	hs := newHealthServer("127.0.0.1:0", nil)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	hs.handlePrometheus(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ============================================================
// Item 12: Tamper-evident audit log
// ============================================================

func TestAuditHashChain(t *testing.T) {
	logger, err := NewAuditLogger("", 100)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	ctx := context.Background()
	// Log 3 entries
	logger.Log(ctx, &AuditEntry{Type: "initialize", SessionID: "s1"})
	logger.Log(ctx, &AuditEntry{Type: "tool_success", SessionID: "s1", ToolName: "ping"})
	logger.Log(ctx, &AuditEntry{Type: "tool_denied", SessionID: "s1", ToolName: "shell_exec"})

	// Verify chain integrity
	if !logger.VerifyChain() {
		t.Fatal("hash chain verification failed on clean log")
	}

	// Verify each entry has a hash
	entries := logger.Query(AuditFilter{})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for i, entry := range entries {
		if entry.Hash == "" {
			t.Errorf("entry %d has empty hash", i)
		}
		if i > 0 && entry.PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d PrevHash mismatch", i)
		}
	}
}

func TestAuditHashChainTamperDetected(t *testing.T) {
	logger, err := NewAuditLogger("", 100)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	ctx := context.Background()
	logger.Log(ctx, &AuditEntry{Type: "initialize", SessionID: "s1"})
	logger.Log(ctx, &AuditEntry{Type: "tool_success", SessionID: "s1", ToolName: "ping"})

	// Verify clean
	if !logger.VerifyChain() {
		t.Fatal("chain should be valid before tampering")
	}

	// Tamper: modify an entry's content without updating hash
	logger.mu.Lock()
	logger.entries[0].ToolName = "tampered_tool"
	logger.mu.Unlock()

	// Verify should now fail
	if logger.VerifyChain() {
		t.Fatal("chain verification should fail after tampering")
	}
}

func TestComputeAuditHash(t *testing.T) {
	action := &AuditAction{
		ID:        "test-1",
		Type:      "tool_success",
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		SessionID: "s1",
		ToolName:  "ping",
	}
	hash1 := computeAuditHash("", action)
	hash2 := computeAuditHash("", action)
	if hash1 != hash2 {
		t.Error("same inputs should produce same hash")
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	// Different prevHash → different hash
	hash3 := computeAuditHash("abcdef", action)
	if hash3 == hash1 {
		t.Error("different prevHash should produce different hash")
	}

	// Different content → different hash
	action2 := &AuditAction{
		ID:        "test-2",
		Type:      "tool_success",
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		SessionID: "s1",
		ToolName:  "ping",
	}
	hash4 := computeAuditHash("", action2)
	if hash4 == hash1 {
		t.Error("different ID should produce different hash")
	}
}

// ============================================================
// Item 13: Global auth rate limiting
// ============================================================

func TestGlobalAuthRateLimit(t *testing.T) {
	authMgr := NewAuthManager(&AuthConfig{
		BearerToken:     "test-token",
		MaxAuthAttempts: 1000, // high per-conn limit so global triggers first
	})

	// Simulate 101 global failures
	authMgr.mu.Lock()
	authMgr.globalAttempts = 101
	authMgr.globalWindowStart = time.Now()
	authMgr.mu.Unlock()

	if !authMgr.IsGlobalRateLimited() {
		t.Error("should be rate limited with 101 global attempts")
	}
}

func TestGlobalAuthRateLimitNotExceeded(t *testing.T) {
	authMgr := NewAuthManager(&AuthConfig{
		BearerToken:     "test-token",
		MaxAuthAttempts: 5,
	})

	// Simulate 50 global failures (below 100 threshold)
	authMgr.mu.Lock()
	authMgr.globalAttempts = 50
	authMgr.globalWindowStart = time.Now()
	authMgr.mu.Unlock()

	if authMgr.IsGlobalRateLimited() {
		t.Error("should NOT be rate limited with 50 global attempts")
	}
}

func TestGlobalAuthRateLimitWindowExpired(t *testing.T) {
	authMgr := NewAuthManager(&AuthConfig{
		BearerToken:     "test-token",
		MaxAuthAttempts: 5,
	})

	// Simulate high attempts but expired window
	authMgr.mu.Lock()
	authMgr.globalAttempts = 200
	authMgr.globalWindowStart = time.Now().Add(-2 * time.Minute) // expired
	authMgr.mu.Unlock()

	if authMgr.IsGlobalRateLimited() {
		t.Error("should NOT be rate limited with expired window")
	}
}

func TestGlobalAuthRateLimitZeroState(t *testing.T) {
	authMgr := NewAuthManager(&AuthConfig{
		BearerToken:     "test-token",
		MaxAuthAttempts: 5,
	})

	// Fresh manager — no global attempts at all
	if authMgr.IsGlobalRateLimited() {
		t.Error("fresh manager should not be rate limited")
	}
}
