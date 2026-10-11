// SPDX-License-Identifier: Apache-2.0
// Tests for gap closure: logging/setLevel filter, notifications/progress,
// JSON-RPC batch, currentSessionID for TCP/stdio, roots/list.

package mcpsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================
// Gap 1: logging/setLevel actually filters log output
// ============================================================

func TestLogLevelFilterDebugShowsAll(t *testing.T) {
	// Verify level mapping
	tests := []struct {
		mcp   string
		slogL slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"notice", slog.LevelInfo},
		{"warning", slog.LevelWarn},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"critical", slog.LevelError},
		{"alert", slog.LevelError},
		{"emergency", slog.LevelError},
		{"unknown", slog.LevelInfo}, // default
	}
	for _, tt := range tests {
		got := mcpLevelToSlog(tt.mcp)
		if got != tt.slogL {
			t.Errorf("mcpLevelToSlog(%q) = %v, want %v", tt.mcp, got, tt.slogL)
		}
	}
}

func TestLogLevelFiltering(t *testing.T) {
	// Create a buffer-backed handler to test filtering
	var buf bytes.Buffer
	filterHandler := &levelFilterHandler{inner: slog.NewTextHandler(&buf, nil)}
	logger := slog.New(filterHandler)

	// Set level to warning — debug and info should be filtered out
	setLogLevel("warning")
	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")
	logger.Error("error msg")

	output := buf.String()
	if strings.Contains(output, "debug msg") {
		t.Error("debug message should be filtered when level is warning")
	}
	if strings.Contains(output, "info msg") {
		t.Error("info message should be filtered when level is warning")
	}
	if !strings.Contains(output, "warn msg") {
		t.Error("warn message should pass when level is warning")
	}
	if !strings.Contains(output, "error msg") {
		t.Error("error message should pass when level is warning")
	}

	// Set level to debug — everything should pass
	setLogLevel("debug")
	buf.Reset()
	logger.Debug("debug msg 2")
	if !strings.Contains(buf.String(), "debug msg 2") {
		t.Error("debug message should pass when level is debug")
	}

	// Reset to info for other tests
	setLogLevel("info")
}

func TestLogLevelThreadSafe(t *testing.T) {
	// Concurrent reads and writes should not panic
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			setLogLevel("debug")
		}()
		go func() {
			defer wg.Done()
			_ = getLogLevel()
		}()
	}
	wg.Wait()
}

func TestLogLevelViaRPC(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)
	setLogLevel("info")

	// Set to error via RPC
	params, _ := json.Marshal(map[string]interface{}{"level": "error"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "logging/setLevel", Params: params, ID: 1}
	resp := h.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("logging/setLevel failed: %v", resp)
	}
	if got := getLogLevel(); got != "error" {
		t.Errorf("expected log level 'error', got %q", got)
	}

	// Reset
	setLogLevel("info")
}

// ============================================================
// Gap 2: notifications/progress sent during long tool execution
// ============================================================

func TestProgressTokenParsing(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)
	h.Registry.Register("slow_tool", "Slow tool", 10, map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
		"required":   []interface{}{},
	})
	h.Registry.RegisterHandler("slow_tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		time.Sleep(100 * time.Millisecond)
		return "done", nil
	})

	// Verify that a request with _meta.progressToken is accepted
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "slow_tool",
		"arguments": map[string]interface{}{},
		"_meta":     map[string]interface{}{"progressToken": "token-123"},
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 1}
	resp := h.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestProgressNotificationSent(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)
	h.ExecTimeout = 30 * time.Second

	var notifMu sync.Mutex
	var notifications []struct {
		method string
		params interface{}
	}
	h.NotifyCallback = func(method string, params interface{}) {
		notifMu.Lock()
		notifications = append(notifications, struct {
			method string
			params interface{}
		}{method, params})
		notifMu.Unlock()
	}

	h.Registry.Register("very_slow", "Very slow tool", 10, map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
	})
	h.Registry.RegisterHandler("very_slow", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		// Sleep long enough for at least one 5s progress tick
		time.Sleep(6 * time.Second)
		return "completed", nil
	})

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "very_slow",
		"arguments": map[string]interface{}{},
		"_meta":     map[string]interface{}{"progressToken": "pt-abc"},
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 42}

	done := make(chan struct{})
	go func() {
		h.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
		close(done)
	}()
	<-done

	notifMu.Lock()
	defer notifMu.Unlock()
	var progressNotifs int
	for _, n := range notifications {
		if n.method == "notifications/progress" {
			progressNotifs++
			pm, ok := n.params.(map[string]interface{})
			if !ok {
				t.Error("progress notification params should be a map")
				continue
			}
			if pm["progressToken"] != "pt-abc" {
				t.Errorf("expected progressToken 'pt-abc', got %v", pm["progressToken"])
			}
		}
	}
	if progressNotifs == 0 {
		t.Error("expected at least one notifications/progress to be sent")
	}
}

func TestProgressNoTokenNoNotification(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)
	h.ExecTimeout = 5 * time.Second

	var notifCount int
	var notifMu sync.Mutex
	h.NotifyCallback = func(method string, params interface{}) {
		notifMu.Lock()
		if method == "notifications/progress" {
			notifCount++
		}
		notifMu.Unlock()
	}

	h.Registry.Register("fast", "Fast tool", 10, map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
	})
	h.Registry.RegisterHandler("fast", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "ok", nil
	})

	// No _meta.progressToken
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "fast",
		"arguments": map[string]interface{}{},
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 1}
	resp := h.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected: %v", resp)
	}

	notifMu.Lock()
	defer notifMu.Unlock()
	if notifCount > 0 {
		t.Errorf("expected no progress notifications without token, got %d", notifCount)
	}
}

// ============================================================
// Gap 3: JSON-RPC batch handling
// ============================================================

func TestHandleBatchRequest(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)

	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 2},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 3},
	}
	responses := h.HandleBatchRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, batch)
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(responses))
	}
	for i, r := range responses {
		if r.Error != nil {
			t.Errorf("response %d has error: %v", i, r.Error)
		}
	}
}

func TestHandleBatchRequestWithNotifications(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)

	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1},
		{JSONRPC: JSONRPCVersion, Method: "notifications/initialized"}, // no ID = notification
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 2},
	}
	responses := h.HandleBatchRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, batch)
	// notifications/initialized returns nil, so only 2 responses
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses (1 notification excluded), got %d", len(responses))
	}
}

func TestHandleBatchRequestAllNotifications(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)

	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "notifications/initialized"},
		{JSONRPC: JSONRPCVersion, Method: "notifications/cancelled"},
	}
	responses := h.HandleBatchRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, batch)
	if len(responses) != 0 {
		t.Errorf("expected 0 responses for all-notification batch, got %d", len(responses))
	}
}

func TestBatchTCP(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.handler.Authorizer = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := srv.server.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// Send a batch of 3 ping requests
	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 2},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 3},
	}
	if err := enc.Encode(batch); err != nil {
		t.Fatalf("Encode batch: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var responses []*JSONRPCResponse
	if err := dec.Decode(&responses); err != nil {
		t.Fatalf("Decode batch response: %v", err)
	}
	if len(responses) != 3 {
		t.Errorf("expected 3 batch responses, got %d", len(responses))
	}
}

func TestBatchStdio(t *testing.T) {
	// Use os.Pipe for deadline support
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer stdoutR.Close()
	defer stdoutW.Close()

	srv, err := NewSecuredMCPServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.handler.Authorizer = nil

	// Create a stdio transport manually
	transport := &stdioTransport{
		handler: func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
			return srv.handler.HandleRequest(conn, req)
		},
		encoder: json.NewEncoder(stdoutW),
		decoder: json.NewDecoder(stdinR),
		conn: &Connection{
			ID:        "stdio-test",
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
			Session:   &Session{ID: "stdio-test"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go transport.run(ctx)

	// Send a batch of 2 ping requests
	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 10},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 20},
	}
	batchJSON, _ := json.Marshal(batch)
	stdinW.Write(batchJSON)

	// Read response (batch should come back as array)
	stdoutR.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(stdoutR)
	var responses []*JSONRPCResponse
	if err := dec.Decode(&responses); err != nil {
		t.Fatalf("Decode batch response: %v", err)
	}
	if len(responses) != 2 {
		t.Errorf("expected 2 batch responses, got %d", len(responses))
	}
}

func TestBatchHTTP(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.AuthToken = ""

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.handler.Authorizer = nil

	// Create and start the streamable HTTP transport
	transport := newStreamableHTTPTransport("127.0.0.1:0", func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return srv.handler.HandleRequest(conn, req)
	})
	ln, err := startStreamableHTTPListener(transport)
	if err != nil {
		t.Fatalf("startStreamableHTTPListener: %v", err)
	}
	defer ln.Close()
	defer transport.httpSrv.Close()

	go transport.httpSrv.Serve(ln)
	baseURL := "http://" + ln.Addr().String()

	// First, initialize to get a session
	initReq, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: JSONRPCVersion, Method: "initialize", ID: 1,
		Params: json.RawMessage(`{"protocolVersion":"2025-06-18","clientInfo":{"name":"batch-test","version":"1.0"}}`),
	})
	resp, err := http.Post(baseURL+"/mcp", "application/json", bytes.NewReader(initReq))
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("no Mcp-Session-Id header")
	}
	resp.Body.Close()

	// Send a batch of ping requests
	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 100},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 200},
	}
	batchJSON, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", baseURL+"/mcp", bytes.NewReader(batchJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("batch POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var responses []*JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&responses); err != nil {
		t.Fatalf("Decode batch response: %v", err)
	}
	if len(responses) != 2 {
		t.Errorf("expected 2 batch responses, got %d", len(responses))
	}
}

// ============================================================
// Gap 4: currentSessionID set by TCP/stdio transports
// ============================================================

func TestCurrentSessionIDSetTCP(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.handler.Authorizer = nil

	// Track the sessionID seen during tool execution
	var seenSessionID string
	var sidMu sync.Mutex
	srv.RegisterTool("sid_check", "Check session ID", 10, map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
	})
	srv.RegisterToolHandler("sid_check", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		sidMu.Lock()
		seenSessionID = currentSessionID.Get()
		sidMu.Unlock()
		return "ok", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := srv.server.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// Initialize first
	initReq, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "sid-test", "version": "1.0"},
	})
	enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initReq, ID: 1})
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var initResp JSONRPCResponse
	dec.Decode(&initResp)

	// Call the tool
	toolParams, _ := json.Marshal(map[string]interface{}{"name": "sid_check", "arguments": map[string]interface{}{}})
	enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: toolParams, ID: 2})
	var toolResp JSONRPCResponse
	dec.Decode(&toolResp)

	sidMu.Lock()
	defer sidMu.Unlock()
	if seenSessionID == "" {
		t.Error("expected currentSessionID to be set during TCP tool execution, got empty string")
	}
}

func TestCurrentSessionIDSetStdio(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer stdoutR.Close()
	defer stdoutW.Close()

	srv, err := NewSecuredMCPServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.handler.Authorizer = nil

	var seenSessionID string
	var sidMu sync.Mutex
	srv.RegisterTool("sid_stdio", "Check session ID via stdio", 10, map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
	})
	srv.RegisterToolHandler("sid_stdio", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		sidMu.Lock()
		seenSessionID = currentSessionID.Get()
		sidMu.Unlock()
		return "ok", nil
	})

	transport := &stdioTransport{
		handler: func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
			return srv.handler.HandleRequest(conn, req)
		},
		encoder: json.NewEncoder(stdoutW),
		decoder: json.NewDecoder(stdinR),
		conn: &Connection{
			ID:        "stdio-sid",
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
			Session:   &Session{ID: "stdio-sid"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.run(ctx)

	// Call the tool
	toolParams, _ := json.Marshal(map[string]interface{}{"name": "sid_stdio", "arguments": map[string]interface{}{}})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: toolParams, ID: 1}
	reqJSON, _ := json.Marshal(req)
	stdinW.Write(reqJSON)

	// Read response
	stdoutR.SetReadDeadline(time.Now().Add(5 * time.Second))
	dec := json.NewDecoder(stdoutR)
	var resp JSONRPCResponse
	dec.Decode(&resp)

	sidMu.Lock()
	defer sidMu.Unlock()
	if seenSessionID != "stdio-sid" {
		t.Errorf("expected currentSessionID 'stdio-sid', got %q", seenSessionID)
	}
}

// ============================================================
// Gap 5: roots/list returns empty roots
// ============================================================

func TestRootsListEmpty(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "roots/list", ID: 1}
	resp := h.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	roots, ok := result["roots"].([]interface{})
	if !ok {
		t.Fatalf("expected roots to be []interface{}, got %T", result["roots"])
	}
	if len(roots) != 0 {
		t.Errorf("expected empty roots, got %d items", len(roots))
	}
}

func TestRootsListViaBatch(t *testing.T) {
	h := NewRequestHandler(nil, nil, nil)
	batch := []JSONRPCRequest{
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1},
		{JSONRPC: JSONRPCVersion, Method: "roots/list", ID: 2},
		{JSONRPC: JSONRPCVersion, Method: "ping", ID: 3},
	}
	responses := h.HandleBatchRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, batch)
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(responses))
	}
	// roots/list response should have empty roots
	rootsResp := responses[1]
	if rootsResp.Error != nil {
		t.Fatalf("roots/list error: %v", rootsResp.Error)
	}
	result, ok := rootsResp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", rootsResp.Result)
	}
	roots, ok := result["roots"].([]interface{})
	if !ok {
		t.Fatalf("expected roots slice, got %T", result["roots"])
	}
	if len(roots) != 0 {
		t.Errorf("expected empty roots in batch, got %d", len(roots))
	}
}

// ============================================================
// Gap 2+4 integration: progress notification via TCP (currentNotifyFn)
// ============================================================

func TestProgressNotificationViaTCP(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	cfg.ExecTimeout = 30 * time.Second
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	srv.handler.Authorizer = nil

	srv.RegisterTool("slow_tcp", "Slow tool for TCP progress test", 10, map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{},
	})
	srv.RegisterToolHandler("slow_tcp", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		time.Sleep(6 * time.Second)
		return "done", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := srv.server.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// Initialize
	initReq, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"clientInfo":      map[string]interface{}{"name": "progress-test", "version": "1.0"},
	})
	enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", Params: initReq, ID: 1})
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var initResp JSONRPCResponse
	dec.Decode(&initResp)

	// Call slow tool with progress token
	toolParams, _ := json.Marshal(map[string]interface{}{
		"name":      "slow_tcp",
		"arguments": map[string]interface{}{},
		"_meta":     map[string]interface{}{"progressToken": "tcp-pt-1"},
	})
	enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: toolParams, ID: 2})

	// We should receive at least one progress notification (no ID, has method)
	// followed by the final tool response (has ID)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var progressSeen bool
	for i := 0; i < 5; i++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		// Check if it's a notification (has method, no id) or response (has id)
		var check struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id,omitempty"`
			Params json.RawMessage `json:"params,omitempty"`
		}
		json.Unmarshal(raw, &check)
		if check.Method == "notifications/progress" {
			progressSeen = true
			var pm struct {
				ProgressToken string `json:"progressToken"`
				Progress      int    `json:"progress"`
			}
			json.Unmarshal(check.Params, &pm)
			if pm.ProgressToken != "tcp-pt-1" {
				t.Errorf("expected progressToken 'tcp-pt-1', got %q", pm.ProgressToken)
			}
		}
		// If it has an ID and no method, it's the final response
		if len(check.ID) > 0 && check.Method == "" {
			break
		}
	}
	if !progressSeen {
		t.Error("expected at least one notifications/progress via TCP")
	}
}
