// SPDX-License-Identifier: Apache-2.0
// Tests for transport (stdio), health endpoint, config file, and new CLI flags.

package mcpsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================
// stdio Transport Tests
// ============================================================

func TestStdioTransportBasic(t *testing.T) {
	// Create a pipe to simulate stdin/stdout
	input := &bytes.Buffer{}
	output := &bytes.Buffer{}

	handler := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return &JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Result:  map[string]interface{}{"echo": req.Method},
		}
	}

	transport := &stdioTransport{
		handler: handler,
		encoder: json.NewEncoder(output),
		decoder: json.NewDecoder(input),
		conn: &Connection{
			ID:        "test-stdio",
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
			Session:   &Session{ID: "test-stdio"},
		},
	}

	// Write a request to the input buffer
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      1,
	}
	json.NewEncoder(input).Encode(req)

	// Run with a context that we cancel after processing
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		transport.run(ctx)
	}()

	// Give it time to process
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()

	// Check output
	var resp JSONRPCResponse
	if err := json.NewDecoder(output).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.JSONRPC != JSONRPCVersion {
		t.Errorf("response jsonrpc = %s, want %s", resp.JSONRPC, JSONRPCVersion)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %v", resp.Result)
	}
	if result["echo"] != "ping" {
		t.Errorf("echo = %v, want ping", result["echo"])
	}
}

func TestStdioTransportMultipleRequests(t *testing.T) {
	input := &bytes.Buffer{}
	output := &bytes.Buffer{}

	callCount := 0
	handler := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		callCount++
		return &JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
			Result:  map[string]interface{}{"count": callCount},
		}
	}

	transport := &stdioTransport{
		handler: handler,
		encoder: json.NewEncoder(output),
		decoder: json.NewDecoder(input),
		conn: &Connection{
			ID:        "test-stdio-multi",
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
			Session:   &Session{ID: "test-stdio-multi"},
		},
	}

	// Write multiple requests
	for i := 1; i <= 3; i++ {
		req := &JSONRPCRequest{
			JSONRPC: JSONRPCVersion,
			Method:  "ping",
			ID:      i,
		}
		json.NewEncoder(input).Encode(req)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		transport.run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	wg.Wait()

	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}

	// Decode all responses
	decoder := json.NewDecoder(output)
	for i := 1; i <= 3; i++ {
		var resp JSONRPCResponse
		if err := decoder.Decode(&resp); err != nil {
			t.Fatalf("failed to decode response %d: %v", i, err)
		}
		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatalf("response %d result is not a map: %v", i, resp.Result)
		}
		count, _ := result["count"].(float64)
		if int(count) != i {
			t.Errorf("response %d count = %v, want %d", i, count, i)
		}
	}
}

func TestStdioTransportEOF(t *testing.T) {
	// Empty input → immediate EOF
	input := &bytes.Buffer{}
	output := &bytes.Buffer{}

	handler := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: req.ID}
	}

	transport := &stdioTransport{
		handler: handler,
		encoder: json.NewEncoder(output),
		decoder: json.NewDecoder(input),
		conn: &Connection{
			ID:        "test-stdio-eof",
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
			Session:   &Session{ID: "test-stdio-eof"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := transport.run(ctx)
	if err != nil {
		t.Errorf("run with empty input should return nil, got %v", err)
	}
}

func TestStdioTransportContextCancel(t *testing.T) {
	// Input that blocks (never closes) — should exit on context cancel
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()

	output := &bytes.Buffer{}

	handler := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: req.ID}
	}

	transport := &stdioTransport{
		handler: handler,
		encoder: json.NewEncoder(output),
		decoder: json.NewDecoder(io.LimitReader(r, 1<<20)),
		conn: &Connection{
			ID:        "test-stdio-cancel",
			CreatedAt: time.Now(),
			LastSeen:  time.Now(),
			Session:   &Session{ID: "test-stdio-cancel"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		transport.run(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("stdio transport did not exit after context cancel")
	}
}

// ============================================================
// Health Endpoint Tests
// ============================================================

func TestHealthServerHealthz(t *testing.T) {
	srv := &SecuredMCPServer{
		config:  DefaultServerConfig(),
		handler: NewRequestHandler(nil, nil, nil),
	}
	hs := newHealthServer("127.0.0.1:0", srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// We need to get the actual listening address
	ln, err := newHealthListener(hs)
	if err != nil {
		t.Fatalf("failed to start health server: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		hs.httpSrv.Shutdown(context.Background())
	}()

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("healthz status field = %v, want ok", result["status"])
	}
	if result["version"] != Version {
		t.Errorf("healthz version = %v, want %s", result["version"], Version)
	}
}

func TestHealthServerReadyz(t *testing.T) {
	srv := &SecuredMCPServer{
		config:  DefaultServerConfig(),
		handler: NewRequestHandler(nil, nil, nil),
	}
	hs := newHealthServer("127.0.0.1:0", srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := newHealthListener(hs)
	if err != nil {
		t.Fatalf("failed to start health server: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		hs.httpSrv.Shutdown(context.Background())
	}()

	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("readyz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "ready" {
		t.Errorf("readyz status = %v, want ready", result["status"])
	}
}

func TestHealthServerStats(t *testing.T) {
	srv, err := NewSecuredMCPServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}

	hs := newHealthServer("127.0.0.1:0", srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := newHealthListener(hs)
	if err != nil {
		t.Fatalf("failed to start health server: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		hs.httpSrv.Shutdown(context.Background())
	}()

	resp, err := http.Get("http://" + addr + "/stats")
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("stats status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if _, ok := result["tools_registered"]; !ok {
		t.Errorf("stats missing tools_registered field")
	}
	if _, ok := result["active_sessions"]; !ok {
		t.Errorf("stats missing active_sessions field")
	}
	if _, ok := result["policy_rules"]; !ok {
		t.Errorf("stats missing policy_rules field")
	}
}

func TestHealthServerNilServer(t *testing.T) {
	hs := newHealthServer("127.0.0.1:0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := newHealthListener(hs)
	if err != nil {
		t.Fatalf("failed to start health server: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		hs.httpSrv.Shutdown(context.Background())
	}()

	// /readyz with nil server → 503
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("readyz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("readyz with nil server status = %d, want 503", resp.StatusCode)
	}

	// /stats with nil server → 503
	resp2, err := http.Get("http://" + addr + "/stats")
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("stats with nil server status = %d, want 503", resp2.StatusCode)
	}
}

func TestHealthServerStart(t *testing.T) {
	srv, err := NewSecuredMCPServer(DefaultServerConfig())
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}

	hs := newHealthServer("127.0.0.1:0", srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hs.start(ctx); err != nil {
		t.Fatalf("health server start: %v", err)
	}

	// Give the goroutine time to start serving
	time.Sleep(50 * time.Millisecond)

	// Make a request using the discovered address
	resp, err := http.Get("http://" + hs.lnAddr + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
}

// newHealthListener starts the health server's listener and returns it.
// This is a test helper that replaces the normal start() flow.
func newHealthListener(hs *healthServer) (net.Listener, error) {
	// Import net lazily — we need it here
	return startHealthListener(hs)
}

// ============================================================
// ServeOptions Tests
// ============================================================

func TestDefaultServeOptions(t *testing.T) {
	opts := DefaultServeOptions()
	if opts.Transport != "tcp" {
		t.Errorf("default transport = %s, want tcp", opts.Transport)
	}
	if opts.HealthAddr != "" {
		t.Errorf("default health addr = %s, want empty", opts.HealthAddr)
	}
}

func TestServeWithOptionsInvalidTransport(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuditLogPath = ""

	err := ServeWithOptions(cfg, &ServeOptions{
		Transport: "invalid",
	})
	if err == nil {
		t.Fatal("ServeWithOptions should fail with invalid transport")
	}
	if !strings.Contains(err.Error(), "unknown transport") {
		t.Errorf("error should mention unknown transport, got: %v", err)
	}
}

func TestServeWithOptionsStdio(t *testing.T) {
	// This is hard to test fully without stdin, but we can test that
	// it doesn't panic on init. We'll cancel via context.
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuditLogPath = ""

	// Override stdin with empty reader → immediate EOF
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close() // close write end so stdin is at EOF immediately

	err := ServeWithOptions(cfg, &ServeOptions{
		Transport: "stdio",
	})
	if err != nil {
		t.Errorf("ServeWithOptions stdio should return nil on EOF, got: %v", err)
	}
}

// ============================================================
// Config File Tests
// ============================================================

func TestLoadConfigFile(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.json"

	configJSON := `{
		"Address": "127.0.0.1:19000",
		"AuthToken": "test-config-token",
		"MaxSessions": 25,
		"RateLimitRPM": 100,
		"ScanResponses": true,
		"BlockOnPII": false,
		"BlockOnSecrets": true,
		"RedactEnabled": true,
		"RedactPII": true,
		"RedactPlaceholder": "[SCRUBBED]",
		"TLSEnabled": false,
		"ExecTimeout": 60000000000
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg := DefaultServerConfig()
	if err := loadConfigFileForTest(cfg, configPath); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}

	if cfg.Address != "127.0.0.1:19000" {
		t.Errorf("Address = %s, want 127.0.0.1:19000", cfg.Address)
	}
	if cfg.AuthToken != "test-config-token" {
		t.Errorf("AuthToken = %s, want test-config-token", cfg.AuthToken)
	}
	if cfg.MaxSessions != 25 {
		t.Errorf("MaxSessions = %d, want 25", cfg.MaxSessions)
	}
	if cfg.RateLimitRPM != 100 {
		t.Errorf("RateLimitRPM = %d, want 100", cfg.RateLimitRPM)
	}
	if cfg.BlockOnPII != false {
		t.Errorf("BlockOnPII = %v, want false", cfg.BlockOnPII)
	}
	if cfg.RedactEnabled != true {
		t.Errorf("RedactEnabled = %v, want true", cfg.RedactEnabled)
	}
	if cfg.RedactPlaceholder != "[SCRUBBED]" {
		t.Errorf("RedactPlaceholder = %s, want [SCRUBBED]", cfg.RedactPlaceholder)
	}
	if cfg.ExecTimeout != 60*time.Second {
		t.Errorf("ExecTimeout = %v, want 60s", cfg.ExecTimeout)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	cfg := DefaultServerConfig()
	err := loadConfigFileForTest(cfg, "/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("should fail on nonexistent config file")
	}
}

func TestLoadConfigFileInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/bad.json"
	os.WriteFile(configPath, []byte("{invalid json}"), 0644)

	cfg := DefaultServerConfig()
	err := loadConfigFileForTest(cfg, configPath)
	if err == nil {
		t.Fatal("should fail on invalid JSON")
	}
}

func TestLoadConfigFilePartialOverride(t *testing.T) {
	// Config file only sets some fields — others should keep defaults
	tmpDir := t.TempDir()
	configPath := tmpDir + "/partial.json"

	configJSON := `{
		"Address": "127.0.0.1:19001",
		"AuthToken": "partial-token"
	}`

	os.WriteFile(configPath, []byte(configJSON), 0644)

	cfg := DefaultServerConfig()
	originalMaxSessions := cfg.MaxSessions
	originalScan := cfg.ScanResponses

	if err := loadConfigFileForTest(cfg, configPath); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}

	if cfg.Address != "127.0.0.1:19001" {
		t.Errorf("Address = %s, want 127.0.0.1:19001", cfg.Address)
	}
	if cfg.AuthToken != "partial-token" {
		t.Errorf("AuthToken = %s, want partial-token", cfg.AuthToken)
	}
	// Unset fields should keep defaults
	if cfg.MaxSessions != originalMaxSessions {
		t.Errorf("MaxSessions = %d, want %d (default)", cfg.MaxSessions, originalMaxSessions)
	}
	if cfg.ScanResponses != originalScan {
		t.Errorf("ScanResponses = %v, want %v (default)", cfg.ScanResponses, originalScan)
	}
}

// loadConfigFileForTest is a test wrapper that calls the same logic
// as main.loadConfigFile but within the mcpsecurity package.
func loadConfigFileForTest(cfg *ServerConfigV2, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, cfg)
}
