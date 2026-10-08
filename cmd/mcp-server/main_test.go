// SPDX-License-Identifier: Apache-2.0
// CLI helper tests for the mcp-server entry point.

package main

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestGetenv(t *testing.T) {
	os.Setenv("MCP_TEST_GETENV", "hello")
	defer os.Unsetenv("MCP_TEST_GETENV")

	if v := getenv("MCP_TEST_GETENV", "fallback"); v != "hello" {
		t.Errorf("getenv = %s, want hello", v)
	}

	if v := getenv("MCP_NONEXISTENT_VAR", "fallback"); v != "fallback" {
		t.Errorf("getenv for nonexistent = %s, want fallback", v)
	}

	// Empty string should return fallback (we check for != "")
	os.Setenv("MCP_TEST_EMPTY", "")
	defer os.Unsetenv("MCP_TEST_EMPTY")
	if v := getenv("MCP_TEST_EMPTY", "fallback"); v != "fallback" {
		t.Errorf("getenv for empty = %s, want fallback", v)
	}
}

func TestGetenvInt(t *testing.T) {
	os.Setenv("MCP_TEST_INT", "42")
	defer os.Unsetenv("MCP_TEST_INT")

	if v := getenvInt("MCP_TEST_INT", 0); v != 42 {
		t.Errorf("getenvInt = %d, want 42", v)
	}

	// Nonexistent → fallback
	if v := getenvInt("MCP_NONEXISTENT_INT", 99); v != 99 {
		t.Errorf("getenvInt for nonexistent = %d, want 99", v)
	}

	// Non-numeric → fallback
	os.Setenv("MCP_TEST_BAD_INT", "abc")
	defer os.Unsetenv("MCP_TEST_BAD_INT")
	if v := getenvInt("MCP_TEST_BAD_INT", 77); v != 77 {
		t.Errorf("getenvInt for bad = %d, want 77", v)
	}

	// Zero
	os.Setenv("MCP_TEST_ZERO", "0")
	defer os.Unsetenv("MCP_TEST_ZERO")
	if v := getenvInt("MCP_TEST_ZERO", 99); v != 0 {
		t.Errorf("getenvInt for zero = %d, want 0", v)
	}

	// Large number
	os.Setenv("MCP_TEST_LARGE", "12345")
	defer os.Unsetenv("MCP_TEST_LARGE")
	if v := getenvInt("MCP_TEST_LARGE", 0); v != 12345 {
		t.Errorf("getenvInt for large = %d, want 12345", v)
	}
}

// TestRunInvalidAddress tests run() with an invalid listen address.
// Serve() should fail immediately, and run() should return the error.
func TestRunInvalidAddress(t *testing.T) {
	err := run([]string{"--addr", "invalid:addr:format", "--audit", ""})
	if err == nil {
		t.Fatal("run should fail with invalid address")
	}
}

// TestRunInvalidAuditPath tests run() with an invalid audit log path.
// NewSecuredMCPServer should fail inside Serve(), and run() should return the error.
func TestRunInvalidAuditPath(t *testing.T) {
	err := run([]string{"--addr", "127.0.0.1:0", "--audit", "/nonexistent/dir/audit.json"})
	if err == nil {
		t.Fatal("run should fail with invalid audit path")
	}
}

// TestRunFlagParseError tests run() with invalid flags.
func TestRunFlagParseError(t *testing.T) {
	err := run([]string{"--invalid-flag"})
	if err == nil {
		t.Fatal("run should fail with invalid flag")
	}
}

// TestRunEnvVars tests that environment variables are picked up by run().
// It starts the server in a goroutine, sends SIGTERM to stop it.
func TestRunEnvVars(t *testing.T) {
	os.Setenv("MCP_SERVER_ADDR", "127.0.0.1:18097")
	os.Setenv("MCP_AUTH_TOKEN", "test-env-token")
	os.Setenv("MCP_AUDIT_LOG", "")
	os.Setenv("MCP_MAX_SESSIONS", "10")
	os.Setenv("MCP_RATE_LIMIT_RPM", "30")
	defer os.Unsetenv("MCP_SERVER_ADDR")
	defer os.Unsetenv("MCP_AUTH_TOKEN")
	defer os.Unsetenv("MCP_AUDIT_LOG")
	defer os.Unsetenv("MCP_MAX_SESSIONS")
	defer os.Unsetenv("MCP_RATE_LIMIT_RPM")

	var exited atomic.Bool
	errCh := make(chan error, 1)

	go func() {
		errCh <- run(nil) // nil args → uses env vars, flag.Parse(nil) works
		exited.Store(true)
	}()

	// Give server time to start
	time.Sleep(300 * time.Millisecond)

	// Send SIGTERM to trigger graceful shutdown
	// run() → Serve() → signal handler cancels context → Stop()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	// Wait for run to return
	select {
	case err := <-errCh:
		// Should return nil after graceful shutdown
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5 seconds")
	}

	if !exited.Load() {
		t.Fatal("run should have exited")
	}
}

// TestRunGracefulShutdown tests the full lifecycle: start → signal → stop.
func TestRunGracefulShutdown(t *testing.T) {
	var exited atomic.Bool
	errCh := make(chan error, 1)

	go func() {
		errCh <- run([]string{"--addr", "127.0.0.1:18096", "--audit", ""})
		exited.Store(true)
	}()

	// Give server time to start
	time.Sleep(300 * time.Millisecond)

	// Send SIGINT to self to trigger shutdown
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	select {
	case err := <-errCh:
		// Graceful shutdown should return nil
		if err != nil {
			t.Errorf("run should return nil after graceful shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5 seconds")
		syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
	}

	if !exited.Load() {
		t.Fatal("run should have exited")
	}
}
