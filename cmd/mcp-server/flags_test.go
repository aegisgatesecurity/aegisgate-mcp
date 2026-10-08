// SPDX-License-Identifier: Apache-2.0
// Tests for new CLI flags (enhancements, config file, transport).

package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunConfigFile(t *testing.T) {
	// Create a temp config file with auth token
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.json"
	os.WriteFile(configPath, []byte(`{
		"Address": "127.0.0.1:18098",
		"AuthToken": "config-file-token"
	}`), 0644)

	// Run with --config flag — should pick up address and token from file
	errCh := make(chan error, 1)
	go func() {
		errCh <- run([]string{"--config", configPath, "--audit", ""})
	}()

	// Give it time to start, then kill
	time.Sleep(300 * time.Millisecond)

	// Send SIGTERM
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	select {
	case err := <-errCh:
		// Should be nil (graceful shutdown)
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5 seconds")
	}
}

func TestRunStdioTransport(t *testing.T) {
	// stdio transport with empty stdin → immediate exit
	// Override stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close()

	err := run([]string{"--transport", "stdio", "--audit", ""})
	if err != nil {
		t.Errorf("run with stdio transport should return nil on EOF, got: %v", err)
	}
}

func TestRunInvalidTransport(t *testing.T) {
	err := run([]string{"--transport", "invalid-transport", "--audit", ""})
	if err == nil {
		t.Fatal("run should fail with invalid transport")
	}
	if !strings.Contains(err.Error(), "unknown transport") {
		t.Errorf("error should mention unknown transport, got: %v", err)
	}
}

func TestRunConfigFileNotFound(t *testing.T) {
	err := run([]string{"--config", "/nonexistent/path/config.json"})
	if err == nil {
		t.Fatal("run should fail with nonexistent config file")
	}
	if !strings.Contains(err.Error(), "config file") {
		t.Errorf("error should mention config file, got: %v", err)
	}
}

func TestRunInvalidConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/bad.json"
	os.WriteFile(configPath, []byte("{not valid json}"), 0644)

	err := run([]string{"--config", configPath})
	if err == nil {
		t.Fatal("run should fail with invalid config file")
	}
}

func TestRunNewFlagsAccepted(t *testing.T) {
	// Verify all new flags are accepted without errors
	// Use stdio so it exits immediately on EOF
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close()

	err := run([]string{
		"--transport", "stdio",
		"--audit", "",
		"--exec-timeout", "60",
		"--max-connections", "500",
		"--scan-responses", "true",
		"--block-pii", "true",
		"--block-secrets", "true",
		"--block-xss", "true",
		"--block-prompt-inject", "true",
		"--redact", "false",
		"--redact-pii", "false",
		"--redact-secrets", "true",
		"--redact-placeholder", "[SCRUBBED]",
		"--tls", "false",
		"--tls-min-version", "1.2",
		"--health-addr", "",
		"--demo",
	})
	if err != nil {
		t.Errorf("run with all new flags should succeed, got: %v", err)
	}
}

func TestGetenvBool(t *testing.T) {
	os.Setenv("MCP_TEST_BOOL_TRUE", "true")
	defer os.Unsetenv("MCP_TEST_BOOL_TRUE")
	if v := getenvBool("MCP_TEST_BOOL_TRUE", false); v != true {
		t.Errorf("getenvBool(true) = %v, want true", v)
	}

	os.Setenv("MCP_TEST_BOOL_FALSE", "false")
	defer os.Unsetenv("MCP_TEST_BOOL_FALSE")
	if v := getenvBool("MCP_TEST_BOOL_FALSE", true); v != false {
		t.Errorf("getenvBool(false) = %v, want false", v)
	}

	// Nonexistent → fallback
	if v := getenvBool("MCP_NONEXISTENT_BOOL", true); v != true {
		t.Errorf("getenvBool(nonexistent) = %v, want true (fallback)", v)
	}

	// Invalid → fallback
	os.Setenv("MCP_TEST_BOOL_BAD", "notabool")
	defer os.Unsetenv("MCP_TEST_BOOL_BAD")
	if v := getenvBool("MCP_TEST_BOOL_BAD", true); v != true {
		t.Errorf("getenvBool(bad) = %v, want true (fallback)", v)
	}
}
