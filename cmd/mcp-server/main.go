// SPDX-License-Identifier: Apache-2.0
// AegisGate MCP — standalone CLI entry point.
// For OT/ICS environments. Zero external dependencies. Air-gapped capable.
//
// Usage:
//   mcp-server [--addr :8081] [--token <bearer>] [--audit /var/log/mcp-audit.json]
//              [--config /path/to/config.json]
//
// Environment variables (override defaults; flags override env vars):
//   MCP_SERVER_ADDR          Listen address (default :8081)
//   MCP_AUTH_TOKEN           Bearer token for authentication
//   MCP_AUDIT_LOG            Audit log file path
//   MCP_MAX_SESSIONS         Max concurrent sessions (default 50)
//   MCP_RATE_LIMIT_RPM       Rate limit per minute (default 60)
//   MCP_EXEC_TIMEOUT         Tool execution timeout (seconds, default 30)
//   MCP_SCAN_RESPONSES       Enable response scanning (true/false, default true)
//   MCP_BLOCK_PII            Block responses with PII (default true)
//   MCP_BLOCK_SECRETS        Block responses with secrets (default true)
//   MCP_BLOCK_XSS            Block responses with XSS (default true)
//   MCP_BLOCK_PROMPT_INJECT  Block responses with prompt injection (default true)
//   MCP_REDACT_ENABLED       Enable secret/PII redaction (default false)
//   MCP_REDACT_PII           Redact PII from responses (default false)
//   MCP_REDACT_SECRETS       Redact secrets from responses (default true)
//   MCP_REDACT_PLACEHOLDER   Redaction placeholder text (default [REDACTED])
//   MCP_TLS_ENABLED          Enable TLS transport (default false)
//   MCP_TLS_CERT             Server certificate file (PEM)
//   MCP_TLS_KEY              Server private key file (PEM)
//   MCP_TLS_CLIENT_CA        CA bundle for client certs (enables mTLS)
//   MCP_TLS_MIN_VERSION      Minimum TLS version: 1.2 or 1.3 (default 1.2)
//   MCP_TRANSPORT            Transport mode: tcp or stdio (default tcp)
//   MCP_HEALTH_ADDR          Health endpoint listen address (empty = disabled)
//   MCP_DEMO_TOOLS           Register demo tools — ping, system_info, echo (default false)
//   MCP_TEST_AGENT           Register a test agent for pentesting (default false). When enabled,
//                            registers a "restricted" role agent with access to demo tools only.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	mcp "github.com/aegisgatesecurity/aegisgate-mcp"
)

// run is the testable entry point. main() calls run(os.Args[1:]).
// Returns the error so callers (including tests) can handle it.
func run(args []string) error {
	fs := flag.NewFlagSet("mcp-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configFile := fs.String("config", getenv("MCP_CONFIG_FILE", ""), "JSON config file path")

	// --- Network ---
	addr := fs.String("addr", getenv("MCP_SERVER_ADDR", ":8081"), "Listen address (TCP mode)")
	transport := fs.String("transport", getenv("MCP_TRANSPORT", "tcp"), "Transport mode: tcp, stdio, or http (Streamable HTTP, MCP 2025-06-18)")
	maxConn := fs.Int("max-connections", getenvInt("MCP_MAX_CONNECTIONS", 1000), "Max concurrent TCP connections (-1 = unlimited)")

	// --- Auth ---
	token := fs.String("token", getenv("MCP_AUTH_TOKEN", ""), "Bearer token for authentication")

	// --- Audit ---
	auditLog := fs.String("audit", getenv("MCP_AUDIT_LOG", ""), "Audit log file path")

	// --- Sessions ---
	maxSessions := fs.Int("max-sessions", getenvInt("MCP_MAX_SESSIONS", 50), "Max concurrent sessions")

	// --- Guardrails ---
	rateLimit := fs.Int("rate-limit", getenvInt("MCP_RATE_LIMIT_RPM", 60), "Rate limit (requests/min)")
	execTimeout := fs.Int("exec-timeout", getenvInt("MCP_EXEC_TIMEOUT", 30), "Tool execution timeout (seconds)")

	// --- Response scanning ---
	scanResponses := fs.Bool("scan-responses", getenvBool("MCP_SCAN_RESPONSES", true), "Enable response scanning")
	blockPII := fs.Bool("block-pii", getenvBool("MCP_BLOCK_PII", true), "Block responses containing PII")
	blockSecrets := fs.Bool("block-secrets", getenvBool("MCP_BLOCK_SECRETS", true), "Block responses containing secrets")
	blockXSS := fs.Bool("block-xss", getenvBool("MCP_BLOCK_XSS", true), "Block responses containing XSS")
	blockPrompt := fs.Bool("block-prompt-inject", getenvBool("MCP_BLOCK_PROMPT_INJECT", true), "Block responses containing prompt injection")

	// --- Redaction ---
	redactEnabled := fs.Bool("redact", getenvBool("MCP_REDACT_ENABLED", false), "Enable secret/PII redaction")
	redactPII := fs.Bool("redact-pii", getenvBool("MCP_REDACT_PII", false), "Redact PII from responses")
	redactSecrets := fs.Bool("redact-secrets", getenvBool("MCP_REDACT_SECRETS", true), "Redact secrets from responses")
	redactPlaceholder := fs.String("redact-placeholder", getenv("MCP_REDACT_PLACEHOLDER", "[REDACTED]"), "Redaction placeholder text")

	// --- TLS/mTLS ---
	tlsEnabled := fs.Bool("tls", getenvBool("MCP_TLS_ENABLED", false), "Enable TLS transport")
	tlsCert := fs.String("tls-cert", getenv("MCP_TLS_CERT", ""), "Server certificate file (PEM)")
	tlsKey := fs.String("tls-key", getenv("MCP_TLS_KEY", ""), "Server private key file (PEM)")
	tlsClientCA := fs.String("tls-client-ca", getenv("MCP_TLS_CLIENT_CA", ""), "CA bundle for client certs (enables mTLS)")
	tlsMinVer := fs.String("tls-min-version", getenv("MCP_TLS_MIN_VERSION", "1.2"), "Minimum TLS version: 1.2 or 1.3")

	// --- Health endpoint ---
	healthAddr := fs.String("health-addr", getenv("MCP_HEALTH_ADDR", ""), "Health endpoint listen address (empty = disabled)")

	// --- Demo tools ---
	demoTools := fs.Bool("demo", getenvBool("MCP_DEMO_TOOLS", false), "Register demo tools (ping, system_info, echo)")

	// --- Test agent (for pentesting) ---
	testAgent := fs.Bool("test-agent", getenvBool("MCP_TEST_AGENT", false), "Register a test agent for pentesting (restricted role, demo tools only)")

	// ML threat detection (Char CNN-BiLSTM v13)
	mlEnabled := fs.Bool("ml", getenvBool("MCP_ML_ENABLED", false), "Enable neural threat detection (L3, requires CGO build)")
	mlShadow := fs.Bool("ml-shadow", getenvBool("MCP_ML_SHADOW", false), "ML shadow mode: log predictions but never block")
	mlThreshold := fs.Float64("ml-threshold", getenvFloat("MCP_ML_THRESHOLD", 0.50), "ML threat score threshold (0.0-1.0)")
	mlModelPath := fs.String("ml-model", getenv("MCP_ML_MODEL", ""), "Path to ONNX model file (empty = ./models/threat_cnn_bilstm.onnx)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Start with defaults
	cfg := mcp.DefaultServerConfig()

	// Load JSON config file if specified (lowest priority — flags override)
	if *configFile != "" {
		if err := loadConfigFile(cfg, *configFile); err != nil {
			return fmt.Errorf("config file: %w", err)
		}
	}

	// Apply flags/env vars (override config file values)
	cfg.Address = *addr
	cfg.MaxConnections = *maxConn
	cfg.AuthToken = *token
	cfg.AuditLogPath = *auditLog
	cfg.MaxSessions = *maxSessions
	cfg.RateLimitRPM = *rateLimit
	cfg.ExecTimeout = time.Duration(*execTimeout) * time.Second
	cfg.ScanResponses = *scanResponses
	cfg.BlockOnPII = *blockPII
	cfg.BlockOnSecrets = *blockSecrets
	cfg.BlockOnXSS = *blockXSS
	cfg.BlockOnPromptInject = *blockPrompt
	cfg.RedactEnabled = *redactEnabled
	cfg.RedactPII = *redactPII
	cfg.RedactSecrets = *redactSecrets
	cfg.RedactPlaceholder = *redactPlaceholder
	cfg.TLSEnabled = *tlsEnabled
	cfg.TLSCertFile = *tlsCert
	cfg.TLSKeyFile = *tlsKey
	cfg.TLSClientCAFile = *tlsClientCA
	cfg.TLSMinVersion = *tlsMinVer
	cfg.DemoTools = *demoTools
	cfg.TestAgent = *testAgent
	cfg.MLEnabled = *mlEnabled
	cfg.MLShadowMode = *mlShadow
	cfg.MLThreshold = *mlThreshold
	cfg.MLModelPath = *mlModelPath

	// Transport mode and health endpoint are CLI-only (not in ServerConfigV2)
	opts := &mcp.ServeOptions{
		Transport:  *transport,
		HealthAddr: *healthAddr,
	}

	slog.Info("AegisGate MCP starting",
		"version", mcp.Version,
		"transport", opts.Transport,
		"address", cfg.Address,
		"auth_enabled", cfg.AuthToken != "",
		"audit_log", cfg.AuditLogPath,
		"tls_enabled", cfg.TLSEnabled,
		"redact_enabled", cfg.RedactEnabled,
		"health_addr", opts.HealthAddr)

	return mcp.ServeWithOptions(cfg, opts)
}

// loadConfigFile loads a JSON config file into the ServerConfigV2 struct.
// Fields in the config file override defaults but are themselves overridden
// by CLI flags and environment variables.
func loadConfigFile(cfg *mcp.ServerConfigV2, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// --- Environment variable helpers ---

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fallback
		}
		return n
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fallback
		}
		return b
	}
	return fallback
}

func getenvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fallback
		}
		return f
	}
	return fallback
}
