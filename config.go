// SPDX-License-Identifier: Apache-2.0
// Config — configuration for the standalone MCP security server.
// Replaces the platform's tier system with a simple, flat config.

package mcpsecurity

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

// ServerConfigV2 is the top-level configuration for the MCP security server.
// It replaces the platform's tier-based config with simple, flat values.
type ServerConfigV2 struct {
	// Network
	Address string // Listen address (default ":8081")

	// Connections
	MaxConnections int // Max concurrent TCP connections (default 1000, -1 = unlimited)

	// Auth
	AuthToken string            // Global bearer token (if empty, no token auth)
	APIKeys   map[string]string // agentID → apiKey

	// Sessions
	MaxSessions    int
	SessionTimeout time.Duration

	// Guardrails
	MaxToolsPerSession int
	ExecTimeout        time.Duration
	RateLimitRPM       int

	// Response scanning
	ScanResponses       bool
	BlockOnPII          bool
	BlockOnSecrets      bool
	BlockOnXSS          bool
	BlockOnPromptInject bool

	// Secret redaction (alternative to blocking — scrubs sensitive data
	// from responses instead of blocking them entirely)
	RedactEnabled     bool
	RedactPII         bool
	RedactSecrets     bool
	RedactPlaceholder string

	// Audit
	AuditLogPath    string
	MaxAuditEntries int

	// STDIO validation
	EnableStdioValidation bool

	// TLS/mTLS transport (for OT/ICS encrypted connections)
	TLSEnabled      bool
	TLSCertFile     string // server certificate (PEM)
	TLSKeyFile      string // server private key (PEM)
	TLSClientCAFile string // CA bundle for client certs (enables mTLS)
	TLSMinVersion   string // "1.2" or "1.3" (default "1.2")

	// ML threat detection (Char CNN-BiLSTM, v13 model).
	// When enabled, the neural detector runs as L3 behind the regex
	// scanner (L1) and ATLAS compliance (L2). It catches semantic attacks
	// and evasion variants that regex cannot detect.
	// Requires CGO_ENABLED=1 build; falls back to heuristic-only when
	// CGO is disabled.
	MLEnabled bool
	// MLShadowMode logs predictions but never blocks. Use for 7-day
	// calibration before enabling blocking.
	MLShadowMode bool
	// MLThreshold is the score above which content is classified as
	// adversarial. Default: 0.50 (calibrated for 0% FPR).
	MLThreshold float64
	// MLModelPath is the path to the ONNX model file. If empty, uses
	// the vendored model at ./models/threat_cnn_bilstm.onnx.
	MLModelPath string

	// DemoTools registers three example tools (ping, system_info, echo)
	// on startup. Useful for testing and demonstration.
	DemoTools bool

	// TestAgent registers a restricted-role agent with access to demo tools
	// only. Used for pentesting and integration testing. The agent ID is
	// "authenticated" (the default agent ID when bearer token auth succeeds
	// without an explicit agentId in the initialize params).
	TestAgent bool
}

// DefaultServerConfig returns sensible defaults for an OT/ICS MCP server.
func DefaultServerConfig() *ServerConfigV2 {
	return &ServerConfigV2{
		Address:               ":8081",
		MaxConnections:        1000,
		MaxSessions:           50,
		SessionTimeout:        1 * time.Hour,
		MaxToolsPerSession:    100,
		ExecTimeout:           30 * time.Second,
		RateLimitRPM:          60,
		ScanResponses:         true,
		BlockOnPII:            true,
		BlockOnSecrets:        true,
		BlockOnXSS:            true,
		BlockOnPromptInject:   true,
		MaxAuditEntries:       10000,
		EnableStdioValidation: true,
	}
}

// ToGuardrailConfig converts to guardrail config.
func (c *ServerConfigV2) ToGuardrailConfig() *GuardrailConfig {
	return &GuardrailConfig{
		MaxSessions:        c.MaxSessions,
		MaxToolsPerSession: c.MaxToolsPerSession,
		ExecTimeout:        c.ExecTimeout,
		RateLimitRPM:       c.RateLimitRPM,
		Enabled:            true,
	}
}

// ToSessionConfig converts to session config.
func (c *ServerConfigV2) ToSessionConfig() *SessionConfig {
	return &SessionConfig{
		MaxSessions:    c.MaxSessions,
		SessionTimeout: c.SessionTimeout,
		CleanupPeriod:  5 * time.Minute,
	}
}

// ToAuthConfig converts to auth config.
func (c *ServerConfigV2) ToAuthConfig() *AuthConfig {
	return &AuthConfig{
		BearerToken:     c.AuthToken,
		APIKeys:         c.APIKeys,
		SessionExpiry:   c.SessionTimeout,
		MaxAuthAttempts: 5,
	}
}

// BuildTLSConfig builds a *tls.Config from the server config.
// Returns nil if TLS is not enabled. If TLSClientCAFile is set,
// mutual TLS (client cert verification) is enabled.
func (c *ServerConfigV2) BuildTLSConfig() (*tls.Config, error) {
	if !c.TLSEnabled {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	minVer := tls.VersionTLS12
	switch c.TLSMinVersion {
	case "1.3":
		minVer = tls.VersionTLS13
	case "1.2", "":
		minVer = tls.VersionTLS12
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   uint16(minVer),
	}

	// mTLS: require client certificates
	if c.TLSClientCAFile != "" {
		caCert, err := os.ReadFile(c.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificates from %s", c.TLSClientCAFile)
		}
		cfg.ClientCAs = caPool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}
