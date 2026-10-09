// SPDX-License-Identifier: Apache-2.0
// MCP Security Server — main entry point.
// Standalone secured MCP server with built-in security layers.
// Zero external Go dependencies. Go standard library only. Air-gapped capable.
// ML inference (optional, CGO_ENABLED=1) uses vendored onnxruntime_go.

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aegisgatesecurity/aegisgate-mcp/internal/ml"
)

// SecuredMCPServer is the complete standalone MCP server with all security layers.
type SecuredMCPServer struct {
	config       *ServerConfigV2
	server       *Server
	handler      *RequestHandler
	guardrails   *GuardrailMiddleware
	scanner      *ContentScanner
	authMgr      *AuthManager
	sigVerifier  *SignatureVerifier
	stdioGuard   *StdioValidator
	auditLogger  *AuditLoggerImpl
	sessionMgr   *InMemorySessionManager
	rbacMgr      *RBACManager
	policyEngine *PolicyEngine
	// L3: Neural threat detector (Char CNN-BiLSTM v13).
	// Catches semantic attacks and evasion variants that regex (L1) misses.
	// Nil when ML is disabled or CGO is unavailable.
	threatDetector *ml.ThreatDetector
	// Evasion detector: detects encoding/splitting/obfuscation techniques.
	evasionDetector *ml.EvasionDetector
	// ML inference throttle — rate-limits ML detection to prevent
	// standalone server from being used as high-throughput ML API.
	mlThrottle *ml.Throttle
}

// NewSecuredMCPServer creates a new secured MCP server with all security layers.
func NewSecuredMCPServer(cfg *ServerConfigV2) (*SecuredMCPServer, error) {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}

	// Audit logger
	auditLogger, err := NewAuditLogger(cfg.AuditLogPath, cfg.MaxAuditEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Session manager
	sessionMgr := NewInMemorySessionManager(cfg.ToSessionConfig())

	// RBAC manager
	rbacMgr := NewRBACManager()

	// Policy engine (wraps RBAC for fine-grained rules)
	policyEngine := NewPolicyEngine()

	// Auth manager
	authMgr := NewAuthManager(cfg.ToAuthConfig())

	// Wire auth success callback: create RBAC session on successful auth.
	// The session ID is stored on the connection so the RBAC authorizer
	// can look it up for tool call authorization.
	authMgr.OnAuthSuccess = func(connID, agentID string) string {
		sid, err := rbacMgr.CreateSession(agentID)
		if err != nil {
			slog.Warn("failed to create RBAC session", "agentID", agentID, "error", err)
			return ""
		}
		return sid
	}

	// Signature verifier
	sigVerifier := NewSignatureVerifier()

	// STDIO validator
	stdioGuard := NewStdioValidator()

	// Content scanner
	scanner := NewContentScanner()

	// Request handler with RBAC authorizer wrapped by policy engine
	handler := NewRequestHandler(nil, auditLogger, sessionMgr)
	rbacAuth := NewRBACAuthorizer(rbacMgr)
	policyAuth := NewPolicyAuthorizer(policyEngine, rbacAuth, handler.Registry)
	handler.Authorizer = policyAuth
	handler.ExecTimeout = cfg.ExecTimeout
	if cfg.EnableStdioValidation {
		handler.StdioValidator = stdioGuard
	}

	// Input scanner: scan tool parameters for prompt injection (defense-in-depth)
	if cfg.ScanResponses {
		handler.InputScanner = scanner
	}

	// L3: Neural threat detector (Char CNN-BiLSTM v13).
	// Catches semantic attacks and evasion variants that regex (L1) misses.
	// Falls back to heuristic-only when CGO is disabled (no ONNX runtime).
	var threatDetector *ml.ThreatDetector
	var evasionDetector *ml.EvasionDetector
	if cfg.MLEnabled || cfg.MLShadowMode {
		mlCfg := ml.DefaultDetectorConfig()
		mlCfg.Enabled = cfg.MLEnabled
		mlCfg.ShadowMode = cfg.MLShadowMode
		if cfg.MLThreshold > 0 {
			mlCfg.Threshold = cfg.MLThreshold
		} else {
			mlCfg.Threshold = 0.50 // calibrated for 0% FPR
		}
		if cfg.MLModelPath != "" {
			mlCfg.ModelPath = cfg.MLModelPath
		} else {
			// Default: vendored model in ./models/
			absPath, _ := filepath.Abs("models/threat_cnn_bilstm.onnx")
			mlCfg.ModelPath = absPath
		}
		threatDetector = ml.NewThreatDetector(mlCfg)
		if err := threatDetector.LoadModel(mlCfg.ModelPath); err != nil {
			slog.Warn("ML model load failed, falling back to heuristic-only",
				"error", err, "path", mlCfg.ModelPath)
			// Detector still works — heuristic fallback is active
		} else {
			slog.Info("ML threat detector loaded",
				"model", mlCfg.ModelPath, "threshold", mlCfg.Threshold,
				"shadow_mode", mlCfg.ShadowMode)
		}
		evasionDetector = ml.NewEvasionDetector()
	}

	// Wire ML threat detector to handler for input parameter scanning
	// ML inference throttle — caps ML detection throughput to prevent
	// standalone server from being used as org-wide ML API. Graceful
	// degradation: when throttled, ML is skipped and L1/L2 heuristics
	// handle detection (same as non-CGO build).
	var mlThrottle *ml.Throttle
	if threatDetector != nil {
		mlThrottle = ml.NewThrottle(ml.ThrottleConfig{
			MaxPerMinute:   cfg.MLMaxPerMinute,
			MaxBurstPerSec: cfg.MLMaxBurstPerSec,
			MaxConcurrent:  cfg.MLMaxConcurrent,
		})
		handler.ThreatDetector = threatDetector
	}

	// Guardrails
	guardrails := NewGuardrailMiddleware(cfg.ToGuardrailConfig(), handler.Registry)

	// Build server
	srv := &SecuredMCPServer{
		config:          cfg,
		handler:         handler,
		guardrails:      guardrails,
		scanner:         scanner,
		authMgr:         authMgr,
		sigVerifier:     sigVerifier,
		stdioGuard:      stdioGuard,
		auditLogger:     auditLogger,
		sessionMgr:      sessionMgr,
		rbacMgr:         rbacMgr,
		policyEngine:    policyEngine,
		threatDetector:  threatDetector,
		evasionDetector: evasionDetector,
		mlThrottle:      mlThrottle,
	}

	// Wire the handler chain: auth → guardrails → response scan → handler
	srv.wireHandlerChain()

	// Register demo tools if enabled
	if cfg.DemoTools {
		if err := RegisterDemoTools(srv); err != nil {
			return nil, fmt.Errorf("failed to register demo tools: %w", err)
		}
	}

	// Register test agent if enabled (for pentesting)
	// The agent ID "authenticated" matches the default agent ID assigned
	// when bearer token auth succeeds without an explicit agentId.
	if cfg.TestAgent {
		srv.RegisterAgent("authenticated", "Test Agent (restricted)", RoleRestricted,
			[]ToolPermission{
				ToolPermission("tool:ping"),
				ToolPermission("tool:echo"),
				ToolPermission("tool:system_info"),
			})
		slog.Info("test agent registered", "agent_id", "authenticated", "role", "restricted")
	}

	return srv, nil
}

// wireHandlerChain sets up the middleware chain:
// auth → signature verification → guardrails → response scan → core handler
func (s *SecuredMCPServer) wireHandlerChain() {
	// Start with the core handler
	var chain HandlerFunc = func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return s.handler.HandleRequest(conn, req)
	}

	// Wrap with response scanning
	if s.config.ScanResponses {
		chain = s.wrapWithResponseScan(chain)
	}

	// Wrap with guardrails
	chain = s.guardrails.GuardrailHandler(chain)

	// Wrap with signature verification
	chain = s.wrapWithSignatureVerification(chain)

	// Wrap with auth
	chain = s.authMgr.AuthMiddleware(chain)

	// Set on server
	tlsCfg, err := s.config.BuildTLSConfig()
	if err != nil {
		slog.Error("TLS config error", "error", err)
	}
	s.server = NewServer(&ServerConfig{
		Address:        s.config.Address,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    5 * time.Minute,
		MaxConnections: s.config.MaxConnections,
		TLSConfig:      tlsCfg,
	})
	s.server.SetHandleFunc(chain)
}

// wrapWithSignatureVerification wraps a handler with ECDSA P-256 signature
// verification. If a request carries a KeyID and Signature, the signature is
// verified against the trusted key store. Unsigned requests pass through
// (access control is handled by AuthMiddleware).
func (s *SecuredMCPServer) wrapWithSignatureVerification(inner HandlerFunc) HandlerFunc {
	return func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		if s.sigVerifier.Enabled() && req.KeyID != "" && req.Signature != "" {
			var connAddr net.Addr
			if conn != nil && conn.Conn != nil {
				connAddr = conn.Conn.RemoteAddr()
			}
			if err := s.sigVerifier.VerifyRequest(req, connAddr); err != nil {
				slog.Warn("signature verification rejected request",
					"keyId", req.KeyID, "error", err)
				return &JSONRPCResponse{
					JSONRPC: JSONRPCVersion, ID: req.ID,
					Error: &JSONRPCError{Code: ErrorForbidden, Message: "signature verification failed"},
				}
			}
		}
		return inner(conn, req)
	}
}

// wrapWithResponseScan wraps a handler with response scanning.
func (s *SecuredMCPServer) wrapWithResponseScan(inner HandlerFunc) HandlerFunc {
	return func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		resp := inner(conn, req)

		// Only scan tool call results
		if req.Method != "tools/call" && req.Method != "tool/call" {
			return resp
		}
		if resp.Error != nil {
			return resp
		}

		// Extract text from response
		text := extractResponseText(resp)
		if text == "" {
			return resp
		}

		// Skip scanning for error responses (IsError=true). These are tool
		// call denials, validation errors, or timeouts — not tool output.
		// Scanning them causes false positives (e.g., connection IDs in
		// denial messages matching credit card patterns).
		if isToolResultError(resp) {
			return resp
		}

		// Cap scan input to prevent regex DoS on very large tool outputs.
		// Precompiled regex on short strings is fast — the risk is a tool
		// returning a multi-MB document (e.g., database dump) that causes
		// expensive regex backtracking. We scan the first 64KB; if a PII
		// or secret payload is beyond that, it's in non-header content
		// that's less likely to be exfiltrated in a single response.
		const maxScanSize = 64 * 1024 // 64KB
		scanText := text
		if len(scanText) > maxScanSize {
			scanText = scanText[:maxScanSize]
		}

		// Scan the response
		result := s.scanner.ScanResponse(scanText,
			s.config.BlockOnPII, s.config.BlockOnSecrets,
			s.config.BlockOnXSS, s.config.BlockOnPromptInject)

		if result.Blocked {
			slog.Warn("response blocked by scanner",
				"reason", result.Reason,
				"pii", result.PIICount, "secrets", result.SecretCount,
				"xss", result.XSSCount, "prompt", result.PromptCount)
			// Replace response with a blocked message
			return &JSONRPCResponse{
				JSONRPC: JSONRPCVersion, ID: req.ID,
				Result: CallToolResult{
					Content: []ContentBlock{{Type: "text", Text: "Response blocked by security policy: " + result.Reason}},
					IsError: true,
				},
			}
		}

		// Redact sensitive data instead of blocking (if enabled)
		if s.config.RedactEnabled && !result.Blocked {
			redactCfg := &RedactConfig{
				Enabled:       true,
				RedactPII:     s.config.RedactPII,
				RedactSecrets: s.config.RedactSecrets,
				Placeholder:   s.config.RedactPlaceholder,
			}
			redactedText := s.scanner.Redact(text, redactCfg)
			if redactedText != text {
				slog.Info("response redacted",
					"pii", result.PIICount, "secrets", result.SecretCount)
				return &JSONRPCResponse{
					JSONRPC: JSONRPCVersion, ID: req.ID,
					Result: CallToolResult{
						Content: []ContentBlock{{Type: "text", Text: redactedText}},
					},
				}
			}
		}

		if result.PIICount > 0 || result.SecretCount > 0 {
			slog.Info("response scan findings (not blocked)",
				"pii", result.PIICount, "secrets", result.SecretCount,
				"xss", result.XSSCount, "prompt", result.PromptCount)
		}

		// L3: Neural threat detection (Char CNN-BiLSTM v13).
		// Runs AFTER regex scanner (L1/L2) to catch semantic attacks and
		// evasion variants that regex cannot detect. Only runs when L1/L2
		// didn't already block — it's supplementary, not overriding.
		// Two-tier blocking (same as Platform):
		//   Tier 1 (score ≥ 0.95): Block independently, no corroboration needed.
		//   Tier 2 (score ≥ 0.50): Block only with L1/L2 corroboration.
		// In shadow mode, logs predictions but never blocks.
		if s.threatDetector != nil && s.threatDetector.IsEnabled() {
			// ML throttle: check if inference is allowed under scale gates.
			// When throttled, gracefully skip ML (L3) and rely on L1/L2
			// heuristics — same security posture as non-CGO build.
			var mlResult *ml.ThreatScore
			if s.mlThrottle != nil && s.mlThrottle.Allow(time.Now()) {
				score := s.threatDetector.Detect(scanText)
				mlResult = &score
				s.mlThrottle.Release()
			} else {
				// ML throttled — log and meter the degradation
				slog.Warn("ML inference throttled, falling back to L1/L2 heuristics",
					"layer", "L3", "fallback", "L1+L2")
				if s.auditLogger != nil {
					_ = s.auditLogger.Log(context.Background(), &AuditEntry{
						Type: "ml_throttled",
					})
				}
				// Skip ML — L1/L2 results above already handle detection
			}
			if mlResult != nil && mlResult.IsThreat {
				const l3HighConfidence = 0.95
				if mlResult.Score >= l3HighConfidence {
					slog.Warn("ML threat detector blocked response (high confidence)",
						"score", mlResult.Score, "threshold", mlResult.Threshold,
						"tier", "L3-high-confidence", "model", mlResult.ModelVersion)
					return &JSONRPCResponse{
						JSONRPC: JSONRPCVersion, ID: req.ID,
						Result: CallToolResult{
							Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf(
								"Response blocked by neural threat detector (score: %.3f, high confidence)", mlResult.Score)}},
							IsError: true,
						},
					}
				}
				// Tier 2: requires L1/L2 corroboration
				hasCorroboration := result.PIICount > 0 || result.SecretCount > 0 ||
					result.XSSCount > 0 || result.PromptCount > 0
				if hasCorroboration {
					slog.Warn("ML threat detector blocked response (with corroboration)",
						"score", mlResult.Score, "threshold", mlResult.Threshold,
						"tier", "L3-corroborated", "model", mlResult.ModelVersion)
					return &JSONRPCResponse{
						JSONRPC: JSONRPCVersion, ID: req.ID,
						Result: CallToolResult{
							Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf(
								"Response blocked by neural threat detector (score: %.3f, corroborated)", mlResult.Score)}},
							IsError: true,
						},
					}
				}
				slog.Info("ML threat detector alert (no corroboration, not blocked)",
					"score", mlResult.Score, "tier", "L3-alert-only")
			}
		}

		return resp
	}
}

func extractResponseText(resp *JSONRPCResponse) string {
	if resp.Result == nil {
		return ""
	}
	// Try to parse as CallToolResult
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return ""
	}
	var result CallToolResult
	if err := json.Unmarshal(data, &result); err != nil {
		return ""
	}
	var text string
	for _, block := range result.Content {
		if block.Type == "text" {
			text += block.Text + " "
		}
	}
	return text
}

// isToolResultError checks whether a JSONRPCResponse contains a CallToolResult
// with IsError=true. These are tool call denials, validation errors, or timeouts
// — not actual tool output — so they should not be scanned for PII/secrets.
func isToolResultError(resp *JSONRPCResponse) bool {
	if resp.Result == nil {
		return false
	}
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return false
	}
	var result CallToolResult
	if err := json.Unmarshal(data, &result); err != nil {
		return false
	}
	return result.IsError
}
func (s *SecuredMCPServer) RegisterTool(name, description string, riskLevel int, inputSchema map[string]interface{}) error {
	return s.handler.Registry.RegisterWithScanning(name, description, riskLevel, inputSchema, s.handler.ToolPoisoningScanner)
}

// RegisterToolHandler registers a handler function for a tool.
func (s *SecuredMCPServer) RegisterToolHandler(name string, handler ToolHandlerFunc) error {
	return s.handler.Registry.RegisterHandler(name, handler)
}

// RegisterResource registers an MCP resource with a handler function.
// Resources are server-side data that clients can read via resources/read.
func (s *SecuredMCPServer) RegisterResource(uri, name, description, mimeType string, handler ResourceHandlerFunc) error {
	return s.handler.ResourceReg.Register(uri, name, description, mimeType, handler)
}

// RegisterPrompt registers an MCP prompt template with a handler function.
// Prompts are server-side templates that clients can invoke via prompts/get.
func (s *SecuredMCPServer) RegisterPrompt(name, description string, args []PromptArgument, handler PromptHandlerFunc) error {
	return s.handler.PromptReg.Register(name, description, args, handler)
}

// RegisterResourceTemplate registers a URI template for parameterized resources.
func (s *SecuredMCPServer) RegisterResourceTemplate(uriTemplate, name, description, mimeType string) error {
	return s.handler.ResourceReg.RegisterTemplate(uriTemplate, name, description, mimeType)
}

// NotifyToolsListChanged sends a notifications/tools/list_changed to
// connected clients. Call this after dynamically adding or removing tools.
func (s *SecuredMCPServer) NotifyToolsListChanged() {
	s.handler.NotifyListChanged("tools")
}

// NotifyResourcesListChanged sends a notifications/resources/list_changed.
func (s *SecuredMCPServer) NotifyResourcesListChanged() {
	s.handler.NotifyListChanged("resources")
}

// NotifyPromptsListChanged sends a notifications/prompts/list_changed.
func (s *SecuredMCPServer) NotifyPromptsListChanged() {
	s.handler.NotifyListChanged("prompts")
}

// NotifyResourceUpdated sends a notifications/resources/updated to all
// sessions subscribed to the given URI. Call this when a resource's
// content changes.
func (s *SecuredMCPServer) NotifyResourceUpdated(uri string) {
	s.handler.NotifyResourceUpdated(uri)
}

// SetNotifyCallback sets the notification delivery callback. The transport
// layer calls this to wire server-initiated notifications to active SSE
// connections.
func (s *SecuredMCPServer) SetNotifyCallback(cb NotificationCallback) {
	s.handler.NotifyCallback = cb
}

// prompt injection or exfiltration patterns. Returns a *ToolPoisoningError
// if suspicious patterns are found, nil otherwise.
func (s *SecuredMCPServer) ScanToolForPoisoning(name, desc string, inputSchema map[string]interface{}) *ToolPoisoningError {
	if s.handler.ToolPoisoningScanner == nil {
		return nil
	}
	if err := validateToolNotPoisoned(s.handler.ToolPoisoningScanner, name, desc, inputSchema); err != nil {
		if tpe, ok := err.(*ToolPoisoningError); ok {
			return tpe
		}
	}
	return nil
}

// ReloadMLModel hot-swaps the ML threat detection model at runtime.
// The new model is integrity-checked (SHA-256) before loading. If the
// load fails, the existing model continues to serve — no disruption.
// Returns an error if ML is not enabled or the model path is invalid.
func (s *SecuredMCPServer) ReloadMLModel(path string) error {
	if s.threatDetector == nil {
		return fmt.Errorf("ML threat detector is not enabled")
	}
	if path == "" {
		path = s.config.MLModelPath
		if path == "" {
			absPath, _ := filepath.Abs("models/threat_cnn_bilstm.onnx")
			path = absPath
		}
	}
	return s.threatDetector.ReloadModel(path)
}

// RegisterAgent registers an agent with RBAC.
func (s *SecuredMCPServer) RegisterAgent(agentID, name string, role AgentRole, tools []ToolPermission) *Agent {
	return s.rbacMgr.RegisterAgent(agentID, name, role, tools)
}

// AddTrustedKey adds a trusted public key for signature verification.
func (s *SecuredMCPServer) AddTrustedKey(keyID string, pubKey []byte) {
	s.sigVerifier.AddTrustedKey(keyID, pubKey)
}

// AddPolicyRule adds a security policy rule to the policy engine.
func (s *SecuredMCPServer) AddPolicyRule(rule PolicyRule) {
	s.policyEngine.AddRule(rule)
}

// AddPolicy adds a named policy (collection of rules) to the policy engine.
func (s *SecuredMCPServer) AddPolicy(policy Policy) {
	s.policyEngine.AddPolicy(policy)
}

// LoadDefaultPolicies loads the built-in security rules.
func (s *SecuredMCPServer) LoadDefaultPolicies() {
	for _, rule := range DefaultPolicyRules() {
		s.policyEngine.AddRule(rule)
	}
}

// PolicyEngine returns the underlying policy engine for direct manipulation.
func (s *SecuredMCPServer) PolicyEngine() *PolicyEngine {
	return s.policyEngine
}

// Start begins listening for MCP connections.
func (s *SecuredMCPServer) Start(ctx context.Context) error {
	slog.Info("starting secured MCP server",
		"address", s.config.Address,
		"auth_enabled", s.config.AuthToken != "" || len(s.config.APIKeys) > 0,
		"tls_enabled", s.config.TLSEnabled,
		"mtls_enabled", s.config.TLSEnabled && s.config.TLSClientCAFile != "",
		"response_scan", s.config.ScanResponses,
		"redact_enabled", s.config.RedactEnabled,
		"stdio_guard", s.config.EnableStdioValidation,
		"ml_enabled", s.config.MLEnabled,
		"ml_shadow_mode", s.config.MLShadowMode,
		"tools_registered", s.handler.Registry.Count())
	return s.server.StartContext(ctx)
}

// Stop gracefully shuts down the server.
func (s *SecuredMCPServer) Stop() error {
	s.sessionMgr.Stop()
	if err := s.server.Stop(); err != nil {
		return err
	}
	return s.auditLogger.Close()
}

// Stats returns runtime statistics.
func (s *SecuredMCPServer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"tools_registered":     s.handler.Registry.Count(),
		"resources_registered": s.handler.ResourceReg.Count(),
		"prompts_registered":   s.handler.PromptReg.Count(),
		"active_sessions":      s.sessionMgr.ActiveCount(),
		"active_connections":   s.server.ConnectionCount(),
		"max_connections":      s.config.MaxConnections,
		"guardrails":           s.guardrails.Stats(),
		"audit_entries":        s.auditLogger.EntryCount(),
		"stdio_checks":         s.stdioGuard.Stats(),
		"trusted_keys":         s.sigVerifier.TrustedKeyCount(),
		"policy_rules":         s.policyEngine.RuleCount(),
		"ml_throttle":          s.mlThrottleStatsMap(),
	}
}

// MLThrottleStats returns ML inference throttle statistics, or nil if
// ML is not enabled. Useful for monitoring and determining when the
// standalone server's ML capacity is exhausted (upgrade to Platform).
func (s *SecuredMCPServer) MLThrottleStats() *ml.ThrottleStats {
	if s.mlThrottle == nil {
		return nil
	}
	stats := s.mlThrottle.Stats()
	return &stats
}

// mlThrottleStatsMap returns throttle stats as a map for the Stats() dict.
func (s *SecuredMCPServer) mlThrottleStatsMap() map[string]interface{} {
	if s.mlThrottle == nil {
		return nil
	}
	ts := s.mlThrottle.Stats()
	return map[string]interface{}{
		"total_allowed":     ts.TotalAllowed,
		"total_throttled":   ts.TotalThrottled,
		"current_in_flight": ts.CurrentInFlight,
	}
}

// Serve runs the server (TCP transport) until SIGINT or SIGTERM.
// This is the simple API — use ServeWithOptions for stdio transport or
// health endpoint support.
func Serve(cfg *ServerConfigV2) error {
	return ServeWithOptions(cfg, DefaultServeOptions())
}

// ServeWithOptions runs the server with full control over transport mode
// and optional health endpoint. Supports "tcp" and "stdio" transports.
// Runs until SIGINT or SIGTERM is received.
func ServeWithOptions(cfg *ServerConfigV2, opts *ServeOptions) error {
	if opts == nil {
		opts = DefaultServeOptions()
	}

	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Start health endpoint if configured
	if opts.HealthAddr != "" {
		hs := newHealthServer(opts.HealthAddr, srv)
		if err := hs.start(ctx); err != nil {
			return fmt.Errorf("health endpoint: %w", err)
		}
	}

	// Start transport
	switch opts.Transport {
	case "stdio":
		// For stdio, we need the handler chain. Build it the same way
		// wireHandlerChain does, but attach to stdio instead of TCP server.
		var chain HandlerFunc = func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
			return srv.handler.HandleRequest(conn, req)
		}
		if srv.config.ScanResponses {
			chain = srv.wrapWithResponseScan(chain)
		}
		chain = srv.guardrails.GuardrailHandler(chain)
		chain = srv.authMgr.AuthMiddleware(chain)

		transport := newStdioTransport(chain)

		// Run transport in a goroutine. When it exits (stdin closed / EOF),
		// cancel the context to trigger shutdown.
		transportDone := make(chan error, 1)
		go func() {
			transportDone <- transport.run(ctx)
		}()

		select {
		case <-ctx.Done():
			// Signal received
		case err := <-transportDone:
			// stdio transport finished (stdin closed) — trigger shutdown
			if err != nil {
				slog.Error("stdio transport error", "error", err)
			}
			cancel()
		}

		return srv.Stop()

	case "tcp", "":
		if err := srv.Start(ctx); err != nil {
			return err
		}
		// Wait for shutdown
		<-ctx.Done()
		return srv.Stop()

	case "http":
		// Streamable HTTP transport (MCP Spec 2025-06-18).
		// Builds the same handler chain as TCP mode but serves over HTTP.
		var chain HandlerFunc = func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
			return srv.handler.HandleRequest(conn, req)
		}
		if srv.config.ScanResponses {
			chain = srv.wrapWithResponseScan(chain)
		}
		chain = srv.guardrails.GuardrailHandler(chain)
		chain = srv.authMgr.AuthMiddleware(chain)

		transport := newStreamableHTTPTransport(cfg.Address, chain)

		// Wire the notification callback so server-initiated notifications
		// (list_changed, resources/updated) are delivered to active SSE
		// connections via the transport's broadcast mechanism.
		srv.SetNotifyCallback(transport.broadcastNotification)

		if err := transport.start(ctx); err != nil {
			return err
		}
		<-ctx.Done()
		return srv.Stop()

	default:
		return fmt.Errorf("unknown transport: %s (use tcp, stdio, or http)", opts.Transport)
	}
}
