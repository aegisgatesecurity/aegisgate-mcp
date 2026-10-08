// SPDX-License-Identifier: Apache-2.0
// MCP Request Handler — processes JSON-RPC methods with authorization.
// Based on AegisGate Platform upstream handler.go + tool_registry.go

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-mcp/internal/ml"
)

// RequestHandler handles MCP protocol requests.
type RequestHandler struct {
	Authorizer     ToolAuthorizer
	AuditLogger    AuditLogger
	SessionMgr     SessionManager
	Registry       *ToolRegistry
	ExecTimeout    time.Duration   // max execution time per tool call (0 = no limit)
	StdioValidator *StdioValidator // if non-nil, scans tool params for shell injection
	InputScanner   *ContentScanner // if non-nil, scans tool params for prompt injection
	// L3: Neural threat detector for input scanning. If non-nil, scans
	// tool parameters for semantic attacks and evasion variants that
	// regex cannot detect.
	ThreatDetector *ml.ThreatDetector
}

// NewRequestHandler creates a new request handler.
func NewRequestHandler(authorizer ToolAuthorizer, auditLogger AuditLogger, sessionMgr SessionManager) *RequestHandler {
	return &RequestHandler{
		Authorizer:  authorizer,
		AuditLogger: auditLogger,
		SessionMgr:  sessionMgr,
		Registry:    NewToolRegistry(),
	}
}

// HandleRequest handles an MCP JSON-RPC request.
func (h *RequestHandler) HandleRequest(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	ctx := context.Background()
	switch req.Method {
	case "initialize":
		return h.handleInitialize(ctx, conn, req)
	case "notifications/initialized":
		return h.handleInitialized(ctx, conn, req)
	case "tools/list", "tool/list":
		return h.handleListTools(ctx, req)
	case "tools/call", "tool/call":
		return h.handleCallTool(ctx, conn, req)
	case "ping":
		return h.handlePing(req)
	case "resources/list", "resource/list":
		return h.handleListResources(req)
	case "resources/read", "resource/read":
		return h.handleReadResource(ctx, req)
	case "resources/subscribe":
		return h.handleSuccess(req.ID, map[string]interface{}{})
	case "resources/unsubscribe":
		return h.handleSuccess(req.ID, map[string]interface{}{})
	case "prompts/list", "prompt/list":
		return h.handleListPrompts(req)
	case "prompts/get", "prompt/get":
		return h.handleGetPrompt(ctx, req)
	case "logging/setLevel":
		return h.handleSetLogLevel(req)
	case "completion/complete":
		return h.handleComplete(req)
	default:
		return h.handleError(req.ID, ErrorMethodNotFound, "Method not found: "+req.Method)
	}
}

// initializeParams holds the parameters sent with an initialize request.
type initializeParams struct {
	ProtocolVersion string      `json:"protocolVersion,omitempty"`
	ClientInfo      *ClientInfo `json:"clientInfo,omitempty"`
	Capabilities    interface{} `json:"capabilities,omitempty"`
}

func (h *RequestHandler) handleInitialize(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	// Parse clientInfo from initialize params (MCP spec: client sends name + version)
	var clientName, clientVersion string
	if req.Params != nil && conn != nil {
		var params initializeParams
		if err := json.Unmarshal(req.Params, &params); err == nil {
			if params.ClientInfo != nil {
				clientName = params.ClientInfo.Name
				clientVersion = params.ClientInfo.Version
				conn.mu.Lock()
				conn.ClientInfo = params.ClientInfo
				conn.mu.Unlock()
			}
		}
	}

	if h.AuditLogger != nil {
		entry := &AuditEntry{Type: "initialize"}
		if conn != nil {
			entry.SessionID = conn.ID
		}
		h.AuditLogger.Log(ctx, entry)
	}

	slog.Info("initialize",
		"conn_id", func() string {
			if conn != nil {
				return conn.ID
			}
			return ""
		}(),
		"client", clientName, "client_version", clientVersion)

	result := map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{"listChanged": true},
			"resources": map[string]interface{}{"subscribe": true, "listChanged": true},
			"prompts":   map[string]interface{}{"listChanged": true},
			"logging":   map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "aegisgate-mcp",
			"version": Version,
		},
	}
	return h.handleSuccess(req.ID, result)
}

// handleInitialized processes the notifications/initialized notification.
// Per MCP spec, the client sends this after receiving the initialize
// response. It is a notification (no ID → no response expected), but
// we return nil so the caller can skip writing a response.
func (h *RequestHandler) handleInitialized(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	if h.AuditLogger != nil && conn != nil {
		h.AuditLogger.Log(ctx, &AuditEntry{
			Type:      "initialized",
			SessionID: conn.ID,
		})
	}
	// Notifications have no ID — return nil to signal "no response"
	if req.ID == nil {
		return nil
	}
	// If the client mistakenly included an ID, respond with empty success
	return h.handleSuccess(req.ID, map[string]interface{}{})
}

func (h *RequestHandler) handleListTools(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	tools := h.Registry.ToMCPFormat()
	return h.handleSuccess(req.ID, ListToolsResult{Tools: tools})
}

func (h *RequestHandler) handleCallTool(ctx context.Context, conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
	toolName := ""
	toolParams := make(map[string]interface{})
	if req.Params != nil {
		var params map[string]interface{}
		if err := json.Unmarshal(req.Params, &params); err == nil {
			if n, ok := params["name"].(string); ok {
				toolName = n
			}
			if p, ok := params["arguments"].(map[string]interface{}); ok {
				toolParams = p
			}
		}
	}

	sessionID := "anonymous"
	agentID := ""
	if conn != nil && conn.Session != nil {
		sessionID = conn.Session.ID
		agentID = conn.Session.AgentID
	}

	// Authorize
	if h.Authorizer != nil {
		authz, err := h.Authorizer.Authorize(ctx, &AuthorizationCall{
			Name:       toolName,
			Parameters: toolParams,
			SessionID:  sessionID,
			AgentID:    agentID,
		})
		if err != nil {
			slog.Error("authorization error", "error", err)
			return h.handleToolResult(req.ID, "Authorization error", true)
		}
		if !authz.Allowed {
			if h.AuditLogger != nil {
				h.AuditLogger.Log(ctx, &AuditEntry{
					Type: "tool_denied", SessionID: sessionID, AgentID: agentID,
					ToolName: toolName, Error: authz.Reason,
				})
			}
			msg := "Tool call denied"
			if authz.Reason != "" {
				msg += ": " + authz.Reason
			}
			return h.handleToolResult(req.ID, msg, true)
		}
	}

	// Validate parameters against the tool's inputSchema (required fields)
	if h.Registry != nil {
		if missing := validateRequiredParams(h.Registry, toolName, toolParams); len(missing) > 0 {
			if h.AuditLogger != nil {
				h.AuditLogger.Log(ctx, &AuditEntry{
					Type: "tool_invalid_params", SessionID: sessionID, AgentID: agentID,
					ToolName: toolName, Error: "missing required parameters: " + fmt.Sprintf("%v", missing),
				})
			}
			return h.handleToolResult(req.ID,
				fmt.Sprintf("Missing required parameters: %v", missing), true)
		}
	}

	// STDIO validation: scan string parameters for shell injection patterns.
	// This prevents prompt injection from manipulating tools that might
	// pass arguments to subprocesses.
	for _, paramValue := range toolParams {
		if strVal, ok := paramValue.(string); ok && strVal != "" {
			if h.StdioValidator != nil {
				if result := h.StdioValidator.ValidateCommandArgs([]string{strVal}); !result.Valid {
					if h.AuditLogger != nil {
						h.AuditLogger.Log(ctx, &AuditEntry{
							Type: "tool_stdio_blocked", SessionID: sessionID, AgentID: agentID,
							ToolName: toolName, Error: result.Reason,
						})
					}
					slog.Warn("STDIO validation blocked parameter",
						"tool", toolName, "reason", result.Reason)
					return h.handleToolResult(req.ID,
						"Parameter blocked by STDIO validation: "+result.Reason, true)
				}
			}
		}
	}

	// Input scanning: scan string parameters for prompt injection patterns.
	// This is defense-in-depth — the response scanner checks tool OUTPUT,
	// but scanning INPUT prevents the tool from ever processing injection
	// payloads. This catches patterns the STDIO validator misses (which
	// focuses on shell metacharacters, not semantic injection).
	if h.InputScanner != nil {
		for _, paramValue := range toolParams {
			if strVal, ok := paramValue.(string); ok && strVal != "" {
				findings := h.InputScanner.Scan(strVal)
				for _, f := range findings {
					if f.Pattern.Category == CatPrompt && f.Pattern.Severity >= SeverityHigh {
						if h.AuditLogger != nil {
							h.AuditLogger.Log(ctx, &AuditEntry{
								Type: "tool_input_blocked", SessionID: sessionID, AgentID: agentID,
								ToolName: toolName, Error: "prompt injection in parameter: " + f.Pattern.Name,
							})
						}
						slog.Warn("input scanner blocked parameter",
							"tool", toolName, "pattern", f.Pattern.Name,
							"severity", f.Pattern.Severity.String())
						return h.handleToolResult(req.ID,
							"Parameter blocked by input scanner: prompt injection detected ("+f.Pattern.Name+")", true)
					}
				}
			}
		}
	}

	// L3: Neural threat detection on input parameters.
	// Catches semantic attacks and evasion variants that regex (L1) and
	// STDIO validation miss. Runs after regex input scanner, before execution.
	// Same two-tier blocking as response scanning:
	//   Tier 1 (score ≥ 0.95): Block independently.
	//   Tier 2 (score ≥ 0.50): Block only if regex found suspicious patterns.
	if h.ThreatDetector != nil && h.ThreatDetector.IsEnabled() {
		for _, paramValue := range toolParams {
			if strVal, ok := paramValue.(string); ok && strVal != "" {
				mlResult := h.ThreatDetector.Detect(strVal)
				if mlResult.IsThreat {
					const l3HighConfidence = 0.95
					if mlResult.Score >= l3HighConfidence {
						if h.AuditLogger != nil {
							h.AuditLogger.Log(ctx, &AuditEntry{
								Type: "ml_input_blocked", SessionID: sessionID, AgentID: agentID,
								ToolName: toolName, Error: fmt.Sprintf("neural threat detected (score: %.3f, high confidence)", mlResult.Score),
							})
						}
						slog.Warn("ML threat detector blocked input (high confidence)",
							"tool", toolName, "score", mlResult.Score, "model", mlResult.ModelVersion)
						return h.handleToolResult(req.ID,
							fmt.Sprintf("Parameter blocked by neural threat detector (score: %.3f, high confidence)", mlResult.Score), true)
					}
					// Tier 2: check if regex input scanner found anything
					hasRegexCorroboration := false
					if h.InputScanner != nil {
						findings := h.InputScanner.Scan(strVal)
						for _, f := range findings {
							if f.Pattern.Severity >= SeverityMedium {
								hasRegexCorroboration = true
								break
							}
						}
					}
					if hasRegexCorroboration {
						if h.AuditLogger != nil {
							h.AuditLogger.Log(ctx, &AuditEntry{
								Type: "ml_input_blocked", SessionID: sessionID, AgentID: agentID,
								ToolName: toolName, Error: fmt.Sprintf("neural threat detected (score: %.3f, corroborated)", mlResult.Score),
							})
						}
						slog.Warn("ML threat detector blocked input (corroborated)",
							"tool", toolName, "score", mlResult.Score, "model", mlResult.ModelVersion)
						return h.handleToolResult(req.ID,
							fmt.Sprintf("Parameter blocked by neural threat detector (score: %.3f, corroborated)", mlResult.Score), true)
					}
					slog.Info("ML threat detector input alert (no corroboration)",
						"tool", toolName, "score", mlResult.Score)
				}
			}
		}
	}

	// Execute with timeout (prevents hanging tools)
	handler, ok := h.Registry.GetHandler(toolName)
	if !ok {
		return h.handleToolResult(req.ID, "Tool not found: "+toolName, true)
	}

	execCtx := ctx
	var cancelExec context.CancelFunc
	if h.ExecTimeout > 0 {
		execCtx, cancelExec = context.WithTimeout(ctx, h.ExecTimeout)
		defer cancelExec()
	}

	type execResult struct {
		Result interface{}
		Err    error
	}
	resultCh := make(chan execResult, 1)
	go func() {
		r, e := handler(execCtx, toolParams)
		resultCh <- execResult{Result: r, Err: e}
	}()

	var result interface{}
	select {
	case <-execCtx.Done():
		if execCtx.Err() == context.DeadlineExceeded {
			if h.AuditLogger != nil {
				h.AuditLogger.Log(ctx, &AuditEntry{
					Type: "tool_timeout", SessionID: sessionID, AgentID: agentID,
					ToolName: toolName, Error: "execution timeout",
				})
			}
			return h.handleToolResult(req.ID, "Tool execution timed out", true)
		}
		// Context cancelled for other reasons (shutdown)
		return h.handleToolResult(req.ID, "Tool execution cancelled", true)
	case r := <-resultCh:
		if r.Err != nil {
			if h.AuditLogger != nil {
				h.AuditLogger.Log(ctx, &AuditEntry{
					Type: "tool_error", SessionID: sessionID, AgentID: agentID,
					ToolName: toolName, Error: r.Err.Error(),
				})
			}
			return h.handleToolResult(req.ID, r.Err.Error(), true)
		}
		result = r.Result
	}
	if h.AuditLogger != nil {
		h.AuditLogger.Log(ctx, &AuditEntry{
			Type: "tool_success", SessionID: sessionID, AgentID: agentID, ToolName: toolName,
		})
	}
	// Convert result to text content. Strings are used directly;
	// structured types (maps, slices, structs) are JSON-marshaled.
	var text string
	switch v := result.(type) {
	case string:
		text = v
	case nil:
		text = ""
	default:
		data, err := json.Marshal(result)
		if err != nil {
			return h.handleToolResult(req.ID, fmt.Sprintf("failed to encode result: %v", err), true)
		}
		text = string(data)
	}
	return h.handleToolResult(req.ID, text, false)
}

func (h *RequestHandler) handlePing(req *JSONRPCRequest) *JSONRPCResponse {
	return h.handleSuccess(req.ID, nil)
}

// ============================================================
// MCP Spec: Resources
// ============================================================

func (h *RequestHandler) handleListResources(req *JSONRPCRequest) *JSONRPCResponse {
	// AegisGate MCP does not expose resources by default.
	// Return an empty list — clients handle this gracefully.
	return h.handleSuccess(req.ID, map[string]interface{}{"resources": []interface{}{}})
}

func (h *RequestHandler) handleReadResource(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	// No resources are registered. Return an error so the client knows.
	return h.handleError(req.ID, ErrorInvalidParams, "no resources available")
}

// ============================================================
// MCP Spec: Prompts
// ============================================================

func (h *RequestHandler) handleListPrompts(req *JSONRPCRequest) *JSONRPCResponse {
	// AegisGate MCP does not expose prompts by default.
	return h.handleSuccess(req.ID, map[string]interface{}{"prompts": []interface{}{}})
}

func (h *RequestHandler) handleGetPrompt(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	return h.handleError(req.ID, ErrorInvalidParams, "no prompts available")
}

// ============================================================
// MCP Spec: Logging
// ============================================================

var currentLogLevel = "info"

func (h *RequestHandler) handleSetLogLevel(req *JSONRPCRequest) *JSONRPCResponse {
	if req.Params != nil {
		var params struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal(req.Params, &params); err == nil && params.Level != "" {
			currentLogLevel = params.Level
			slog.Info("log level set", "level", params.Level)
		}
	}
	return h.handleSuccess(req.ID, nil)
}

// ============================================================
// MCP Spec: Completion
// ============================================================

func (h *RequestHandler) handleComplete(req *JSONRPCRequest) *JSONRPCResponse {
	// Completion is optional. Return empty completions.
	return h.handleSuccess(req.ID, map[string]interface{}{
		"completion": map[string]interface{}{
			"values":  []interface{}{},
			"total":   0,
			"hasMore": false,
		},
	})
}

func (h *RequestHandler) handleSuccess(id interface{}, result interface{}) *JSONRPCResponse {
	return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: id, Result: result}
}

func (h *RequestHandler) handleError(id interface{}, code int, message string) *JSONRPCResponse {
	return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: id, Error: &JSONRPCError{Code: code, Message: message}}
}

func (h *RequestHandler) handleToolResult(id interface{}, text string, isError bool) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion, ID: id,
		Result: CallToolResult{Content: []ContentBlock{{Type: "text", Text: text}}, IsError: isError},
	}
}

// ============================================================
// Tool Registry
// ============================================================

// ToolRegistry manages MCP tools and their handlers.
type ToolRegistry struct {
	mu       sync.RWMutex
	tools    map[string]*registryTool
	handlers map[string]ToolHandlerFunc
}

type registryTool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	RiskLevel   int
}

// NewToolRegistry creates a new tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools:    make(map[string]*registryTool),
		handlers: make(map[string]ToolHandlerFunc),
	}
}

// Register registers a tool with metadata.
func (r *ToolRegistry) Register(name, desc string, riskLevel int, inputSchema map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		return fmt.Errorf("tool name is required")
	}
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool already registered: %s", name)
	}
	r.tools[name] = &registryTool{Name: name, Description: desc, RiskLevel: riskLevel, InputSchema: inputSchema}
	return nil
}

// RegisterHandler registers a tool handler function.
func (r *ToolRegistry) RegisterHandler(name string, handler ToolHandlerFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		return fmt.Errorf("tool name is required")
	}
	r.handlers[name] = handler
	return nil
}

// GetHandler returns a tool handler by name.
func (r *ToolRegistry) GetHandler(name string) (ToolHandlerFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	handler, ok := r.handlers[name]
	return handler, ok
}

// ToMCPFormat converts tools to MCP Tool format.
func (r *ToolRegistry) ToMCPFormat() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tools := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return tools
}

// GetRiskLevel returns the risk level for a tool.
func (r *ToolRegistry) GetRiskLevel(name string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	if !ok {
		return 100
	}
	return tool.RiskLevel
}

// Count returns the number of registered tools.
func (r *ToolRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// GetInputSchema returns the input schema for a tool, or nil if not found.
func (r *ToolRegistry) GetInputSchema(name string) map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	if !ok {
		return nil
	}
	return tool.InputSchema
}

// ============================================================
// Parameter Validation
// ============================================================

// validateRequiredParams checks that all required properties in the tool's
// inputSchema are present in the provided parameters. Returns a slice of
// missing parameter names (empty if all present or schema has no required list).
func validateRequiredParams(registry *ToolRegistry, toolName string, params map[string]interface{}) []string {
	schema := registry.GetInputSchema(toolName)
	if schema == nil {
		return nil
	}
	required, ok := schema["required"].([]interface{})
	if !ok {
		return nil
	}
	var missing []string
	for _, r := range required {
		name, ok := r.(string)
		if !ok {
			continue
		}
		if _, present := params[name]; !present {
			missing = append(missing, name)
		}
	}
	return missing
}
