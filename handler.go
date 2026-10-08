// SPDX-License-Identifier: Apache-2.0
// MCP Request Handler — processes JSON-RPC methods with authorization.
// Based on AegisGate Platform upstream handler.go + tool_registry.go

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
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
	ResourceReg    *ResourceRegistry
	PromptReg      *PromptRegistry
	ExecTimeout    time.Duration   // max execution time per tool call (0 = no limit)
	StdioValidator *StdioValidator // if non-nil, scans tool params for shell injection
	InputScanner   *ContentScanner // if non-nil, scans tool params for prompt injection
	// L3: Neural threat detector for input scanning. If non-nil, scans
	// tool parameters for semantic attacks and evasion variants that
	// regex cannot detect.
	ThreatDetector *ml.ThreatDetector
	// Tool poisoning scanner: if non-nil, validates tool descriptions
	// and schemas for prompt injection / exfiltration commands at
	// registration time (OWASP MCP Top 10: Tool Poisoning).
	ToolPoisoningScanner *ContentScanner
}

// NewRequestHandler creates a new request handler.
func NewRequestHandler(authorizer ToolAuthorizer, auditLogger AuditLogger, sessionMgr SessionManager) *RequestHandler {
	return &RequestHandler{
		Authorizer:           authorizer,
		AuditLogger:          auditLogger,
		SessionMgr:           sessionMgr,
		Registry:             NewToolRegistry(),
		ResourceReg:          NewResourceRegistry(),
		PromptReg:            NewPromptRegistry(),
		ToolPoisoningScanner: NewContentScanner(),
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
	case "notifications/cancelled":
		// Client-initiated cancellation (MCP spec 2025-06-18).
		// Notification — no response. The request ID being cancelled
		// is in params.requestId. Our tool execution uses context
		// timeouts, so cancellation is handled by the context.
		slog.Info("client cancelled request", "method", req.Method)
		return nil
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
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
			"prompts":   map[string]interface{}{},
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

	// Parse cursor for pagination (MCP spec: cursor is an opaque string)
	cursor := parseCursor(req.Params)
	pageSize := DefaultPageSize

	result := ListToolsResult{Tools: tools}
	if cursor > 0 || len(tools) > pageSize {
		paged, next := paginateTools(tools, cursor, pageSize)
		result.Tools = paged
		if next > 0 {
			result.NextCursor = strconv.Itoa(next)
		}
	}
	return h.handleSuccess(req.ID, result)
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
	resources := h.ResourceReg.List()

	cursor := parseCursor(req.Params)
	pageSize := DefaultPageSize

	result := ListResourcesResult{Resources: resources}
	if cursor > 0 || len(resources) > pageSize {
		paged, next := paginateResources(resources, cursor, pageSize)
		result.Resources = paged
		if next > 0 {
			result.NextCursor = strconv.Itoa(next)
		}
	}
	return h.handleSuccess(req.ID, result)
}

func (h *RequestHandler) handleReadResource(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	var params struct {
		URI string `json:"uri"`
	}
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return h.handleError(req.ID, ErrorInvalidParams, "invalid params: "+err.Error())
		}
	}
	if params.URI == "" {
		return h.handleError(req.ID, ErrorInvalidParams, "uri is required")
	}
	content, err := h.ResourceReg.Read(ctx, params.URI)
	if err != nil {
		return h.handleError(req.ID, ErrorInvalidParams, err.Error())
	}
	return h.handleSuccess(req.ID, ReadResourceResult{Contents: []ResourceContent{*content}})
}

// ============================================================
// MCP Spec: Prompts
// ============================================================

func (h *RequestHandler) handleListPrompts(req *JSONRPCRequest) *JSONRPCResponse {
	prompts := h.PromptReg.List()

	cursor := parseCursor(req.Params)
	pageSize := DefaultPageSize

	result := ListPromptsResult{Prompts: prompts}
	if cursor > 0 || len(prompts) > pageSize {
		paged, next := paginatePrompts(prompts, cursor, pageSize)
		result.Prompts = paged
		if next > 0 {
			result.NextCursor = strconv.Itoa(next)
		}
	}
	return h.handleSuccess(req.ID, result)
}

func (h *RequestHandler) handleGetPrompt(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return h.handleError(req.ID, ErrorInvalidParams, "invalid params: "+err.Error())
		}
	}
	if params.Name == "" {
		return h.handleError(req.ID, ErrorInvalidParams, "name is required")
	}
	result, err := h.PromptReg.Get(ctx, params.Name, params.Arguments)
	if err != nil {
		return h.handleError(req.ID, ErrorInvalidParams, err.Error())
	}
	return h.handleSuccess(req.ID, result)
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

// Register registers a tool with metadata. The tool's description and
// inputSchema are scanned for prompt injection and exfiltration patterns
// (tool poisoning defense, OWASP MCP Top 10).
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

// RegisterWithScanning registers a tool after scanning its description and
// inputSchema for tool poisoning patterns. Returns a *ToolPoisoningError
// if suspicious patterns are detected. Requires a ContentScanner instance.
func (r *ToolRegistry) RegisterWithScanning(name, desc string, riskLevel int, inputSchema map[string]interface{}, scanner *ContentScanner) error {
	if err := validateToolNotPoisoned(scanner, name, desc, inputSchema); err != nil {
		return err
	}
	return r.Register(name, desc, riskLevel, inputSchema)
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
// Tool Poisoning Detection
// ============================================================

// validateToolNotPoisoned scans a tool's description and inputSchema for
// prompt injection, exfiltration commands, or other malicious patterns.
// Returns a *ToolPoisoningError (as error) if suspicious patterns are found.
func validateToolNotPoisoned(scanner *ContentScanner, name, desc string, inputSchema map[string]interface{}) error {
	if scanner == nil {
		return nil
	}
	var patterns []string

	// Scan the description — this is what the LLM sees and can be used
	// to inject hidden instructions.
	if desc != "" {
		findings := scanner.Scan(desc)
		for _, f := range findings {
			if f.Pattern.Severity >= SeverityHigh {
				patterns = append(patterns, f.Pattern.Name)
			}
		}
	}

	// Scan string values in the inputSchema (descriptions, enums, defaults)
	if inputSchema != nil {
		schemaPatterns := scanSchemaForPoisoning(scanner, inputSchema, name)
		patterns = append(patterns, schemaPatterns...)
	}

	if len(patterns) > 0 {
		return &ToolPoisoningError{
			ToolName: name,
			Reason:   "malicious patterns detected in description or inputSchema",
			Patterns: patterns,
		}
	}
	return nil
}

// scanSchemaForPoisoning recursively scans string values in a JSON schema
// for prompt injection patterns. Returns a list of detected pattern names.
func scanSchemaForPoisoning(scanner *ContentScanner, schema map[string]interface{}, toolName string) []string {
	var patterns []string
	for key, val := range schema {
		switch v := val.(type) {
		case string:
			if key == "description" || key == "enum" || key == "default" {
				findings := scanner.Scan(v)
				for _, f := range findings {
					if f.Pattern.Severity >= SeverityHigh {
						slog.Warn("tool poisoning detected in inputSchema",
							"tool", toolName, "field", key,
							"pattern", f.Pattern.Name, "category", f.Pattern.Category)
						patterns = append(patterns, f.Pattern.Name)
					}
				}
			}
		case map[string]interface{}:
			patterns = append(patterns, scanSchemaForPoisoning(scanner, v, toolName)...)
		case []interface{}:
			// Scan array elements (e.g. enum values) for injection
			for _, elem := range v {
				if s, ok := elem.(string); ok {
					findings := scanner.Scan(s)
					for _, f := range findings {
						if f.Pattern.Severity >= SeverityHigh {
							slog.Warn("tool poisoning detected in inputSchema array",
								"tool", toolName, "field", key,
								"pattern", f.Pattern.Name, "category", f.Pattern.Category)
							patterns = append(patterns, f.Pattern.Name)
						}
					}
				}
			}
		}
	}
	return patterns
}

// ============================================================
// Resource Registry (MCP Spec 2025-06-18)
// ============================================================

// ResourceRegistry manages MCP resources and their handlers.
type ResourceRegistry struct {
	mu        sync.RWMutex
	resources map[string]*registeredResource
}

type registeredResource struct {
	Resource Resource
	Handler  ResourceHandlerFunc
}

// NewResourceRegistry creates a new resource registry.
func NewResourceRegistry() *ResourceRegistry {
	return &ResourceRegistry{
		resources: make(map[string]*registeredResource),
	}
}

// Register adds a resource with its handler function.
func (r *ResourceRegistry) Register(uri, name, description, mimeType string, handler ResourceHandlerFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if uri == "" {
		return fmt.Errorf("resource URI is required")
	}
	if _, exists := r.resources[uri]; exists {
		return fmt.Errorf("resource already registered: %s", uri)
	}
	if handler == nil {
		return fmt.Errorf("resource handler is required: %s", uri)
	}
	r.resources[uri] = &registeredResource{
		Resource: Resource{URI: uri, Name: name, Description: description, MimeType: mimeType},
		Handler:  handler,
	}
	return nil
}

// List returns all registered resources.
func (r *ResourceRegistry) List() []Resource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resources := make([]Resource, 0, len(r.resources))
	for _, rr := range r.resources {
		resources = append(resources, rr.Resource)
	}
	return resources
}

// Read reads a resource by URI.
func (r *ResourceRegistry) Read(ctx context.Context, uri string) (*ResourceContent, error) {
	r.mu.RLock()
	rr, ok := r.resources[uri]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
	return rr.Handler(ctx, uri)
}

// Count returns the number of registered resources.
func (r *ResourceRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.resources)
}

// ============================================================
// Prompt Registry (MCP Spec 2025-06-18)
// ============================================================

// PromptRegistry manages MCP prompts and their handler functions.
type PromptRegistry struct {
	mu      sync.RWMutex
	prompts map[string]*registeredPrompt
}

type registeredPrompt struct {
	Prompt  Prompt
	Handler PromptHandlerFunc
}

// NewPromptRegistry creates a new prompt registry.
func NewPromptRegistry() *PromptRegistry {
	return &PromptRegistry{
		prompts: make(map[string]*registeredPrompt),
	}
}

// Register adds a prompt with its handler function.
func (r *PromptRegistry) Register(name, description string, args []PromptArgument, handler PromptHandlerFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		return fmt.Errorf("prompt name is required")
	}
	if _, exists := r.prompts[name]; exists {
		return fmt.Errorf("prompt already registered: %s", name)
	}
	if handler == nil {
		return fmt.Errorf("prompt handler is required: %s", name)
	}
	r.prompts[name] = &registeredPrompt{
		Prompt:  Prompt{Name: name, Description: description, Arguments: args},
		Handler: handler,
	}
	return nil
}

// List returns all registered prompts.
func (r *PromptRegistry) List() []Prompt {
	r.mu.RLock()
	defer r.mu.RUnlock()
	prompts := make([]Prompt, 0, len(r.prompts))
	for _, rp := range r.prompts {
		prompts = append(prompts, rp.Prompt)
	}
	return prompts
}

// Get generates a prompt by name with the given arguments.
func (r *PromptRegistry) Get(ctx context.Context, name string, args map[string]string) (*GetPromptResult, error) {
	r.mu.RLock()
	rp, ok := r.prompts[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("prompt not found: %s", name)
	}
	return rp.Handler(ctx, args)
}

// Count returns the number of registered prompts.
func (r *PromptRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.prompts)
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

// ============================================================
// Pagination helpers (MCP Spec 2025-06-18 — cursor-based)
// ============================================================

// DefaultPageSize is the maximum number of items returned per page
// when the client doesn't specify a limit. MCP servers typically use
// 50-100. We use 100 to avoid paginating in the common case.
const DefaultPageSize = 100

// parseCursor extracts the cursor (offset) from request params.
// Returns 0 if no cursor is present (first page).
func parseCursor(params json.RawMessage) int {
	if params == nil {
		return 0
	}
	var p struct {
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return 0
	}
	if p.Cursor == "" {
		return 0
	}
	n, err := strconv.Atoi(p.Cursor)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// paginateTools returns a page of tools and the next cursor (0 if no more pages).
func paginateTools(tools []Tool, cursor, pageSize int) ([]Tool, int) {
	start := cursor
	if start >= len(tools) {
		return []Tool{}, 0
	}
	end := start + pageSize
	if end > len(tools) {
		end = len(tools)
	}
	paged := tools[start:end]
	next := 0
	if end < len(tools) {
		next = end
	}
	return paged, next
}

// paginateResources returns a page of resources and the next cursor.
func paginateResources(resources []Resource, cursor, pageSize int) ([]Resource, int) {
	start := cursor
	if start >= len(resources) {
		return []Resource{}, 0
	}
	end := start + pageSize
	if end > len(resources) {
		end = len(resources)
	}
	paged := resources[start:end]
	next := 0
	if end < len(resources) {
		next = end
	}
	return paged, next
}

// paginatePrompts returns a page of prompts and the next cursor.
func paginatePrompts(prompts []Prompt, cursor, pageSize int) ([]Prompt, int) {
	start := cursor
	if start >= len(prompts) {
		return []Prompt{}, 0
	}
	end := start + pageSize
	if end > len(prompts) {
		end = len(prompts)
	}
	paged := prompts[start:end]
	next := 0
	if end < len(prompts) {
		next = end
	}
	return paged, next
}
