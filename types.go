// SPDX-License-Identifier: Apache-2.0
// Package mcpsecurity — MCP Protocol Types
// Based on MCP Specification 2025-06-18
// Adapted from AegisGate Platform upstream/aegisguard/pkg/agent-protocol/mcp/types.go

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const ProtocolVersion = "2025-06-18"
const JSONRPCVersion = "2.0"

const (
	ErrorParseError     = -32700
	ErrorInvalidRequest = -32600
	ErrorMethodNotFound = -32601
	ErrorInvalidParams  = -32602
	ErrorInternal       = -32603
	ErrorUnauthorized   = -32000
	ErrorForbidden      = -32001
	ErrorRateLimited    = -32002
)

// --- Protocol Structures ---

type ServerInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type ClientInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type ServerCapabilities struct {
	Tools       *ToolCapabilities `json:"tools,omitempty"`
	ListChanged bool              `json:"listChanged,omitempty"`
}

type ToolCapabilities struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// --- Tool Structures ---

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

type CallToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

type ListToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// --- Resource Structures (MCP Spec 2025-06-18) ---

// Resource represents a server-side resource that clients can read.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceContent holds the content returned from a resource read.
type ResourceContent struct {
	URI      string `json:"uri"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// ListResourcesResult is the response for resources/list.
type ListResourcesResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// ReadResourceResult is the response for resources/read.
type ReadResourceResult struct {
	Contents []ResourceContent `json:"contents"`
}

// ResourceHandlerFunc reads a resource by URI and returns its content.
type ResourceHandlerFunc func(ctx context.Context, uri string) (*ResourceContent, error)

// --- Resource Template Structures (MCP Spec 2025-06-18) ---

// ResourceTemplate represents a URI template for parameterized resources.
type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ListResourceTemplatesResult is the response for resources/templates/list.
type ListResourceTemplatesResult struct {
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
	NextCursor        string             `json:"nextCursor,omitempty"`
}

// --- Prompt Structures (MCP Spec 2025-06-18) ---

// Prompt represents a server-side prompt template.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptArgument defines a named argument for a prompt template.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptMessage is a single message in a prompt result.
type PromptMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// GetPromptResult is the response for prompts/get.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// ListPromptsResult is the response for prompts/list.
type ListPromptsResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// PromptHandlerFunc generates a prompt from the given arguments.
type PromptHandlerFunc func(ctx context.Context, args map[string]string) (*GetPromptResult, error)

// --- Tool Poisoning Detection ---

// ToolPoisoningError describes a tool poisoning detection result.
type ToolPoisoningError struct {
	ToolName string
	Reason   string
	Patterns []string
}

// Error implements the error interface.
func (e *ToolPoisoningError) Error() string {
	return fmt.Sprintf("tool poisoning detected for %q: %s (patterns: %v)", e.ToolName, e.Reason, e.Patterns)
}

// --- JSON-RPC Structures ---

type JSONRPCRequest struct {
	JSONRPC   string          `json:"jsonrpc"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params,omitempty"`
	ID        interface{}     `json:"id,omitempty"`
	KeyID     string          `json:"keyId,omitempty"`     // AegisGate extension: identifies the signing key
	Signature string          `json:"signature,omitempty"` // AegisGate extension: hex-encoded ECDSA P-256 signature (ASN.1 DER)
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JSONRPCNotification represents a JSON-RPC 2.0 notification (no ID, no
// response expected). Per the JSON-RPC 2.0 spec, a notification has a
// top-level `method` field — it is NOT wrapped in a `result` object.
// Used for server-initiated messages like notifications/tools/list_changed.
type JSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// --- Session ---

type Session struct {
	ID      string `json:"id"`
	AgentID string `json:"agentId"`
}

// --- Handler Types ---

// HandlerFunc processes a single MCP JSON-RPC request.
type HandlerFunc func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse

// NotificationCallback is called when the server needs to send a
// notification to connected clients (e.g. tools/list_changed).
// The notification is delivered as a JSON-RPC notification (no ID).
type NotificationCallback func(method string, params interface{})

// ToolHandlerFunc executes a tool and returns its result.
type ToolHandlerFunc func(ctx context.Context, params map[string]interface{}) (interface{}, error)

// --- Authorization ---

type AuthorizationCall struct {
	ID         string
	Name       string
	Parameters map[string]interface{}
	SessionID  string
	AgentID    string
}

type AuthorizationDecision struct {
	Allowed     bool
	Reason      string
	RiskScore   int
	MatchedRule string
}

// --- Audit ---

type AuditEntry struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId,omitempty"`
	AgentID   string `json:"agentId,omitempty"`
	ToolName  string `json:"toolName,omitempty"`
	Error     string `json:"error,omitempty"`
	RiskScore int    `json:"riskScore,omitempty"`
}

// --- Interfaces ---

type ToolAuthorizer interface {
	Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error)
}

type AuditLogger interface {
	Log(ctx context.Context, entry *AuditEntry) error
}

type SessionManager interface {
	CreateSession(ctx context.Context, agentID string) (*Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

func Now() time.Time { return time.Now() }
