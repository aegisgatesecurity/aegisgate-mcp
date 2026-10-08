// SPDX-License-Identifier: Apache-2.0
// Package mcpsecurity — MCP Protocol Types
// Based on MCP Specification 2024-11-05
// Adapted from AegisGate Platform upstream/aegisguard/pkg/agent-protocol/mcp/types.go

package mcpsecurity

import (
	"context"
	"encoding/json"
	"time"
)

const ProtocolVersion = "2024-11-05"
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
	Tools []Tool `json:"tools"`
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

// --- Session ---

type Session struct {
	ID      string `json:"id"`
	AgentID string `json:"agentId"`
}

// --- Handler Types ---

// HandlerFunc processes a single MCP JSON-RPC request.
type HandlerFunc func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse

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
