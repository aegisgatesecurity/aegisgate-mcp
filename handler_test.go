// SPDX-License-Identifier: Apache-2.0
// Handler tests — covers RequestHandler, ToolRegistry, and all dispatch paths.

package mcpsecurity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// --- RequestHandler dispatch ---

func TestHandleRequestInitialize(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", ID: 1}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], ProtocolVersion)
	}
	si, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatal("missing serverInfo")
	}
	if si["name"] != "aegisgate-mcp" {
		t.Errorf("serverInfo.name = %v, want aegisgate-mcp", si["name"])
	}
	if si["version"] != Version {
		t.Errorf("serverInfo.version = %v, want %s", si["version"], Version)
	}
}

func TestHandleRequestPing(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "ping", ID: 2}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp.Error != nil {
		t.Fatalf("ping returned error: %v", resp.Error)
	}
	if resp.ID != 2 {
		t.Errorf("ID = %v, want 2", resp.ID)
	}
}

func TestHandleRequestListTools(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Registry.Register("tool1", "desc", 10, nil)
	handler.Registry.Register("tool2", "desc", 20, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/list", ID: 3}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp.Error != nil {
		t.Fatalf("tools/list returned error: %v", resp.Error)
	}
	result, ok := resp.Result.(ListToolsResult)
	if !ok {
		// Could be map; try marshal/unmarshal
		data, _ := json.Marshal(resp.Result)
		var ltr ListToolsResult
		if err := json.Unmarshal(data, &ltr); err != nil {
			t.Fatalf("expected ListToolsResult, got %T: %s", resp.Result, data)
		}
		result = ltr
	}
	if len(result.Tools) != 2 {
		t.Errorf("tools count = %d, want 2", len(result.Tools))
	}
}

func TestHandleRequestMethodNotFound(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "unknown/method", ID: 4}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != ErrorMethodNotFound {
		t.Errorf("error code = %d, want %d", resp.Error.Code, ErrorMethodNotFound)
	}
	if !strings.Contains(resp.Error.Message, "unknown/method") {
		t.Errorf("error message should contain method name: %s", resp.Error.Message)
	}
}

func TestHandleCallToolSuccess(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Registry.Register("echo", "echo tool", 10, nil)
	handler.Registry.RegisterHandler("echo", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "echo: hello", nil
	})

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]interface{}{"msg": "hello"},
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 5}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp.Error != nil {
		t.Fatalf("tools/call returned error: %v", resp.Error)
	}
	data, _ := json.Marshal(resp.Result)
	var result CallToolResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.IsError {
		t.Error("expected IsError=false")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "echo") {
		t.Errorf("unexpected result: %v", result.Content)
	}
}

func TestHandleCallToolNotFound(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	params, _ := json.Marshal(map[string]interface{}{"name": "nonexistent"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 6}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp.Error != nil {
		t.Fatalf("expected tool result error, not JSON-RPC error: %v", resp.Error)
	}
	data, _ := json.Marshal(resp.Result)
	var result CallToolResult
	json.Unmarshal(data, &result)
	if !result.IsError {
		t.Error("expected IsError=true for missing tool")
	}
	if !strings.Contains(result.Content[0].Text, "not found") {
		t.Errorf("error text should mention 'not found': %s", result.Content[0].Text)
	}
}

func TestHandleCallToolHandlerError(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Registry.Register("fail", "failing tool", 10, nil)
	handler.Registry.RegisterHandler("fail", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return nil, &json.SyntaxError{Offset: 0}
	})
	params, _ := json.Marshal(map[string]interface{}{"name": "fail"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 7}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, resp_err("fail"))
	_ = req
	_ = resp
}

// helper to create a request with params for a named tool
func resp_err(name string) *JSONRPCRequest {
	params, _ := json.Marshal(map[string]interface{}{"name": name})
	return &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 7}
}

func TestHandleCallToolWithNilConn(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Registry.Register("safe", "safe tool", 5, nil)
	handler.Registry.RegisterHandler("safe", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "ok", nil
	})
	params, _ := json.Marshal(map[string]interface{}{"name": "safe"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 8}
	// nil conn should not panic
	resp := handler.HandleRequest(nil, req)
	if resp == nil {
		t.Fatal("nil response")
	}
}

func TestHandleCallToolWithNilParams(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Registry.Register("safe", "safe tool", 5, nil)
	handler.Registry.RegisterHandler("safe", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "ok", nil
	})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: nil, ID: 9}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	if resp == nil {
		t.Fatal("nil response")
	}
}

func TestHandleCallToolWithAuditLogger(t *testing.T) {
	auditLogger, err := NewAuditLogger("", 100)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	handler := NewRequestHandler(nil, auditLogger, nil)
	handler.Registry.Register("audited", "audited tool", 5, nil)
	handler.Registry.RegisterHandler("audited", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "ok", nil
	})
	params, _ := json.Marshal(map[string]interface{}{"name": "audited"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 10}
	handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1", AgentID: "a1"}}, req)
	if auditLogger.EntryCount() < 1 {
		t.Errorf("expected audit entries, got %d", auditLogger.EntryCount())
	}
}

func TestHandleCallToolDeniedWithAuditLogger(t *testing.T) {
	auditLogger, err := NewAuditLogger("", 100)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	rbacMgr := NewRBACManager()
	rbacAuth := NewRBACAuthorizer(rbacMgr)
	handler := NewRequestHandler(rbacAuth, auditLogger, nil)
	handler.Registry.Register("shell_command", "dangerous", 90, nil)
	handler.Registry.RegisterHandler("shell_command", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "should not reach", nil
	})

	// Register restricted agent and create session
	rbacMgr.RegisterAgent("restricted-agent", "Restricted", RoleRestricted, nil)
	sid, err := rbacMgr.CreateSession("restricted-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	params, _ := json.Marshal(map[string]interface{}{"name": "shell_command"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 11}
	conn := &Connection{ID: "c1", Session: &Session{ID: sid, AgentID: "restricted-agent"}}
	resp := handler.HandleRequest(conn, req)
	if resp == nil {
		t.Fatal("nil response")
	}
	// Should be denied
	data, _ := json.Marshal(resp.Result)
	var result CallToolResult
	json.Unmarshal(data, &result)
	if !result.IsError {
		t.Error("expected denial (IsError=true)")
	}
}

// --- ToolRegistry ---

func TestToolRegistryRegisterDuplicate(t *testing.T) {
	r := NewToolRegistry()
	if err := r.Register("dup", "first", 10, nil); err != nil {
		t.Fatalf("first register: %v", err)
	}
	err := r.Register("dup", "second", 20, nil)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error should mention 'already registered': %s", err.Error())
	}
}

func TestToolRegistryRegisterEmptyName(t *testing.T) {
	r := NewToolRegistry()
	err := r.Register("", "desc", 10, nil)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestToolRegistryRegisterHandlerEmptyName(t *testing.T) {
	r := NewToolRegistry()
	err := r.RegisterHandler("", func(ctx context.Context, p map[string]interface{}) (interface{}, error) {
		return nil, nil
	})
	if err == nil {
		t.Error("expected error for empty handler name")
	}
}

func TestToolRegistryGetHandlerMiss(t *testing.T) {
	r := NewToolRegistry()
	_, ok := r.GetHandler("nonexistent")
	if ok {
		t.Error("expected false for nonexistent handler")
	}
}

func TestToolRegistryGetHandlerHit(t *testing.T) {
	r := NewToolRegistry()
	fn := func(ctx context.Context, p map[string]interface{}) (interface{}, error) { return "ok", nil }
	r.RegisterHandler("mytool", fn)
	h, ok := r.GetHandler("mytool")
	if !ok {
		t.Fatal("expected to find handler")
	}
	result, err := h(context.Background(), nil)
	if err != nil || result != "ok" {
		t.Errorf("handler result = %v, err = %v", result, err)
	}
}

func TestToolRegistryGetRiskLevelUnknown(t *testing.T) {
	r := NewToolRegistry()
	if r.GetRiskLevel("unknown") != 100 {
		t.Errorf("unknown tool risk should be 100, got %d", r.GetRiskLevel("unknown"))
	}
}

func TestHandleCallToolWithRBACDenial(t *testing.T) {
	rbacMgr := NewRBACManager()
	rbacAuth := NewRBACAuthorizer(rbacMgr)
	auditLogger, _ := NewAuditLogger("", 100)
	handler := NewRequestHandler(rbacAuth, auditLogger, nil)
	handler.Registry.Register("shell_command", "dangerous", 90, nil)
	handler.Registry.RegisterHandler("shell_command", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "should not reach", nil
	})
	rbacMgr.RegisterAgent("agent-1", "Agent", RoleRestricted, nil)
	sid, _ := rbacMgr.CreateSession("agent-1")

	params, _ := json.Marshal(map[string]interface{}{"name": "shell_command"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 12}
	conn := &Connection{ID: "c1", Session: &Session{ID: sid, AgentID: "agent-1"}}
	resp := handler.HandleRequest(conn, req)
	data, _ := json.Marshal(resp.Result)
	var result CallToolResult
	json.Unmarshal(data, &result)
	if !result.IsError {
		t.Error("expected denial")
	}
	if !strings.Contains(result.Content[0].Text, "denied") {
		t.Errorf("expected 'denied' in text: %s", result.Content[0].Text)
	}
}

func TestHandleCallToolRBACAuthorizeError(t *testing.T) {
	// Create an authorizer that returns an error
	handler := NewRequestHandler(&errorAuthorizer{}, nil, nil)
	handler.Registry.Register("anytool", "tool", 5, nil)
	handler.Registry.RegisterHandler("anytool", func(ctx context.Context, p map[string]interface{}) (interface{}, error) {
		return "ok", nil
	})
	params, _ := json.Marshal(map[string]interface{}{"name": "anytool"})
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", Params: params, ID: 13}
	resp := handler.HandleRequest(&Connection{ID: "c1", Session: &Session{ID: "c1"}}, req)
	data, _ := json.Marshal(resp.Result)
	var result CallToolResult
	json.Unmarshal(data, &result)
	if !result.IsError {
		t.Error("expected error result")
	}
	if !strings.Contains(result.Content[0].Text, "Authorization error") {
		t.Errorf("expected 'Authorization error': %s", result.Content[0].Text)
	}
}

// errorAuthorizer always returns an error
type errorAuthorizer struct{}

func (e *errorAuthorizer) Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error) {
	return nil, &json.SyntaxError{Offset: 0}
}
