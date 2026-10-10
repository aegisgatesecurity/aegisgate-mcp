// SPDX-License-Identifier: Apache-2.0
// Elicitation transport-level tests — verifies the full elicitation/create
// flow across HTTP/SSE, TCP, and stdio transports.

package mcpsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================
// ElicitationRegistry unit tests
// ============================================================

func TestElicitationRegistryRegisterResolve(t *testing.T) {
	reg := NewElicitationRegistry(100 * time.Millisecond)
	id, ch := reg.register()
	if id != 1 {
		t.Errorf("first ID = %d, want 1", id)
	}
	if reg.pendingCount() != 1 {
		t.Errorf("pending count = %d, want 1", reg.pendingCount())
	}
	result := &ElicitationResult{Action: "accept", Content: map[string]interface{}{"name": "test"}}
	ok := reg.resolve(id, elicitationResponse{result: result})
	if !ok {
		t.Fatal("resolve returned false for pending request")
	}
	resp := <-ch
	if resp.result.Action != "accept" {
		t.Errorf("action = %s, want accept", resp.result.Action)
	}
	if reg.pendingCount() != 0 {
		t.Errorf("pending count after resolve = %d, want 0", reg.pendingCount())
	}
}

func TestElicitationRegistryTimeout(t *testing.T) {
	reg := NewElicitationRegistry(50 * time.Millisecond)
	id, ch := reg.register()
	result, err := reg.waitForResponse(id, ch, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if result != nil {
		t.Fatal("expected nil result on timeout")
	}
	if reg.pendingCount() != 0 {
		t.Errorf("pending count after timeout = %d, want 0 (should be cleaned up)", reg.pendingCount())
	}
}

func TestElicitationRegistryResolveNonexistent(t *testing.T) {
	reg := NewElicitationRegistry(0)
	ok := reg.resolve(999, elicitationResponse{})
	if ok {
		t.Fatal("resolve should return false for non-existent ID")
	}
}

func TestElicitationRegistryCancelAll(t *testing.T) {
	reg := NewElicitationRegistry(5 * time.Second)
	_, ch1 := reg.register()
	_, ch2 := reg.register()
	_, ch3 := reg.register()
	if reg.pendingCount() != 3 {
		t.Errorf("pending count = %d, want 3", reg.pendingCount())
	}
	cancelErr := fmt.Errorf("session disconnected")
	reg.cancelAll(cancelErr)
	if reg.pendingCount() != 0 {
		t.Errorf("pending count after cancelAll = %d, want 0", reg.pendingCount())
	}
	// All channels should receive the error
	for i, ch := range []chan elicitationResponse{ch1, ch2, ch3} {
		resp := <-ch
		if resp.err == nil {
			t.Errorf("channel %d: expected error, got nil", i)
		}
	}
}

func TestElicitationRegistryConcurrentRegisterResolve(t *testing.T) {
	reg := NewElicitationRegistry(5 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, ch := reg.register()
			reg.resolve(id, elicitationResponse{result: &ElicitationResult{Action: "accept"}})
			<-ch
		}()
	}
	wg.Wait()
	if reg.pendingCount() != 0 {
		t.Errorf("pending count after concurrent test = %d, want 0", reg.pendingCount())
	}
}

// ============================================================
// parseElicitationResponse tests
// ============================================================

func TestParseElicitationResponseAccept(t *testing.T) {
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      int64(1),
		Result: map[string]interface{}{
			"action":  "accept",
			"content": map[string]interface{}{"name": "Alice"},
		},
	}
	result, err := parseElicitationResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != "accept" {
		t.Errorf("action = %s, want accept", result.Action)
	}
	if result.Content["name"] != "Alice" {
		t.Errorf("content name = %v, want Alice", result.Content["name"])
	}
}

func TestParseElicitationResponseDecline(t *testing.T) {
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      int64(1),
		Result:  map[string]interface{}{"action": "decline"},
	}
	result, err := parseElicitationResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != "decline" {
		t.Errorf("action = %s, want decline", result.Action)
	}
}

func TestParseElicitationResponseError(t *testing.T) {
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      int64(1),
		Error:   &JSONRPCError{Code: -1, Message: "client error"},
	}
	_, err := parseElicitationResponse(resp)
	if err == nil {
		t.Fatal("expected error for error response")
	}
}

func TestParseElicitationResponseMissingAction(t *testing.T) {
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      int64(1),
		Result:  map[string]interface{}{"foo": "bar"},
	}
	_, err := parseElicitationResponse(resp)
	if err == nil {
		t.Fatal("expected error for missing action")
	}
}

func TestParseElicitationResponseRawJSON(t *testing.T) {
	// Test with json.RawMessage result (as would come from HTTP transport)
	rawResult := json.RawMessage(`{"action":"accept","content":{"key":"value"}}`)
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      int64(1),
		Result:  rawResult,
	}
	result, err := parseElicitationResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != "accept" {
		t.Errorf("action = %s, want accept", result.Action)
	}
}

// ============================================================
// buildElicitationRequest tests
// ============================================================

func TestBuildElicitationRequest(t *testing.T) {
	params := &ElicitationParams{
		Message:         "Please enter your name",
		RequestedSchema: map[string]interface{}{"type": "string"},
	}
	req := buildElicitationRequest(42, params)
	if req.Method != "elicitation/create" {
		t.Errorf("method = %s, want elicitation/create", req.Method)
	}
	if req.ID != int64(42) {
		t.Errorf("ID = %v, want 42", req.ID)
	}
	var parsedParams elicitationRequestParams
	if err := json.Unmarshal(req.Params, &parsedParams); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}
	if parsedParams.Message != "Please enter your name" {
		t.Errorf("message = %s", parsedParams.Message)
	}
}

// ============================================================
// isElicitationResponse / handleElicitationResponse tests
// ============================================================

func TestIsElicitationResponse(t *testing.T) {
	reg := NewElicitationRegistry(0)
	id, _ := reg.register()
	if !reg.isElicitationResponse(id) {
		t.Error("isElicitationResponse should return true for pending ID")
	}
	if reg.isElicitationResponse(999) {
		t.Error("isElicitationResponse should return false for unknown ID")
	}
	if reg.isElicitationResponse(nil) {
		t.Error("isElicitationResponse should return false for nil ID")
	}
	if reg.isElicitationResponse("string") {
		t.Error("isElicitationResponse should return false for string ID")
	}
}

func TestHandleElicitationResponseConsumed(t *testing.T) {
	reg := NewElicitationRegistry(5 * time.Second)
	id, ch := reg.register()
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  map[string]interface{}{"action": "accept", "content": map[string]interface{}{}},
	}
	consumed := reg.handleElicitationResponse(resp)
	if !consumed {
		t.Fatal("handleElicitationResponse should return true for pending ID")
	}
	result := <-ch
	if result.result.Action != "accept" {
		t.Errorf("action = %s, want accept", result.result.Action)
	}
}

func TestHandleElicitationResponseNotConsumed(t *testing.T) {
	reg := NewElicitationRegistry(0)
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      int64(999),
		Result:  map[string]interface{}{"action": "accept"},
	}
	consumed := reg.handleElicitationResponse(resp)
	if consumed {
		t.Fatal("handleElicitationResponse should return false for unknown ID")
	}
}

// ============================================================
// TCP transport elicitation test
// ============================================================

func TestTCPElicitationEndToEnd(t *testing.T) {
	// Create a TCP server with a tool that calls ElicitInput
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	cfg.ScanResponses = false
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	t.Cleanup(func() { srv.auditLogger.Close() })
	srv.handler.Authorizer = nil

	// Register a tool that uses elicitation
	elicitDone := make(chan *ElicitationResult, 1)
	srv.RegisterTool("ask_name", "Ask the user for their name", 20, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"prompt": map[string]interface{}{"type": "string"},
		},
	})
	srv.RegisterToolHandler("ask_name", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		result, err := srv.ElicitInput("What is your name?", map[string]interface{}{
			"type": "string",
		})
		if err != nil {
			return nil, err
		}
		elicitDone <- result
		return map[string]interface{}{"name": result.Content["name"]}, nil
	})

	// Start TCP server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := srv.server.listener.Addr().String()

	// Connect as a client
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// Send initialize
	initReq := JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "initialize",
		ID:      1,
		Params:  json.RawMessage(`{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1.0"}}`),
	}
	if err := enc.Encode(&initReq); err != nil {
		t.Fatalf("encode initialize: %v", err)
	}
	var initResp JSONRPCResponse
	if err := dec.Decode(&initResp); err != nil {
		t.Fatalf("decode initialize response: %v", err)
	}

	// Call the tool — the server will send an elicitation/create request
	callReq := JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		ID:      2,
		Params:  json.RawMessage(`{"name":"ask_name","arguments":{}}`),
	}
	if err := enc.Encode(&callReq); err != nil {
		t.Fatalf("encode tools/call: %v", err)
	}

	// Read the elicitation/create request from the server
	var elicitReq JSONRPCRequest
	if err := dec.Decode(&elicitReq); err != nil {
		t.Fatalf("decode elicitation request: %v", err)
	}
	if elicitReq.Method != "elicitation/create" {
		t.Errorf("elicit method = %s, want elicitation/create", elicitReq.Method)
	}
	var elicitParams elicitationRequestParams
	if err := json.Unmarshal(elicitReq.Params, &elicitParams); err != nil {
		t.Fatalf("unmarshal elicit params: %v", err)
	}
	if elicitParams.Message != "What is your name?" {
		t.Errorf("elicit message = %s, want 'What is your name?'", elicitParams.Message)
	}

	// Send the elicitation response
	elicitResp := JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      elicitReq.ID,
		Result:  map[string]interface{}{"action": "accept", "content": map[string]interface{}{"name": "Alice"}},
	}
	if err := enc.Encode(&elicitResp); err != nil {
		t.Fatalf("encode elicit response: %v", err)
	}

	// Read the tools/call response
	var callResp JSONRPCResponse
	if err := dec.Decode(&callResp); err != nil {
		t.Fatalf("decode tools/call response: %v", err)
	}
	if callResp.Error != nil {
		t.Fatalf("call response error: %s", callResp.Error.Message)
	}

	// Verify the elicitation result was delivered to the tool handler
	select {
	case result := <-elicitDone:
		if result.Action != "accept" {
			t.Errorf("elicit action = %s, want accept", result.Action)
		}
		if result.Content["name"] != "Alice" {
			t.Errorf("elicit content name = %v, want Alice", result.Content["name"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for elicitation result")
	}
}

func TestTCPElicitationDecline(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	cfg.ScanResponses = false
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	t.Cleanup(func() { srv.auditLogger.Close() })
	srv.handler.Authorizer = nil

	srv.RegisterTool("ask_perm", "Ask permission", 20, map[string]interface{}{
		"type": "object",
	})
	srv.RegisterToolHandler("ask_perm", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		result, err := srv.ElicitInput("Allow access?", nil)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"action": result.Action}, nil
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := srv.server.listener.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// Initialize
	enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "initialize", ID: 1,
		Params: json.RawMessage(`{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1.0"}}`)})
	var initResp JSONRPCResponse
	dec.Decode(&initResp)

	// Call tool
	enc.Encode(&JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "tools/call", ID: 2,
		Params: json.RawMessage(`{"name":"ask_perm","arguments":{}}`)})

	// Read elicitation request
	var elicitReq JSONRPCRequest
	if err := dec.Decode(&elicitReq); err != nil {
		t.Fatalf("decode elicit req: %v", err)
	}
	if elicitReq.Method != "elicitation/create" {
		t.Fatalf("expected elicitation/create, got %s", elicitReq.Method)
	}

	// Send decline
	enc.Encode(&JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      elicitReq.ID,
		Result:  map[string]interface{}{"action": "decline"},
	})

	// Read tool response
	var callResp JSONRPCResponse
	if err := dec.Decode(&callResp); err != nil {
		t.Fatalf("decode call resp: %v", err)
	}
	if callResp.Error != nil {
		t.Fatalf("unexpected error: %s", callResp.Error.Message)
	}
	// Result can be CallToolResult (TCP) or map[string]interface{} (JSON decoded)
	var textContent string
	switch r := callResp.Result.(type) {
	case CallToolResult:
		if len(r.Content) > 0 {
			textContent = r.Content[0].Text
		}
	case map[string]interface{}:
		if content, ok := r["content"].([]interface{}); ok && len(content) > 0 {
			if block, ok := content[0].(map[string]interface{}); ok {
				textContent, _ = block["text"].(string)
			}
		}
	default:
		t.Fatalf("unexpected result type: %T", callResp.Result)
	}
	var actionMap map[string]interface{}
	if err := json.Unmarshal([]byte(textContent), &actionMap); err != nil {
		t.Fatalf("failed to parse content text: %v (text: %s)", err, textContent)
	}
	if actionMap["action"] != "decline" {
		t.Errorf("action = %v, want decline", actionMap["action"])
	}
}

// ============================================================
// HTTP/SSE transport elicitation test
// ============================================================

func TestHTTPElicitationNoSSEConnection(t *testing.T) {
	// When there's no active SSE connection, elicitation should fail gracefully.
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	cfg.ScanResponses = false
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	t.Cleanup(func() { srv.auditLogger.Close() })
	srv.handler.Authorizer = nil

	// Set up an elicitation callback that simulates no SSE connection
	srv.SetElicitationCallback(func(params *ElicitationParams) (*ElicitationResult, error) {
		return nil, fmt.Errorf("elicitation not available: no active SSE connection for session test")
	})

	_, err = srv.ElicitInput("test", nil)
	if err == nil {
		t.Fatal("expected error when no SSE connection")
	}
	if !strings.Contains(err.Error(), "no active SSE connection") {
		t.Errorf("error should mention no SSE connection, got: %v", err)
	}
}

// ============================================================
// Connection.ElicitFunc integration test
// ============================================================

func TestConnectionElicitFunc(t *testing.T) {
	// Verify that Connection.ElicitFunc is called by ElicitInput
	// when set via the thread-local.
	conn := &Connection{
		ID:        "test",
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &Session{ID: "test"},
	}
	conn.ElicitFunc = func(params *ElicitationParams) (*ElicitationResult, error) {
		if params.Message != "test message" {
			t.Errorf("message = %s, want 'test message'", params.Message)
		}
		return &ElicitationResult{Action: "accept", Content: map[string]interface{}{"answer": 42}}, nil
	}

	handler := &RequestHandler{}
	currentElicitFn.Set(conn.ElicitFunc)
	defer currentElicitFn.Set(nil)

	result, err := handler.ElicitInput(&ElicitationParams{Message: "test message"})
	if err != nil {
		t.Fatalf("ElicitInput error: %v", err)
	}
	if result.Action != "accept" {
		t.Errorf("action = %s, want accept", result.Action)
	}
	if result.Content["answer"] != 42 {
		t.Errorf("content answer = %v, want 42", result.Content["answer"])
	}
}

// ============================================================
// ElicitationRegistry ID generation tests
// ============================================================

func TestElicitationRegistryMonotonicIDs(t *testing.T) {
	reg := NewElicitationRegistry(5 * time.Second)
	id1, ch1 := reg.register()
	id2, ch2 := reg.register()
	id3, _ := reg.register()
	if id1 != 1 || id2 != 2 || id3 != 3 {
		t.Errorf("IDs = %d, %d, %d, want 1, 2, 3", id1, id2, id3)
	}
	reg.resolve(id1, elicitationResponse{result: &ElicitationResult{Action: "accept"}})
	reg.resolve(id2, elicitationResponse{result: &ElicitationResult{Action: "accept"}})
	<-ch1
	<-ch2
}

func TestElicitationRegistryCancelSingle(t *testing.T) {
	reg := NewElicitationRegistry(5 * time.Second)
	id, _ := reg.register()
	if !reg.cancel(id) {
		t.Fatal("cancel should return true for pending request")
	}
	if reg.cancel(id) {
		t.Fatal("cancel should return false for already-cancelled request")
	}
	if reg.pendingCount() != 0 {
		t.Errorf("pending count after cancel = %d, want 0", reg.pendingCount())
	}
}

// ============================================================
// stdio transport elicitation test
// ============================================================

func TestStdioElicitationEndToEnd(t *testing.T) {
	// Use pipes to simulate stdin/stdout
	rIn, wIn := io.Pipe()   // server reads from rIn (client writes to wIn)
	rOut, wOut := io.Pipe() // client reads from rOut (server writes to wOut)

	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.AuthToken = ""
	cfg.ScanResponses = false
	srv, err := NewSecuredMCPServer(cfg)
	if err != nil {
		t.Fatalf("NewSecuredMCPServer: %v", err)
	}
	t.Cleanup(func() { srv.auditLogger.Close() })
	srv.handler.Authorizer = nil

	// Register a tool that uses elicitation
	srv.RegisterTool("ask_value", "Ask for a value", 20, map[string]interface{}{
		"type": "object",
	})
	srv.RegisterToolHandler("ask_value", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		result, err := srv.ElicitInput("Enter a value:", map[string]interface{}{"type": "string"})
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"value": result.Content["value"]}, nil
	})

	// Create stdio transport manually with pipes
	conn := &Connection{
		ID:        "stdio-test",
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &Session{ID: "stdio-test"},
	}
	_ = conn

	// Build the handler chain
	var chain HandlerFunc = func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return srv.handler.HandleRequest(conn, req)
	}
	chain = srv.guardrails.GuardrailHandler(chain)
	chain = srv.authMgr.AuthMiddleware(chain)

	transport := &stdioTransport{
		handler: chain,
		encoder: json.NewEncoder(wOut),
		decoder: json.NewDecoder(io.LimitReader(rIn, 1<<20)),
		conn:    conn,
	}
	_ = transport

	// Start the transport in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go transport.run(ctx)

	// Client side: read from rOut, write to wIn
	clientDec := json.NewDecoder(rOut)
	clientEnc := json.NewEncoder(wIn)

	// Initialize
	clientEnc.Encode(&JSONRPCRequest{
		JSONRPC: JSONRPCVersion, Method: "initialize", ID: 1,
		Params: json.RawMessage(`{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1.0"}}`),
	})
	var initResp JSONRPCResponse
	if err := clientDec.Decode(&initResp); err != nil {
		t.Fatalf("decode init resp: %v", err)
	}

	// Call the tool
	clientEnc.Encode(&JSONRPCRequest{
		JSONRPC: JSONRPCVersion, Method: "tools/call", ID: 2,
		Params: json.RawMessage(`{"name":"ask_value","arguments":{}}`),
	})

	// Read the elicitation/create request
	var elicitReq JSONRPCRequest
	if err := clientDec.Decode(&elicitReq); err != nil {
		t.Fatalf("decode elicit req: %v", err)
	}
	if elicitReq.Method != "elicitation/create" {
		t.Fatalf("expected elicitation/create, got %s", elicitReq.Method)
	}

	// Send the elicitation response
	clientEnc.Encode(&JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      elicitReq.ID,
		Result:  map[string]interface{}{"action": "accept", "content": map[string]interface{}{"value": "hello"}},
	})

	// Read the tools/call response
	var callResp JSONRPCResponse
	if err := clientDec.Decode(&callResp); err != nil {
		t.Fatalf("decode call resp: %v", err)
	}
	if callResp.Error != nil {
		t.Fatalf("call error: %s", callResp.Error.Message)
	}
	// Result can be CallToolResult or map[string]interface{} (JSON decoded)
	var textContent string
	switch r := callResp.Result.(type) {
	case CallToolResult:
		if len(r.Content) > 0 {
			textContent = r.Content[0].Text
		}
	case map[string]interface{}:
		if content, ok := r["content"].([]interface{}); ok && len(content) > 0 {
			if block, ok := content[0].(map[string]interface{}); ok {
				textContent, _ = block["text"].(string)
			}
		}
	default:
		t.Fatalf("unexpected result type: %T", callResp.Result)
	}
	var valueMap map[string]interface{}
	if err := json.Unmarshal([]byte(textContent), &valueMap); err != nil {
		t.Fatalf("failed to parse content: %v (text: %s)", err, textContent)
	}
	if valueMap["value"] != "hello" {
		t.Errorf("value = %v, want hello", valueMap["value"])
	}
}

// ============================================================
// HTTP elicitation end-to-end test with mock SSE
// ============================================================

func TestHTTPSendElicitationNoConnection(t *testing.T) {
	transport := newStreamableHTTPTransport("127.0.0.1:0", func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: req.ID, Result: map[string]interface{}{}}
	})

	_, err := transport.sendElicitation("nonexistent-session", &ElicitationParams{Message: "test"})
	if err == nil {
		t.Fatal("expected error for non-existent session")
	}
	if !strings.Contains(err.Error(), "no active SSE connection") {
		t.Errorf("error should mention no SSE connection, got: %v", err)
	}
}

func TestHTTPSendElicitationWithSSEConn(t *testing.T) {
	transport := newStreamableHTTPTransport("127.0.0.1:0", func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: req.ID, Result: map[string]interface{}{}}
	})

	// Create a session
	sess := transport.createSession()
	sessionID := sess.id

	// Create a mock SSE connection using httptest
	var buf bytes.Buffer
	mockWriter := &mockResponseWriter{header: http.Header{}, body: &buf}
	flusher := &mockFlusher{}
	conn := transport.registerSSEConn(sessionID, mockWriter, flusher, true)
	defer transport.unregisterSSEConn(sessionID, conn)

	// Start the elicitation in a goroutine (it will block)
	type elicitResult struct {
		result *ElicitationResult
		err    error
	}
	resultCh := make(chan elicitResult, 1)
	go func() {
		r, err := transport.sendElicitation(sessionID, &ElicitationParams{
			Message: "Enter your email",
			RequestedSchema: map[string]interface{}{
				"type": "string",
			},
		})
		resultCh <- elicitResult{result: r, err: err}
	}()

	// Wait a bit for the goroutine to send the request
	time.Sleep(50 * time.Millisecond)

	// Verify the SSE event was written
	sseData := buf.String()
	if !strings.Contains(sseData, "elicitation/create") {
		t.Errorf("SSE data should contain elicitation/create: %s", sseData)
	}
	if !strings.Contains(sseData, "Enter your email") {
		t.Errorf("SSE data should contain the message: %s", sseData)
	}

	// Parse the elicitation request to get the ID
	var elicitReq JSONRPCRequest
	for _, line := range strings.Split(sseData, "\n") {
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			json.Unmarshal([]byte(data), &elicitReq)
			break
		}
	}
	if elicitReq.Method != "elicitation/create" {
		t.Fatalf("could not parse elicitation request from SSE: %s", sseData)
	}

	// Simulate the client sending a response POST
	// The response would be delivered via handleElicitationResponse
	resp := &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      elicitReq.ID,
		Result:  map[string]interface{}{"action": "accept", "content": map[string]interface{}{"email": "test@example.com"}},
	}
	transport.elicitReg.handleElicitationResponse(resp)

	// Wait for the goroutine to receive the result
	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("elicitation error: %v", res.err)
		}
		if res.result.Action != "accept" {
			t.Errorf("action = %s, want accept", res.result.Action)
		}
		if res.result.Content["email"] != "test@example.com" {
			t.Errorf("email = %v, want test@example.com", res.result.Content["email"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for elicitation result")
	}
}

// ============================================================
// Mock helpers for HTTP SSE tests
// ============================================================

type mockResponseWriter struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

func (m *mockResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = http.Header{}
	}
	return m.header
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	return m.body.Write(data)
}

func (m *mockResponseWriter) WriteHeader(code int) {
	m.status = code
}

type mockFlusher struct{}

func (m *mockFlusher) Flush() {}

// Ensure mockResponseWriter implements http.ResponseWriter
var _ http.ResponseWriter = (*mockResponseWriter)(nil)
var _ http.Flusher = (*mockFlusher)(nil)
