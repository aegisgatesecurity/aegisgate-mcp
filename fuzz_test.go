package mcpsecurity

import (
	"context"
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// Fuzz tests for the AegisGate MCP security server.
//
// Go fuzz tests are part of the regular test binary. When run with `go test`
// (no -fuzz flag) only the seed corpus is executed as subtests, providing
// regression coverage. When run with `go test -fuzz=FuzzHandleRequest` the
// fuzzer mutates inputs to find panics or assertion violations.
//
// Invariants checked by every fuzz target:
//   1. The handler (or middleware chain) must never panic.
//   2. If a non-nil *JSONRPCResponse is returned it must be JSON-serializable.
//
// All targets cap input size at 1 MiB to avoid excessive memory use.
// ---------------------------------------------------------------------------

// maxFuzzInputSize is the upper bound on fuzz input length. Inputs larger
// than this are skipped to keep the fuzzer responsive.
const maxFuzzInputSize = 1 << 20 // 1 MiB

// ---------------------------------------------------------------------------
// 1. FuzzHandleRequest — fuzz the core HandleRequest method.
//
// This target feeds arbitrary bytes through JSON decoding and then into
// RequestHandler.HandleRequest with a minimal (nil authorizer / nil session
// manager / nil audit logger) handler. The goal is to ensure that no
// combination of method, params, and id causes a panic or produces a
// response that cannot be marshalled back to JSON.
// ---------------------------------------------------------------------------

func FuzzHandleRequest(f *testing.F) {
	handler := NewRequestHandler(nil, nil, nil)

	// Seed corpus — valid, edge-case, and malformed-but-valid-JSON inputs.
	f.Add([]byte(`{"jsonrpc":"2.0","method":"initialize","id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":2}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"ping","id":3}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ping"},"id":4}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"jsonrpc":"2.0"}`))
	f.Add([]byte(`{"method":"initialize"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`""`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"","id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"unknown/method","id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":"not-an-object","id":5}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":""},"id":6}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)) // notification (no ID)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInputSize {
			t.Skip()
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(data, &req); err != nil {
			t.Skip() // Not valid JSON — not our concern
		}

		conn := &Connection{
			ID:      "fuzz-conn",
			Session: &Session{ID: "fuzz-session"},
		}

		// Must not panic.
		resp := handler.HandleRequest(conn, &req)

		// If we got a response, it must be valid JSON-serializable.
		if resp != nil {
			if _, err := json.Marshal(resp); err != nil {
				t.Errorf("response not JSON-serializable: %v", err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 2. FuzzHandleRequestWithAuth — fuzz with auth middleware active.
//
// This target wraps the handler with AuthMiddleware so that the
// authentication layer is also exercised. It ensures that malformed auth
// payloads, unexpected param shapes, and boundary conditions (e.g. max
// auth attempts) do not cause panics.
// ---------------------------------------------------------------------------

func FuzzHandleRequestWithAuth(f *testing.F) {
	// Create auth manager with a configured token.
	authCfg := &AuthConfig{
		BearerToken:     "test-token",
		MaxAuthAttempts: 5,
	}
	authMgr := NewAuthManager(authCfg)

	handler := NewRequestHandler(nil, nil, nil)

	// Wire auth middleware around handler.
	inner := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return handler.HandleRequest(conn, req)
	}
	wrapped := authMgr.AuthMiddleware(inner)

	// Seeds — common requests plus auth-specific edge cases.
	f.Add([]byte(`{"jsonrpc":"2.0","method":"initialize","params":{"auth":{"token":"test-token"}},"id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"initialize","params":{"auth":{"token":"wrong"}},"id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"initialize","params":{"auth":null},"id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":2}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"ping","id":3}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ping"},"id":4}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"jsonrpc":"2.0"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`""`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"","id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"unknown/method","id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":"not-an-object","id":5}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInputSize {
			t.Skip()
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(data, &req); err != nil {
			t.Skip()
		}

		conn := &Connection{
			ID:      "fuzz-auth-conn",
			Session: &Session{ID: "fuzz-auth-session"},
		}

		// Must not panic.
		resp := wrapped(conn, &req)

		// If we got a response, it must be valid JSON-serializable.
		if resp != nil {
			if _, err := json.Marshal(resp); err != nil {
				t.Errorf("response not JSON-serializable: %v", err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 3. FuzzHandleRequestWithScanner — fuzz with response scanner active.
//
// This target exercises the response-scanning middleware (content scanner
// for PII / secrets / XSS / prompt-injection). A custom "echo_fuzz" tool is
// registered whose output the scanner inspects. The goal is to ensure the
// scanner does not panic on unusual tool outputs or request shapes.
// ---------------------------------------------------------------------------

func FuzzHandleRequestWithScanner(f *testing.F) {
	handler := NewRequestHandler(nil, nil, nil)
	handler.Authorizer = nil

	// Register a tool that returns a fixed string; the scanner will
	// inspect it for every fuzz input.
	_ = handler.Registry.Register("echo_fuzz", "echo fuzz input", 10, nil)
	_ = handler.Registry.RegisterHandler("echo_fuzz", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "fuzz output", nil
	})

	// Build a secured server to access wrapWithResponseScan.
	cfg := DefaultServerConfig()
	cfg.ScanResponses = true
	cfg.BlockOnPII = true
	cfg.BlockOnSecrets = true
	cfg.BlockOnXSS = true
	cfg.BlockOnPromptInject = true
	srv, _ := NewSecuredMCPServer(cfg)
	defer srv.Stop()
	srv.handler = handler

	inner := func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		return handler.HandleRequest(conn, req)
	}
	wrapped := srv.wrapWithResponseScan(inner)

	// Seeds — focus on tools/call paths that trigger the echo_fuzz tool,
	// plus general requests that exercise the scanner on error responses.
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo_fuzz"},"id":1}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo_fuzz","arguments":{"input":"hello"}},"id":2}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"nonexistent"},"id":3}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":"not-an-object","id":4}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":""},"id":5}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":6}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"initialize","id":7}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"ping","id":8}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`""`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzInputSize {
			t.Skip()
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(data, &req); err != nil {
			t.Skip()
		}

		conn := &Connection{
			ID:      "fuzz-scan-conn",
			Session: &Session{ID: "fuzz-scan-session"},
		}

		// Must not panic.
		resp := wrapped(conn, &req)

		// If we got a response, it must be valid JSON-serializable.
		if resp != nil {
			if _, err := json.Marshal(resp); err != nil {
				t.Errorf("response not JSON-serializable: %v", err)
			}
		}
	})
}
