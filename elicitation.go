// SPDX-License-Identifier: Apache-2.0
// Elicitation support — MCP spec 2025-06-18 elicitation/create.
//
// This file implements the transport-level wiring for elicitation/create,
// allowing tool handlers to request information from the client/user
// synchronously. The flow is:
//
//  1. Tool handler calls ElicitInput() on SecuredMCPServer or RequestHandler.
//  2. The ElicitationCallback (wired by the transport) registers a pending
//     request in the ElicitationRegistry, assigns a unique request ID, and
//     sends an elicitation/create JSON-RPC request to the client.
//  3. The tool handler blocks on a channel, waiting for the client's response.
//  4. The client processes the request and sends back a JSON-RPC response
//     with action "accept", "decline", or "cancel".
//  5. The transport detects the response (by matching the request ID),
//     delivers it to the pending channel, and the tool handler unblocks.
//
// For the Streamable HTTP transport, the elicitation request is sent as an
// SSE event on the client's open SSE stream, and the response arrives as a
// separate HTTP POST. For TCP and stdio, the request and response flow over
// the same bidirectional connection.

package mcpsecurity

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultElicitationTimeout is how long the server waits for an elicitation
// response from the client before timing out. Tool handlers can override
// this per-request by using ElicitInputWithTimeout.
const DefaultElicitationTimeout = 30 * time.Second

// elicitationResponse is the internal response delivered via channel.
type elicitationResponse struct {
	result *ElicitationResult
	err    error
}

// ElicitationRegistry manages pending elicitation requests, correlating
// server-to-client requests with client-to-server responses by request ID.
// It is safe for concurrent use by multiple goroutines.
type ElicitationRegistry struct {
	// pending maps request ID → channel for delivering the response.
	pending sync.Map // int64 → chan elicitationResponse

	// nextID generates monotonically increasing request IDs.
	nextID int64

	// timeout is the default timeout for elicitation requests.
	timeout time.Duration

	// mu protects the timeout field (set once at construction, read-only after).
	// Using sync.Map for pending, so no mutex needed for that.
}

// NewElicitationRegistry creates a new registry with the given default
// timeout. If timeout is 0, DefaultElicitationTimeout is used.
func NewElicitationRegistry(timeout time.Duration) *ElicitationRegistry {
	if timeout <= 0 {
		timeout = DefaultElicitationTimeout
	}
	return &ElicitationRegistry{
		timeout: timeout,
	}
}

// register creates a pending elicitation request and returns the assigned
// request ID and a channel that will receive the response. The caller should
// send the elicitation/create request to the client, then block on the channel.
func (r *ElicitationRegistry) register() (int64, chan elicitationResponse) {
	id := atomic.AddInt64(&r.nextID, 1)
	ch := make(chan elicitationResponse, 1)
	r.pending.Store(id, ch)
	return id, ch
}

// resolve delivers a response to the pending request with the given ID.
// Returns true if a pending request was found and delivered to, false
// if no pending request exists for the ID (e.g., already timed out or
// never registered).
func (r *ElicitationRegistry) resolve(id int64, resp elicitationResponse) bool {
	val, ok := r.pending.LoadAndDelete(id)
	if !ok {
		return false
	}
	ch := val.(chan elicitationResponse)
	select {
	case ch <- resp:
	default:
		// Channel has buffer of 1; if full, the waiter already timed out.
	}
	return true
}

// cancel removes a pending request without delivering a response.
// Used when a session disconnects or the server is shutting down.
func (r *ElicitationRegistry) cancel(id int64) bool {
	_, ok := r.pending.LoadAndDelete(id)
	return ok
}

// cancelAll cancels all pending requests with the given error.
// Used on session disconnect or server shutdown.
func (r *ElicitationRegistry) cancelAll(err error) {
	r.pending.Range(func(key, val any) bool {
		r.pending.Delete(key)
		ch := val.(chan elicitationResponse)
		select {
		case ch <- elicitationResponse{err: err}:
		default:
		}
		return true
	})
}

// pendingCount returns the number of pending elicitation requests.
func (r *ElicitationRegistry) pendingCount() int {
	count := 0
	r.pending.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// waitForResponse blocks on the channel until a response is received
// or the timeout expires. Returns the result and nil error on success,
// or nil and an error on timeout.
func (r *ElicitationRegistry) waitForResponse(id int64, ch chan elicitationResponse, timeout time.Duration) (*ElicitationResult, error) {
	if timeout <= 0 {
		timeout = r.timeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp := <-ch:
		return resp.result, resp.err
	case <-timer.C:
		r.cancel(id)
		return nil, fmt.Errorf("elicitation timed out after %s", timeout)
	}
}

// elicitationRequestParams is the params field sent in an elicitation/create
// JSON-RPC request from server to client.
type elicitationRequestParams struct {
	Message         string                 `json:"message"`
	RequestedSchema map[string]interface{} `json:"requestedSchema,omitempty"`
}

// buildElicitationRequest constructs a JSON-RPC request for elicitation/create
// with the given request ID and parameters.
func buildElicitationRequest(id int64, params *ElicitationParams) *JSONRPCRequest {
	reqParams := elicitationRequestParams{
		Message:         params.Message,
		RequestedSchema: params.RequestedSchema,
	}
	rawParams, err := json.Marshal(reqParams)
	if err != nil {
		slog.Error("failed to marshal elicitation params", "error", err)
		rawParams = []byte(`{}`)
	}
	return &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "elicitation/create",
		Params:  rawParams,
		ID:      id,
	}
}

// parseElicitationResponse parses a JSON-RPC response from the client
// into an ElicitationResult. The response result should contain an
// "action" field ("accept", "decline", or "cancel") and optionally a
// "content" field with the user's input.
func parseElicitationResponse(resp *JSONRPCResponse) (*ElicitationResult, error) {
	if resp.Error != nil {
		return nil, fmt.Errorf("elicitation error: %s (code %d)", resp.Error.Message, resp.Error.Code)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		// Result might be json.RawMessage or other type; try marshaling and re-parsing
		raw, err := json.Marshal(resp.Result)
		if err != nil {
			return nil, fmt.Errorf("elicitation: invalid response result type")
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("elicitation: failed to parse response: %w", err)
		}
	}

	action, _ := result["action"].(string)
	if action == "" {
		return nil, fmt.Errorf("elicitation: missing action in response")
	}

	er := &ElicitationResult{
		Action: action,
	}
	if content, ok := result["content"].(map[string]interface{}); ok {
		er.Content = content
	}
	return er, nil
}

// isElicitationResponse checks if a JSON-RPC response ID matches a pending
// elicitation request in the registry. Returns true if the response should
// be handled as an elicitation response (not a normal request response).
func (r *ElicitationRegistry) isElicitationResponse(id interface{}) bool {
	if id == nil {
		return false
	}
	var idInt int64
	switch v := id.(type) {
	case int64:
		idInt = v
	case int:
		idInt = int64(v)
	case float64:
		idInt = int64(v)
	case json.Number:
		var err error
		if idInt, err = v.Int64(); err != nil {
			return false
		}
	default:
		return false
	}
	_, ok := r.pending.Load(idInt)
	return ok
}

// handleElicitationResponse delivers a JSON-RPC response to the matching
// pending elicitation request. Returns true if the response was consumed
// (matched a pending request), false otherwise.
func (r *ElicitationRegistry) handleElicitationResponse(resp *JSONRPCResponse) bool {
	if resp == nil || resp.ID == nil {
		return false
	}
	var idInt int64
	switch v := resp.ID.(type) {
	case int64:
		idInt = v
	case int:
		idInt = int64(v)
	case float64:
		idInt = int64(v)
	case json.Number:
		var err error
		if idInt, err = v.Int64(); err != nil {
			return false
		}
	default:
		return false
	}

	result, err := parseElicitationResponse(resp)
	return r.resolve(idInt, elicitationResponse{result: result, err: err})
}
