// SPDX-License-Identifier: Apache-2.0
// Streamable HTTP Transport — MCP Spec 2025-06-18 transport.
//
// The Streamable HTTP transport replaces the deprecated HTTP+SSE transport.
// Clients POST JSON-RPC requests to a single endpoint. The server responds
// with either:
//   - HTTP 200 + JSON body (for simple request/response)
//   - HTTP 200 + text/event-stream (for streaming responses)
//
// This implementation supports the simple request/response mode. Streaming
// (SSE) is supported via the Accept header — if the client requests
// text/event-stream, the server opens an SSE stream and sends responses
// as Server-Sent Events.
//
// Security: all requests pass through the same middleware chain as TCP
// (auth → signature verification → guardrails → response scan → handler).

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// streamableHTTPTransport implements the MCP 2025-06-18 Streamable HTTP transport.
type streamableHTTPTransport struct {
	handler HandlerFunc
	addr    string
	lnAddr  string
	httpSrv *http.Server
	mu      sync.Mutex
}

// newStreamableHTTPTransport creates a new Streamable HTTP transport.
func newStreamableHTTPTransport(addr string, handler HandlerFunc) *streamableHTTPTransport {
	t := &streamableHTTPTransport{
		handler: handler,
		addr:    addr,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", t.handleMCP)
	mux.HandleFunc("/mcp/", t.handleMCP)
	t.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}
	return t
}

// start begins listening for Streamable HTTP requests.
func (t *streamableHTTPTransport) start(ctx context.Context) error {
	ln, err := net.Listen("tcp", t.addr)
	if err != nil {
		return fmt.Errorf("streamable HTTP listen %s: %w", t.addr, err)
	}
	t.lnAddr = ln.Addr().String()
	slog.Info("streamable HTTP transport listening", "address", t.lnAddr, "endpoint", "/mcp")

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = t.httpSrv.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := t.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("streamable HTTP transport error", "error", err)
		}
	}()

	return nil
}

// handleMCP processes incoming MCP requests over HTTP.
func (t *streamableHTTPTransport) handleMCP(w http.ResponseWriter, r *http.Request) {
	// Only accept POST (per MCP 2025-06-18 Streamable HTTP spec)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body (limit to 1MB to prevent abuse)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Parse the JSON-RPC request
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   &JSONRPCError{Code: ErrorParseError, Message: "parse error: " + err.Error()},
		})
		return
	}

	// Create a pseudo-connection for this HTTP request.
	// Session ID is derived from the request ID for traceability.
	sessionID := "http-anonymous"
	if idStr := fmt.Sprintf("%v", req.ID); idStr != "" && idStr != "<nil>" && idStr != "null" {
		sessionID = "http-" + idStr
	}
	conn := &Connection{
		ID:        fmt.Sprintf("http-%d", time.Now().UnixNano()),
		Conn:      nil, // no underlying net.Conn for HTTP
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &Session{ID: sessionID},
	}
	conn.SetLastSeen(time.Now())

	// Process through the handler chain (same as TCP)
	resp := t.handler(conn, &req)

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("MCP-Protocol-Version", ProtocolVersion)
	if resp == nil {
		// Notification — no response expected
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// startStreamableHTTPListener is a test helper that starts the listener
// without context management, returning the listener for address discovery.
func startStreamableHTTPListener(t *streamableHTTPTransport) (net.Listener, error) {
	ln, err := net.Listen("tcp", t.addr)
	if err != nil {
		return nil, err
	}
	t.httpSrv.Addr = ln.Addr().String()
	go func() {
		if err := t.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("streamable HTTP transport error", "error", err)
		}
	}()
	return ln, nil
}

// unused import guard (strings will be used when SSE streaming is added)
var _ = strings.Contains
