// SPDX-License-Identifier: Apache-2.0
// Streamable HTTP Transport — MCP Spec 2025-06-18 transport.
//
// The Streamable HTTP transport replaces the deprecated HTTP+SSE transport.
// Clients POST JSON-RPC requests to a single endpoint. The server responds
// with:
//   - HTTP 200 + application/json (for simple request/response)
//   - HTTP 200 + text/event-stream (when client requests SSE via Accept header)
//   - HTTP 202 (for notifications, no response body)
//   - HTTP 400 (for parse errors)
//   - HTTP 405 (for non-POST/DELETE methods)
//
// SSE streaming: If the client includes "text/event-stream" in the Accept
// header, the server responds with Content-Type: text/event-stream and
// streams JSON-RPC responses as Server-Sent Events (data: {json}\n\n).
//
// Session management: The server generates an Mcp-Session-Id on initialize
// and returns it in the response header. Subsequent requests should include
// this header. If a client sends a session ID that does not match an active
// session, the server responds with 404 Not Found.
//
// Security: all requests pass through the same middleware chain as TCP
// (auth → signature verification → guardrails → response scan → handler).

package mcpsecurity

import (
	"context"
	"encoding/hex"
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

// sessionLifetime is how long an idle HTTP session remains valid.
const sessionLifetime = 30 * time.Minute

// streamableHTTPTransport implements the MCP 2025-06-18 Streamable HTTP transport.
type streamableHTTPTransport struct {
	handler HandlerFunc
	addr    string
	lnAddr  string
	httpSrv *http.Server
	mu      sync.Mutex

	// session management
	sessions  map[string]*httpSession // session ID → session
	sessionMu sync.RWMutex
}

// httpSession tracks an active Streamable HTTP session.
type httpSession struct {
	id        string
	createdAt time.Time
	lastSeen  time.Time
	conn      *Connection
}

// newStreamableHTTPTransport creates a new Streamable HTTP transport.
func newStreamableHTTPTransport(addr string, handler HandlerFunc) *streamableHTTPTransport {
	t := &streamableHTTPTransport{
		handler:  handler,
		addr:     addr,
		sessions: make(map[string]*httpSession),
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

// createSession creates a new HTTP session and stores it.
func (t *streamableHTTPTransport) createSession() *httpSession {
	id, err := generateSessionID()
	if err != nil {
		slog.Error("failed to generate session ID", "error", err)
		// Fall back to a timestamp-based ID (should never happen in practice)
		id = hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	now := time.Now()
	conn := &Connection{
		ID:        "http-" + id,
		Conn:      nil,
		CreatedAt: now,
		LastSeen:  now,
		Session:   &Session{ID: id},
	}
	conn.SetLastSeen(now)
	sess := &httpSession{
		id:        id,
		createdAt: now,
		lastSeen:  now,
		conn:      conn,
	}
	t.sessionMu.Lock()
	t.sessions[id] = sess
	t.sessionMu.Unlock()
	slog.Info("streamable HTTP session created", "session_id", id)
	return sess
}

// getSession retrieves an active session by ID. Returns nil if not found
// or expired.
func (t *streamableHTTPTransport) getSession(id string) *httpSession {
	if id == "" {
		return nil
	}
	t.sessionMu.RLock()
	sess, ok := t.sessions[id]
	t.sessionMu.RUnlock()
	if !ok {
		return nil
	}
	// Check for expiry
	if time.Since(sess.lastSeen) > sessionLifetime {
		t.sessionMu.Lock()
		delete(t.sessions, id)
		t.sessionMu.Unlock()
		slog.Info("streamable HTTP session expired", "session_id", id)
		return nil
	}
	return sess
}

// touchSession updates the last-seen time for a session.
func (t *streamableHTTPTransport) touchSession(id string) {
	t.sessionMu.Lock()
	if sess, ok := t.sessions[id]; ok {
		sess.lastSeen = time.Now()
		sess.conn.SetLastSeen(sess.lastSeen)
	}
	t.sessionMu.Unlock()
}

// deleteSession removes a session from the transport.
func (t *streamableHTTPTransport) deleteSession(id string) {
	t.sessionMu.Lock()
	delete(t.sessions, id)
	t.sessionMu.Unlock()
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
	// Per MCP 2025-06-18 Streamable HTTP spec:
	// - POST: send a JSON-RPC request or notification
	// - DELETE: terminate the session
	if r.Method == http.MethodDelete {
		sessionID := r.Header.Get("Mcp-Session-Id")
		if sessionID == "" {
			http.Error(w, "missing Mcp-Session-Id header", http.StatusBadRequest)
			return
		}
		t.deleteSession(sessionID)
		slog.Info("streamable HTTP session terminated by client", "session_id", sessionID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only accept POST (per MCP 2025-06-18 Streamable HTTP spec)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, DELETE")
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
		w.Header().Set("MCP-Protocol-Version", ProtocolVersion)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			Error:   &JSONRPCError{Code: ErrorParseError, Message: "parse error: " + err.Error()},
		})
		return
	}

	// Session management:
	// - initialize: create a new session, return Mcp-Session-Id header
	// - other requests: validate session ID from header, 404 if invalid
	clientSessionID := r.Header.Get("Mcp-Session-Id")
	isInitialize := req.Method == "initialize"

	var conn *Connection

	if isInitialize {
		// Create a new session for this client
		sess := t.createSession()
		conn = sess.conn
	} else {
		// Validate the session ID
		sess := t.getSession(clientSessionID)
		if sess == nil {
			w.Header().Set("MCP-Protocol-Version", ProtocolVersion)
			http.Error(w, "session not found or expired", http.StatusNotFound)
			return
		}
		conn = sess.conn
		t.touchSession(clientSessionID)
	}

	// Set the session ID context for subscription tracking
	currentSessionID.Set(conn.Session.ID)
	defer func() { currentSessionID.Set("") }()

	// Check if client requests SSE streaming
	wantSSE := acceptsSSE(r)

	// Process through the handler chain (same as TCP)
	resp := t.handler(conn, &req)

	// Set common headers
	w.Header().Set("MCP-Protocol-Version", ProtocolVersion)

	// Always set Mcp-Session-Id on initialize responses
	if isInitialize {
		w.Header().Set("Mcp-Session-Id", conn.Session.ID)
	}

	if wantSSE {
		// SSE streaming mode: respond with text/event-stream
		t.writeSSEResponse(w, resp)
		return
	}

	// Plain JSON response mode
	w.Header().Set("Content-Type", "application/json")
	if resp == nil {
		// Notification — no response expected
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// acceptsSSE checks if the client's Accept header includes text/event-stream.
func acceptsSSE(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		mediaType := strings.TrimSpace(strings.Split(part, ";")[0])
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}

// writeSSEResponse writes a JSON-RPC response (or notification ack) as an
// SSE event stream. For responses, it sends a single data event. For
// notifications (nil response), it sends a comment ack and closes.
func (t *streamableHTTPTransport) writeSSEResponse(w http.ResponseWriter, resp *JSONRPCResponse) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	if resp == nil {
		// Notification — send comment ack, no data event
		_, _ = w.Write([]byte(": ack\n\n"))
		if canFlush {
			flusher.Flush()
		}
		return
	}

	// Write the JSON-RPC response as an SSE data event
	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("failed to marshal SSE response", "error", err)
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	if canFlush {
		flusher.Flush()
	}
}

// makeNotificationCallback creates a NotificationCallback that writes
// server-initiated notifications as SSE events to the given ResponseWriter.
// This is used for P2 (list_changed) and P3 (resources/updated) notifications.
func (t *streamableHTTPTransport) makeNotificationCallback(w http.ResponseWriter) NotificationCallback {
	flusher, canFlush := w.(http.Flusher)
	return func(method string, params interface{}) {
		notification := JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			Result: map[string]interface{}{
				"method": method,
				"params": params,
			},
		}
		// For notifications, we use a nil ID to indicate no response expected
		notification.ID = nil
		data, err := json.Marshal(notification)
		if err != nil {
			slog.Error("failed to marshal notification", "error", err)
			return
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		if canFlush {
			flusher.Flush()
		}
	}
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
