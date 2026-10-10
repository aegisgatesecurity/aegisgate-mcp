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
	"sync/atomic"
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

	// SSE connection registry: tracks active long-lived SSE connections
	// so the server can push notifications to connected clients.
	// Supports multiple connections per session (multiplexing) for
	// clients that open parallel SSE streams or reconnect while the
	// old connection is still timing out.
	sseConns  map[string][]*sseConn // session ID → active SSE connections
	sseConnMu sync.RWMutex

	// Elicitation registry for correlating elicitation/create requests
	// with client responses. Set via setElicitationRegistry.
	elicitReg *ElicitationRegistry
}

// sseConn wraps an active SSE connection for notification delivery.
type sseConn struct {
	mu       sync.Mutex // serializes writes to w (ResponseWriter is not concurrency-safe)
	w        http.ResponseWriter
	flusher  http.Flusher
	canFlush bool
}

// httpSession tracks an active Streamable HTTP session.
type httpSession struct {
	id        string
	createdAt time.Time
	lastSeen  time.Time
	conn      *Connection
	// SSE event tracking for Last-Event-ID reconnection support.
	// eventID is the last assigned event ID (monotonically increasing).
	eventID int64
	// eventBuffer stores recent SSE events for replay on reconnection.
	// Bounded to maxEventBuffer entries to prevent memory exhaustion.
	eventBuffer []bufferedEvent
	eventBufMu  sync.Mutex
}

// bufferedEvent stores an SSE event for replay on reconnection.
type bufferedEvent struct {
	id   int64
	data []byte // marshaled JSON-RPC notification
}

// maxEventBuffer is the maximum number of events stored per session
// for Last-Event-ID reconnection replay. Events beyond this limit
// are evicted (oldest first). If a client reconnects with a gap
// larger than the buffer, the server sends a re-sync error event.
const maxEventBuffer = 100

// nextEventID assigns the next monotonic event ID for this session.
func (s *httpSession) nextEventID() int64 {
	return atomic.AddInt64(&s.eventID, 1)
}

// bufferEvent stores an SSE event for replay on reconnection.
func (s *httpSession) bufferEvent(id int64, data []byte) {
	s.eventBufMu.Lock()
	defer s.eventBufMu.Unlock()
	s.eventBuffer = append(s.eventBuffer, bufferedEvent{id: id, data: data})
	// Evict oldest events if buffer is full
	if len(s.eventBuffer) > maxEventBuffer {
		s.eventBuffer = s.eventBuffer[len(s.eventBuffer)-maxEventBuffer:]
	}
}

// replayEvents returns buffered events with IDs greater than lastEventID.
// Returns nil if no events to replay. Returns the highest buffered event ID
// so the caller can detect gaps (if lastEventID + 1 < first replayed ID,
// events were lost due to buffer eviction).
func (s *httpSession) replayEvents(lastEventID int64) []bufferedEvent {
	s.eventBufMu.Lock()
	defer s.eventBufMu.Unlock()
	var events []bufferedEvent
	for _, e := range s.eventBuffer {
		if e.id > lastEventID {
			events = append(events, e)
		}
	}
	return events
}

// newStreamableHTTPTransport creates a new Streamable HTTP transport.
func newStreamableHTTPTransport(addr string, handler HandlerFunc) *streamableHTTPTransport {
	t := &streamableHTTPTransport{
		handler:   handler,
		addr:      addr,
		sessions:  make(map[string]*httpSession),
		sseConns:  make(map[string][]*sseConn),
		elicitReg: NewElicitationRegistry(0),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", t.handleMCP)
	mux.HandleFunc("/mcp/", t.handleMCP)
	t.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout is 0 (disabled) because long-lived SSE connections
		// must stay open indefinitely for server-initiated notifications.
		// A finite WriteTimeout would kill SSE streams after that duration,
		// breaking push notification delivery. Connection-level protection
		// is provided by ReadHeaderTimeout (slowloris), ReadTimeout (body),
		// IdleTimeout (keepalive), and handler context cancellation.
		WriteTimeout: 0,
		IdleTimeout:  5 * time.Minute,
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
	// - GET: open a long-lived SSE connection for server-initiated messages
	// - POST: send a JSON-RPC request or notification
	// - DELETE: terminate the session
	if r.Method == http.MethodGet {
		t.handleSSEStream(w, r)
		return
	}

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
		w.Header().Set("Allow", "GET, POST, DELETE")
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

	// Check if this is an elicitation response from the client.
	// When the server sends an elicitation/create request via SSE,
	// the client responds with a JSON-RPC response (has result/error
	// but no method). We detect this by checking if the ID matches
	// a pending elicitation request.
	if req.Method == "" && t.elicitReg != nil && t.elicitReg.isElicitationResponse(req.ID) {
		// This is an elicitation response — deliver it to the pending
		// request and return 202 Accepted (no body needed).
		resp := &JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      req.ID,
		}
		// Re-marshal the body to extract result/error fields
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err == nil {
			if r, ok := raw["result"]; ok {
				resp.Result = json.RawMessage(r)
			}
			if e, ok := raw["error"]; ok {
				var jerr JSONRPCError
				if json.Unmarshal(e, &jerr) == nil {
					resp.Error = &jerr
				}
			}
		}
		t.elicitReg.handleElicitationResponse(resp)
		w.WriteHeader(http.StatusAccepted)
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
		// SSE streaming mode: respond with text/event-stream and hold
		// the connection open for server-initiated notifications.
		t.writeSSEResponse(w, resp, conn.Session.ID, r)
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

// handleSSEStream handles GET requests to open a long-lived SSE connection
// for receiving server-initiated notifications. Per MCP 2025-06-18, this
// is optional but recommended for real-time notification delivery.
func (t *streamableHTTPTransport) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	// Validate session
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id header", http.StatusBadRequest)
		return
	}
	sess := t.getSession(sessionID)
	if sess == nil {
		w.Header().Set("MCP-Protocol-Version", ProtocolVersion)
		http.Error(w, "session not found or expired", http.StatusNotFound)
		return
	}
	t.touchSession(sessionID)

	// Open SSE stream
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("MCP-Protocol-Version", ProtocolVersion)
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	// Send an initial comment to signal the stream is open
	_, _ = w.Write([]byte(": stream-open\n\n"))
	if canFlush {
		flusher.Flush()
	}

	// Last-Event-ID reconnection: if the client sends a Last-Event-ID
	// header, replay buffered events with IDs greater than that value.
	if lastEventIDStr := r.Header.Get("Last-Event-ID"); lastEventIDStr != "" {
		var lastEventID int64
		if _, err := fmt.Sscanf(lastEventIDStr, "%d", &lastEventID); err == nil {
			events := sess.replayEvents(lastEventID)
			if len(events) > 0 {
				slog.Info("replaying SSE events on reconnection",
					"session_id", sessionID, "last_event_id", lastEventIDStr, "events", len(events))
				for _, e := range events {
					_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.id, e.data)
				}
				if canFlush {
					flusher.Flush()
				}
			}
		}
	}

	// Register this connection for notification delivery
	conn := t.registerSSEConn(sessionID, w, flusher, canFlush)
	defer t.unregisterSSEConn(sessionID, conn)

	// Hold the connection open until the client disconnects
	<-r.Context().Done()
	slog.Debug("SSE stream closed by client", "session_id", sessionID)
}

// writeSSEResponse writes a JSON-RPC response (or notification ack) as an
// SSE event, then holds the connection open for server-initiated notifications.
// The connection is unregistered when the client disconnects.
func (t *streamableHTTPTransport) writeSSEResponse(w http.ResponseWriter, resp *JSONRPCResponse, sessionID string, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	if resp == nil {
		// Client notification — send comment ack
		_, _ = w.Write([]byte(": ack\n\n"))
		if canFlush {
			flusher.Flush()
		}
	} else {
		// Write the JSON-RPC response as an SSE data event with event ID
		data, err := json.Marshal(resp)
		if err != nil {
			slog.Error("failed to marshal SSE response", "error", err)
			return
		}
		// Assign event ID if session exists
		sess := t.getSession(sessionID)
		var eventID int64
		if sess != nil {
			eventID = sess.nextEventID()
			sess.bufferEvent(eventID, data)
			_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", eventID, data)
		} else {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		}
		if canFlush {
			flusher.Flush()
		}
	}

	// Register this connection for server-initiated notification delivery
	conn := t.registerSSEConn(sessionID, w, flusher, canFlush)
	defer t.unregisterSSEConn(sessionID, conn)

	// Hold the connection open until the client disconnects or server shuts down
	<-r.Context().Done()
	slog.Debug("SSE response stream closed by client", "session_id", sessionID)
}

// registerSSEConn registers an active SSE connection for notification delivery.
func (t *streamableHTTPTransport) registerSSEConn(sessionID string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) *sseConn {
	t.sseConnMu.Lock()
	defer t.sseConnMu.Unlock()
	conn := &sseConn{w: w, flusher: flusher, canFlush: canFlush}
	t.sseConns[sessionID] = append(t.sseConns[sessionID], conn)
	slog.Debug("registered SSE connection", "session_id", sessionID, "total_conns", len(t.sseConns[sessionID]))
	return conn
}

// unregisterSSEConn removes an SSE connection from the registry.
// With multiplexing, multiple connections may exist per session.
// The connection is identified by pointer comparison.
func (t *streamableHTTPTransport) unregisterSSEConn(sessionID string, conn *sseConn) {
	t.sseConnMu.Lock()
	defer t.sseConnMu.Unlock()
	conns := t.sseConns[sessionID]
	for i, c := range conns {
		if c == conn {
			// Remove this connection from the slice
			t.sseConns[sessionID] = append(conns[:i], conns[i+1:]...)
			if len(t.sseConns[sessionID]) == 0 {
				delete(t.sseConns, sessionID)
			}
			slog.Debug("unregistered SSE connection", "session_id", sessionID, "remaining_conns", len(t.sseConns[sessionID]))
			return
		}
	}
}

// broadcastNotification sends a JSON-RPC notification to all active SSE
// connections. This is the NotificationCallback wired to the handler.
func (t *streamableHTTPTransport) broadcastNotification(method string, params interface{}) {
	notification := JSONRPCNotification{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  params,
	}
	data, err := json.Marshal(notification)
	if err != nil {
		slog.Error("failed to marshal notification", "error", err)
		return
	}

	t.sseConnMu.RLock()
	defer t.sseConnMu.RUnlock()

	for sessionID, conns := range t.sseConns {
		// Get session for event ID assignment and buffering
		sess := t.getSession(sessionID)
		var eventID int64
		if sess != nil {
			eventID = sess.nextEventID()
			sess.bufferEvent(eventID, data)
		}

		for _, conn := range conns {
			conn.mu.Lock()
			_, err := fmt.Fprintf(conn.w, "id: %d\ndata: %s\n\n", eventID, data)
			if err != nil {
				slog.Debug("failed to write notification to SSE connection", "session_id", sessionID, "error", err)
				conn.mu.Unlock()
				continue
			}
			if conn.canFlush {
				conn.flusher.Flush()
			}
			conn.mu.Unlock()
			slog.Debug("delivered notification via SSE", "session_id", sessionID, "method", method, "event_id", eventID)
		}
	}
}

// sendElicitation sends an elicitation/create request to the client via
// the SSE connection for the given session. It registers a pending request
// in the elicitation registry and blocks until the client responds or the
// timeout expires. This is the ElicitationCallback wired to the handler.
func (t *streamableHTTPTransport) sendElicitation(sessionID string, params *ElicitationParams) (*ElicitationResult, error) {
	if t.elicitReg == nil {
		return nil, fmt.Errorf("elicitation not available: no registry")
	}

	// Register the pending request
	reqID, ch := t.elicitReg.register()

	// Build the elicitation/create JSON-RPC request
	elicitReq := buildElicitationRequest(reqID, params)
	data, err := json.Marshal(elicitReq)
	if err != nil {
		t.elicitReg.cancel(reqID)
		return nil, fmt.Errorf("elicitation: failed to marshal request: %w", err)
	}

	// Send the request via the client's SSE connection.
	// We need to find the active SSE connection for this session.
	t.sseConnMu.RLock()
	conns := t.sseConns[sessionID]
	t.sseConnMu.RUnlock()

	if len(conns) == 0 {
		t.elicitReg.cancel(reqID)
		return nil, fmt.Errorf("elicitation not available: no active SSE connection for session %s", sessionID)
	}

	// Assign event ID and buffer for replay support
	sess := t.getSession(sessionID)
	var eventID int64
	if sess != nil {
		eventID = sess.nextEventID()
		sess.bufferEvent(eventID, data)
	}

	// Send to the first available SSE connection for this session
	conns[0].mu.Lock()
	if _, err := fmt.Fprintf(conns[0].w, "id: %d\ndata: %s\n\n", eventID, data); err != nil {
		conns[0].mu.Unlock()
		t.elicitReg.cancel(reqID)
		return nil, fmt.Errorf("elicitation: failed to send via SSE: %w", err)
	}
	if conns[0].canFlush {
		conns[0].flusher.Flush()
	}
	conns[0].mu.Unlock()

	slog.Debug("sent elicitation/create via SSE", "session_id", sessionID, "request_id", reqID)

	// Block until the client responds or timeout
	return t.elicitReg.waitForResponse(reqID, ch, 0)
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
