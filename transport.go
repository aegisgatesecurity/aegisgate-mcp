// SPDX-License-Identifier: Apache-2.0
// Transport — stdio transport and health endpoint for the MCP server.
// Zero external dependencies. Go standard library only.

package mcpsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ServeOptions configures how the server runs (transport mode, health endpoint).
type ServeOptions struct {
	Transport  string // "tcp" (default) or "stdio"
	HealthAddr string // if non-empty, starts a health HTTP listener on this address
}

// DefaultServeOptions returns default serve options.
func DefaultServeOptions() *ServeOptions {
	return &ServeOptions{
		Transport:  "tcp",
		HealthAddr: "",
	}
}

// ============================================================
// stdio Transport
// ============================================================

// stdioTransport reads JSON-RPC requests from stdin and writes responses to stdout.
// This is the standard transport for local MCP clients (Claude Desktop, Cursor, etc.).
type stdioTransport struct {
	handler HandlerFunc
	encoder *json.Encoder
	decoder *json.Decoder
	conn    *Connection
	mu      sync.Mutex
}

// newStdioTransport creates a stdio transport that uses the given handler.
func newStdioTransport(handler HandlerFunc) *stdioTransport {
	conn := &Connection{
		ID:        "stdio",
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &Session{ID: "stdio"},
	}
	return &stdioTransport{
		handler: handler,
		encoder: json.NewEncoder(os.Stdout),
		decoder: json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)),
		conn:    conn,
	}
}

// run reads and processes requests until stdin is closed or context is cancelled.
func (t *stdioTransport) run(ctx context.Context) error {
	slog.Info("MCP server stdio transport ready")

	// Channel to signal decoder has stopped (stdin closed)
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- t.readLoop(ctx)
	}()

	select {
	case <-ctx.Done():
		slog.Info("stdio transport: context cancelled, shutting down")
		return nil
	case err := <-doneCh:
		if err != nil && err != io.EOF {
			slog.Error("stdio transport error", "error", err)
		}
		return nil
	}
}

func (t *stdioTransport) readLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		var req JSONRPCRequest
		if err := t.decoder.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		t.conn.SetLastSeen(time.Now())

		resp := t.handler(t.conn, &req)
		// Notifications (no ID) may return nil to skip the response
		if resp == nil {
			continue
		}
		t.mu.Lock()
		if err := t.encoder.Encode(resp); err != nil {
			t.mu.Unlock()
			return fmt.Errorf("encode response: %w", err)
		}
		t.mu.Unlock()
	}
}

// ============================================================
// Health Endpoint
// ============================================================

// healthServer provides a simple HTTP health/readiness endpoint.
// Returns JSON with server status and runtime statistics.
type healthServer struct {
	addr      string
	lnAddr    string // actual listening address
	server    *SecuredMCPServer
	httpSrv   *http.Server
	startTime time.Time
}

// newHealthServer creates a health endpoint server.
func newHealthServer(addr string, srv *SecuredMCPServer) *healthServer {
	mux := http.NewServeMux()
	hs := &healthServer{
		addr:      addr,
		server:    srv,
		httpSrv:   &http.Server{Addr: addr, Handler: mux},
		startTime: time.Now(),
	}

	mux.HandleFunc("/healthz", hs.handleHealth)
	mux.HandleFunc("/readyz", hs.handleReady)
	mux.HandleFunc("/stats", hs.handleStats)
	mux.HandleFunc("/metrics", hs.handlePrometheus)

	return hs
}

// start begins listening for health check requests.
func (h *healthServer) start(ctx context.Context) error {
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("health endpoint listen %s: %w", h.addr, err)
	}
	h.lnAddr = ln.Addr().String()
	slog.Info("health endpoint listening", "address", h.lnAddr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.httpSrv.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := h.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("health endpoint error", "error", err)
		}
	}()

	return nil
}

// startHealthListener is a test helper that starts the HTTP server listener
// without the context management, returning the listener for address discovery.
func startHealthListener(hs *healthServer) (net.Listener, error) {
	ln, err := net.Listen("tcp", hs.addr)
	if err != nil {
		return nil, err
	}
	hs.httpSrv.Addr = ln.Addr().String()
	go func() {
		if err := hs.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("health endpoint error", "error", err)
		}
	}()
	return ln, nil
}

func (h *healthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"version":  Version,
		"uptime_s": int(time.Since(h.startTime).Seconds()),
	})
}

func (h *healthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

func (h *healthServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.server == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "server not available"})
		return
	}
	json.NewEncoder(w).Encode(h.server.Stats())
}

// handlePrometheus emits metrics in Prometheus text exposition format.
// No external libraries — plain text format per the Prometheus spec.
func (h *healthServer) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if h.server == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	stats := h.server.Stats()

	var buf strings.Builder
	buf.WriteString("# HELP aegisgate_mcp_tools_registered Number of registered tools\n")
	buf.WriteString("# TYPE aegisgate_mcp_tools_registered gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_tools_registered %v\n", stats["tools_registered"])

	buf.WriteString("# HELP aegisgate_mcp_active_sessions Number of active sessions\n")
	buf.WriteString("# TYPE aegisgate_mcp_active_sessions gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_active_sessions %v\n", stats["active_sessions"])

	buf.WriteString("# HELP aegisgate_mcp_active_connections Number of active TCP connections\n")
	buf.WriteString("# TYPE aegisgate_mcp_active_connections gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_active_connections %v\n", stats["active_connections"])

	buf.WriteString("# HELP aegisgate_mcp_max_connections Maximum concurrent TCP connections\n")
	buf.WriteString("# TYPE aegisgate_mcp_max_connections gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_max_connections %v\n", stats["max_connections"])

	buf.WriteString("# HELP aegisgate_mcp_audit_entries Number of audit log entries\n")
	buf.WriteString("# TYPE aegisgate_mcp_audit_entries gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_audit_entries %v\n", stats["audit_entries"])

	buf.WriteString("# HELP aegisgate_mcp_trusted_keys Number of trusted signature keys\n")
	buf.WriteString("# TYPE aegisgate_mcp_trusted_keys gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_trusted_keys %v\n", stats["trusted_keys"])

	buf.WriteString("# HELP aegisgate_mcp_policy_rules Number of policy rules\n")
	buf.WriteString("# TYPE aegisgate_mcp_policy_rules gauge\n")
	fmt.Fprintf(&buf, "aegisgate_mcp_policy_rules %v\n", stats["policy_rules"])

	// Guardrail stats if available
	if guardrails, ok := stats["guardrails"].(map[string]interface{}); ok {
		if rl, ok := guardrails["rate_limit_rpm"]; ok {
			buf.WriteString("# HELP aegisgate_mcp_rate_limit_rpm Configured rate limit per minute\n")
			buf.WriteString("# TYPE aegisgate_mcp_rate_limit_rpm gauge\n")
			fmt.Fprintf(&buf, "aegisgate_mcp_rate_limit_rpm %v\n", rl)
		}
		if ms, ok := guardrails["max_sessions"]; ok {
			buf.WriteString("# HELP aegisgate_mcp_max_sessions Maximum concurrent sessions\n")
			buf.WriteString("# TYPE aegisgate_mcp_max_sessions gauge\n")
			fmt.Fprintf(&buf, "aegisgate_mcp_max_sessions %v\n", ms)
		}
	}

	buf.WriteString("# HELP aegisgate_mcp_up Server is running\n")
	buf.WriteString("# TYPE aegisgate_mcp_up gauge\n")
	buf.WriteString("aegisgate_mcp_up 1\n")

	w.Write([]byte(buf.String()))
}
