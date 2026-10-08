// SPDX-License-Identifier: Apache-2.0
// MCP Server — JSON-RPC over TCP, based on AegisGate Platform upstream server.go
// Zero external dependencies, Go stdlib only.

package mcpsecurity

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Connection represents an active MCP connection.
type Connection struct {
	ID         string
	Conn       net.Conn
	CreatedAt  time.Time
	lastSeen   atomic.Value // time.Time — hot path, lock-free
	LastSeen   time.Time    // set at creation, kept in sync via lastSeen
	Session    *Session
	ClientInfo *ClientInfo
	AgentID    string
	mu         sync.RWMutex // protects Session, ClientInfo, AgentID (infrequent writes)
}

// GetLastSeen returns the last time this connection received a message.
func (c *Connection) GetLastSeen() time.Time {
	if v := c.lastSeen.Load(); v != nil {
		return v.(time.Time)
	}
	return c.LastSeen
}

// SetLastSeen atomically updates the last-seen timestamp.
func (c *Connection) SetLastSeen(t time.Time) {
	c.lastSeen.Store(t)
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	Address        string
	Handler        *RequestHandler
	HandleFunc     HandlerFunc
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxConnections int         // 0 = unlimited
	TLSConfig      *tls.Config // if non-nil, wraps listener with TLS
}

// ErrTooManyConnections is returned when the server rejects a connection
// because the MaxConnections limit has been reached.
var ErrTooManyConnections = errors.New("max_connections_reached")

// Server represents an MCP server instance.
type Server struct {
	config      *ServerConfig
	listener    net.Listener
	handler     *RequestHandler
	handleFunc  HandlerFunc
	connections map[string]*Connection
	connMu      sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewServer creates a new MCP server.
func NewServer(cfg *ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 1000 // default cap; set -1 for unlimited
	}
	return &Server{
		config:      cfg,
		handler:     cfg.Handler,
		handleFunc:  cfg.HandleFunc,
		connections: make(map[string]*Connection),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// StartContext begins listening with context support.
func (s *Server) StartContext(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	ln, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Address, err)
	}
	// Wrap with TLS if configured
	if s.config.TLSConfig != nil {
		ln = tls.NewListener(ln, s.config.TLSConfig)
		slog.Info("MCP server TLS enabled", "address", s.config.Address,
			"min_version", s.config.TLSConfig.MinVersion,
			"mtls", s.config.TLSConfig.ClientAuth == tls.RequireAndVerifyClientCert)
	}
	s.listener = ln
	slog.Info("MCP server listening", "address", s.config.Address)
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	slog.Info("MCP server shutting down...")
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	s.connMu.Lock()
	for id, conn := range s.connections {
		conn.Conn.Close()
		delete(s.connections, id)
	}
	s.connMu.Unlock()
	s.wg.Wait()
	slog.Info("MCP server stopped")
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}
		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			slog.Error("MCP server accept error", "error", err)
			continue
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(nc net.Conn) {
	defer s.wg.Done()
	connID := fmt.Sprintf("conn-%d-%s", time.Now().UnixNano(), randomSuffix(8))
	conn := &Connection{
		ID:        connID,
		Conn:      nc,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &Session{ID: connID},
	}
	conn.SetLastSeen(time.Now()) // initialize atomic lastSeen

	// Check connection cap before registering
	if s.config.MaxConnections > 0 {
		s.connMu.RLock()
		active := len(s.connections)
		s.connMu.RUnlock()
		if active >= s.config.MaxConnections {
			slog.Warn("connection rejected: max_connections reached",
				"active", active, "max", s.config.MaxConnections)
			nc.Close()
			return
		}
	}

	s.connMu.Lock()
	s.connections[connID] = conn
	s.connMu.Unlock()
	defer func() {
		s.connMu.Lock()
		delete(s.connections, connID)
		s.connMu.Unlock()
		nc.Close()
	}()
	slog.Info("MCP connection established", "conn_id", connID)
	s.handleMCPProtocol(conn)
}

func (s *Server) handleMCPProtocol(conn *Connection) {
	decoder := json.NewDecoder(io.LimitReader(conn.Conn, 1<<20))
	encoder := json.NewEncoder(conn.Conn)

	// Batch LastSeen updates — only update every 5 seconds, not on every message.
	// This avoids lock contention on the hot path while still providing accurate
	// idle timeout detection.
	lastSeenBatch := time.Now()
	const lastSeenInterval = 5 * time.Second

	for {
		conn.Conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))
		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if time.Since(conn.GetLastSeen()) > s.config.IdleTimeout {
					return
				}
				continue
			}
			return
		}

		// Batch LastSeen update — only if interval has elapsed
		now := time.Now()
		if now.Sub(lastSeenBatch) >= lastSeenInterval {
			conn.SetLastSeen(now)
			lastSeenBatch = now
		}

		var resp *JSONRPCResponse
		if s.handleFunc != nil {
			resp = s.handleFunc(conn, &req)
		} else if s.handler != nil {
			resp = s.handler.HandleRequest(conn, &req)
		} else {
			resp = &JSONRPCResponse{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Error:   &JSONRPCError{Code: ErrorInternal, Message: "no handler configured"},
			}
		}
		// Notifications (no ID) may return nil to skip the response
		if resp == nil {
			continue
		}
		conn.Conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

// SetHandleFunc sets a custom handler function.
func (s *Server) SetHandleFunc(fn HandlerFunc) {
	s.handleFunc = fn
}

// ConnectionCount returns the number of active connections.
func (s *Server) ConnectionCount() int {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return len(s.connections)
}

// randomSuffix generates a random hex suffix of the given length.
func randomSuffix(n int) string {
	b := make([]byte, n/2+1)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
