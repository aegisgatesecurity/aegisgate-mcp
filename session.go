// SPDX-License-Identifier: Apache-2.0
// Session Manager — tracks MCP sessions with expiry and anti-hijacking.
// Based on AegisGate Platform session_manager.go + upstream context-isolator.

package mcpsecurity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// SessionConfig holds session management configuration.
type SessionConfig struct {
	MaxSessions    int           // Maximum concurrent sessions (default: 100)
	SessionTimeout time.Duration // Session expiry (default: 1h)
	CleanupPeriod  time.Duration // Cleanup interval (default: 5m)
}

// DefaultSessionConfig returns sensible defaults.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		MaxSessions:    100,
		SessionTimeout: 1 * time.Hour,
		CleanupPeriod:  5 * time.Minute,
	}
}

// ManagedSession represents a tracked MCP session.
type ManagedSession struct {
	ID        string
	AgentID   string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
	mu        sync.RWMutex
}

// IsExpired returns true if the session has expired.
func (s *ManagedSession) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Now().After(s.ExpiresAt)
}

// Touch updates the last-seen timestamp.
func (s *ManagedSession) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
}

// InMemorySessionManager is a thread-safe in-memory session manager.
type InMemorySessionManager struct {
	config   *SessionConfig
	mu       sync.RWMutex
	sessions map[string]*ManagedSession
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewInMemorySessionManager creates a new session manager.
func NewInMemorySessionManager(cfg *SessionConfig) *InMemorySessionManager {
	if cfg == nil {
		cfg = DefaultSessionConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &InMemorySessionManager{
		config:   cfg,
		sessions: make(map[string]*ManagedSession),
		ctx:      ctx,
		cancel:   cancel,
	}
	go mgr.cleanupLoop()
	return mgr
}

// CreateSession implements SessionManager interface.
func (m *InMemorySessionManager) CreateSession(ctx context.Context, agentID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= m.config.MaxSessions {
		return nil, fmt.Errorf("max sessions reached (%d)", m.config.MaxSessions)
	}
	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	now := time.Now()
	ms := &ManagedSession{
		ID:        id,
		AgentID:   agentID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.config.SessionTimeout),
		LastSeen:  now,
	}
	m.sessions[id] = ms
	slog.Info("session created", "session_id", id, "agent_id", agentID)
	return &Session{ID: id, AgentID: agentID}, nil
}

// GetSession implements SessionManager interface.
func (m *InMemorySessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	m.mu.RLock()
	ms, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	if ms.IsExpired() {
		m.mu.Lock()
		delete(m.sessions, sessionID)
		m.mu.Unlock()
		return nil, ErrSessionExpired
	}
	ms.Touch()
	return &Session{ID: ms.ID, AgentID: ms.AgentID}, nil
}

// DeleteSession implements SessionManager interface.
func (m *InMemorySessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionID]; !ok {
		return ErrSessionNotFound
	}
	delete(m.sessions, sessionID)
	slog.Info("session deleted", "session_id", sessionID)
	return nil
}

// ActiveCount returns the number of active sessions.
func (m *InMemorySessionManager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Stop shuts down the session manager and cleanup goroutine.
func (m *InMemorySessionManager) Stop() {
	m.cancel()
}

func (m *InMemorySessionManager) cleanupLoop() {
	ticker := time.NewTicker(m.config.CleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for id, s := range m.sessions {
				if now.After(s.ExpiresAt) {
					delete(m.sessions, id)
					slog.Debug("expired session cleaned up", "session_id", id)
				}
			}
			m.mu.Unlock()
		}
	}
}

// generateSessionID creates a cryptographically random session ID.
// 32 bytes = 256 bits of entropy, hex-encoded to 64 chars.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
