// SPDX-License-Identifier: Apache-2.0
// Guardrails — rate limiting, tool call limits, parameter validation, chain analysis.
// Based on AegisGate Platform pkg/mcpserver/guardrails.go + pkg/toolauth/chain_analyzer.go.

package mcpsecurity

import (
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Guardrail error codes.
const (
	ErrMaxSessions       = "max_sessions_reached"
	ErrSessionToolLimit  = "session_tool_limit_reached"
	ErrExecTimeout       = "execution_timeout"
	ErrRateLimitExceeded = "rate_limit_exceeded"
)

// GuardrailConfig holds configuration for the guardrail middleware.
type GuardrailConfig struct {
	MaxSessions        int           // Max concurrent sessions (default: 50)
	MaxToolsPerSession int           // Max tool calls per session (default: 100)
	ExecTimeout        time.Duration // Max tool execution time (default: 30s)
	RateLimitRPM       int           // Rate limit requests per minute (default: 60)
	Enabled            bool
}

// DefaultGuardrailConfig returns sensible defaults.
func DefaultGuardrailConfig() *GuardrailConfig {
	return &GuardrailConfig{
		MaxSessions:        50,
		MaxToolsPerSession: 100,
		ExecTimeout:        30 * time.Second,
		RateLimitRPM:       60,
		Enabled:            true,
	}
}

// sessionState tracks per-session guardrail counters.
type sessionState struct {
	ID         string
	AgentID    string
	ToolCount  int64
	CreatedAt  time.Time
	LastSeen   time.Time
	ClientAddr string
}

// rateBucket is a token bucket for per-connection rate limiting.
// Unlike a fixed-window counter, the token bucket allows short bursts
// up to the capacity while maintaining the average rate over time.
// Tokens refill at a rate of RateLimitRPM tokens per minute.
type rateBucket struct {
	tokens         int64
	capacity       int64
	lastRefillTime time.Time
}

// GuardrailMiddleware enforces guardrails on MCP requests.
type GuardrailMiddleware struct {
	config      *GuardrailConfig
	mu          sync.RWMutex
	sessions    map[string]*sessionState
	rateBuckets map[string]*rateBucket
	chain       *ChainAnalyzer
	registry    *ToolRegistry
}

// NewGuardrailMiddleware creates a new guardrail middleware.
func NewGuardrailMiddleware(cfg *GuardrailConfig, registry *ToolRegistry) *GuardrailMiddleware {
	if cfg == nil {
		cfg = DefaultGuardrailConfig()
	}
	return &GuardrailMiddleware{
		config:      cfg,
		sessions:    make(map[string]*sessionState),
		rateBuckets: make(map[string]*rateBucket),
		chain:       NewChainAnalyzer(),
		registry:    registry,
	}
}

// GuardrailHandler wraps a HandlerFunc with guardrail checks.
func (g *GuardrailMiddleware) GuardrailHandler(inner HandlerFunc) HandlerFunc {
	if !g.config.Enabled {
		return inner
	}
	return func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		// Only guard tool calls
		if req.Method != "tools/call" && req.Method != "tool/call" {
			return inner(conn, req)
		}

		sessionID := "anonymous"
		if conn.Session != nil {
			sessionID = conn.Session.ID
		}

		// Max sessions check
		if g.config.MaxSessions > 0 {
			g.mu.RLock()
			activeCount := len(g.sessions)
			g.mu.RUnlock()
			if activeCount >= g.config.MaxSessions {
				// Allow if this session already exists (not a new one)
				g.mu.RLock()
				_, exists := g.sessions[sessionID]
				g.mu.RUnlock()
				if !exists {
					slog.Warn("max sessions exceeded", "active", activeCount, "max", g.config.MaxSessions)
					return &JSONRPCResponse{
						JSONRPC: JSONRPCVersion, ID: req.ID,
						Error: &JSONRPCError{Code: ErrorForbidden, Message: ErrMaxSessions},
					}
				}
			}
		}

		// Rate limit check
		if g.config.RateLimitRPM > 0 {
			if !g.checkRateLimit(conn.ID) {
				slog.Warn("rate limit exceeded", "conn_id", conn.ID)
				return &JSONRPCResponse{
					JSONRPC: JSONRPCVersion, ID: req.ID,
					Error: &JSONRPCError{Code: ErrorRateLimited, Message: ErrRateLimitExceeded},
				}
			}
		}

		// Session tracking
		state := g.getOrCreateSession(sessionID, conn)

		// Tool count limit
		count := atomic.AddInt64(&state.ToolCount, 1)
		if g.config.MaxToolsPerSession > 0 && count > int64(g.config.MaxToolsPerSession) {
			slog.Warn("session tool limit", "session_id", sessionID, "count", count)
			return &JSONRPCResponse{
				JSONRPC: JSONRPCVersion, ID: req.ID,
				Error: &JSONRPCError{Code: ErrorForbidden, Message: ErrSessionToolLimit},
			}
		}

		// Extract tool name for logging and chain analysis
		toolName := extractToolName(req)
		if toolName != "" {
			// Chain analysis
			chainResult := g.chain.RecordCall(sessionID, toolName)
			if chainResult != nil && chainResult.OverallRisk == ChainRiskHigh {
				slog.Warn("chain analysis: high risk detected",
					"session_id", sessionID, "tool", toolName,
					"flags", chainResult.Flags, "call_count", chainResult.CallCount)
			}
		}

		return inner(conn, req)
	}
}

// checkRateLimit implements token bucket rate limiting per connection.
// Tokens refill at RateLimitRPM tokens per minute. The bucket capacity
// is set to RateLimitRPM (allowing a full minute's worth of requests in
// a burst). When tokens are depleted, requests are denied until the
// next refill.
func (g *GuardrailMiddleware) checkRateLimit(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	capacity := int64(g.config.RateLimitRPM)
	bucket, ok := g.rateBuckets[key]
	if !ok {
		// Initialize bucket with full capacity and consume first token
		g.rateBuckets[key] = &rateBucket{
			tokens:         capacity - 1, // consume one token on creation
			capacity:       capacity,
			lastRefillTime: now,
		}
		return true
	}

	// Refill tokens based on elapsed time.
	// Refill rate: RateLimitRPM tokens per 60 seconds.
	// tokensToAdd = elapsed_seconds * RateLimitRPM / 60
	elapsed := now.Sub(bucket.lastRefillTime)
	if elapsed > 0 {
		refillRate := float64(g.config.RateLimitRPM) / 60.0 // tokens per second
		tokensToAdd := int64(elapsed.Seconds() * refillRate)
		if tokensToAdd > 0 {
			bucket.tokens += tokensToAdd
			if bucket.tokens > bucket.capacity {
				bucket.tokens = bucket.capacity
			}
			bucket.lastRefillTime = now
		}
	}

	// Check if a token is available
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	return false
}

func (g *GuardrailMiddleware) getOrCreateSession(sessionID string, conn *Connection) *sessionState {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.sessions[sessionID]; ok {
		s.LastSeen = time.Now()
		return s
	}
	agentID := ""
	if conn != nil {
		if conn.Session != nil {
			agentID = conn.Session.AgentID
		}
		if conn.Conn != nil {
			// Safe to get remote addr
		}
	}
	s := &sessionState{
		ID: sessionID, AgentID: agentID,
		CreatedAt: time.Now(), LastSeen: time.Now(),
	}
	g.sessions[sessionID] = s
	return s
}

func extractToolName(req *JSONRPCRequest) string {
	if req.Params == nil {
		return ""
	}
	var params map[string]interface{}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return ""
	}
	if n, ok := params["name"].(string); ok {
		return n
	}
	return ""
}

// ============================================================
// Tool Call Chain Analysis (from pkg/toolauth/chain_analyzer.go)
// ============================================================

// ChainRiskLevel represents the overall risk of a tool call chain.
type ChainRiskLevel int

const (
	ChainRiskLow ChainRiskLevel = iota
	ChainRiskMedium
	ChainRiskHigh
)

func (r ChainRiskLevel) String() string {
	switch r {
	case ChainRiskLow:
		return "low"
	case ChainRiskMedium:
		return "medium"
	case ChainRiskHigh:
		return "high"
	}
	return "unknown"
}

// ChainWindow is the maximum number of tool calls retained for analysis.
const ChainWindow = 20

// ChainResult holds the analysis result for a tool call chain.
type ChainResult struct {
	OverallRisk ChainRiskLevel
	Flags       []string
	CallCount   int
}

// ChainAnalyzer analyzes sequences of tool calls within a session.
type ChainAnalyzer struct {
	mu       sync.RWMutex
	sessions map[string][]string // sessionID → []toolName
}

// NewChainAnalyzer creates a new chain analyzer.
func NewChainAnalyzer() *ChainAnalyzer {
	return &ChainAnalyzer{sessions: make(map[string][]string)}
}

// RecordCall records a tool call and returns a chain risk assessment.
func (c *ChainAnalyzer) RecordCall(sessionID, toolName string) *ChainResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	calls := c.sessions[sessionID]
	calls = append(calls, toolName)
	if len(calls) > ChainWindow {
		calls = calls[len(calls)-ChainWindow:]
	}
	c.sessions[sessionID] = calls

	return c.analyze(calls)
}

func (c *ChainAnalyzer) analyze(calls []string) *ChainResult {
	result := &ChainResult{CallCount: len(calls)}
	if len(calls) < 2 {
		result.OverallRisk = ChainRiskLow
		return result
	}

	// Detect privilege escalation: low-risk → high-risk
	highRiskTools := map[string]bool{"shell_command": true, "file_delete": true, "db_query": true}
	for i := 1; i < len(calls); i++ {
		if highRiskTools[calls[i]] && !highRiskTools[calls[i-1]] {
			result.Flags = append(result.Flags, "privilege_escalation")
		}
	}

	// Detect data exfiltration: read sensitive → write external
	readTools := map[string]bool{"file_read": true, "db_query": true, "code_search": true}
	writeTools := map[string]bool{"http_request": true, "file_write": true, "web_search": true}
	for i := 1; i < len(calls); i++ {
		if readTools[calls[i-1]] && writeTools[calls[i]] {
			result.Flags = append(result.Flags, "data_exfiltration_chain")
		}
	}

	// Detect repeated dangerous tool calls
	dangerousCount := 0
	for _, t := range calls {
		if highRiskTools[t] {
			dangerousCount++
		}
	}
	if dangerousCount >= 3 {
		result.Flags = append(result.Flags, "repeated_dangerous_tools")
	}

	// Set overall risk
	switch {
	case len(result.Flags) >= 2:
		result.OverallRisk = ChainRiskHigh
	case len(result.Flags) == 1:
		result.OverallRisk = ChainRiskHigh
	default:
		result.OverallRisk = ChainRiskLow
	}

	return result
}

// GetChain returns the call history for a session.
func (c *ChainAnalyzer) GetChain(sessionID string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	calls := c.sessions[sessionID]
	out := make([]string, len(calls))
	copy(out, calls)
	return out
}

// ResetSession clears chain data for a session.
func (c *ChainAnalyzer) ResetSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, sessionID)
}

// Stats returns guardrail statistics.
func (g *GuardrailMiddleware) Stats() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return map[string]interface{}{
		"active_sessions":       len(g.sessions),
		"max_sessions":          g.config.MaxSessions,
		"max_tools_per_session": g.config.MaxToolsPerSession,
		"rate_limit_rpm":        g.config.RateLimitRPM,
	}
}
