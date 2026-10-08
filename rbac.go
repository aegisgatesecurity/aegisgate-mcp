// SPDX-License-Identifier: Apache-2.0
// RBAC — Role-Based Access Control for MCP tools.
// Based on AegisGate Platform upstream/aegisguard/pkg/rbac/.

package mcpsecurity

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AgentRole defines the hierarchy of agent roles.
type AgentRole string

const (
	RoleRestricted AgentRole = "restricted" // Read-only, limited tools
	RoleStandard   AgentRole = "standard"   // Standard tool access
	RolePrivileged AgentRole = "privileged" // Elevated access, most tools
	RoleAdmin      AgentRole = "admin"      // Full access, all tools
)

// AtLeast returns true if this role is >= the required role.
func (r AgentRole) AtLeast(required AgentRole) bool {
	order := map[AgentRole]int{
		RoleRestricted: 0, RoleStandard: 1, RolePrivileged: 2, RoleAdmin: 3,
	}
	return order[r] >= order[required]
}

// ToolPermission is a string like "tool:file_read".
type ToolPermission string

const PermToolAll ToolPermission = "tool:*"

// Agent represents an MCP client agent.
type Agent struct {
	ID      string
	Name    string
	Role    AgentRole
	Tools   []ToolPermission
	Enabled bool
	mu      sync.RWMutex
}

// CanExecuteTool checks if the agent can execute a specific tool.
func (a *Agent) CanExecuteTool(toolName string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.Role == RoleAdmin {
		return true
	}
	for _, perm := range a.Tools {
		if perm == PermToolAll {
			return true
		}
		if string(perm) == "tool:"+toolName {
			return true
		}
	}
	// Check role defaults if no explicit permissions
	if len(a.Tools) == 0 {
		return defaultRoleCanExecute(a.Role, toolName)
	}
	return false
}

func defaultRoleCanExecute(role AgentRole, toolName string) bool {
	switch role {
	case RoleRestricted:
		// Restricted: only read-only tools
		safe := map[string]bool{
			"ping": true, "system_info": true, "file_exists": true,
			"git_status": true, "git_log": true, "memory_stats": true,
		}
		return safe[toolName]
	case RoleStandard:
		// Standard: read + low-risk write
		safe := map[string]bool{
			"ping": true, "system_info": true, "file_exists": true,
			"file_read": true, "git_status": true, "git_log": true,
			"git_diff": true, "code_search": true, "web_search": true,
			"memory_stats": true, "network_connections": true,
			"file_copy": true, "file_mkdir": true,
		}
		return safe[toolName]
	case RolePrivileged:
		// Privileged: everything except shell_command and code_execute
		dangerous := map[string]bool{
			"shell_command": true, "code_execute_go": true,
			"code_execute_py": true, "code_execute_js": true,
		}
		return !dangerous[toolName]
	case RoleAdmin:
		return true
	}
	return false
}

// RBACManager manages agents and sessions.
type RBACManager struct {
	mu       sync.RWMutex
	agents   map[string]*Agent
	sessions map[string]*rbacSession
}

type rbacSession struct {
	ID        string
	AgentID   string
	Agent     *Agent
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewRBACManager creates a new RBAC manager.
func NewRBACManager() *RBACManager {
	return &RBACManager{
		agents:   make(map[string]*Agent),
		sessions: make(map[string]*rbacSession),
	}
}

// RegisterAgent registers an agent.
func (m *RBACManager) RegisterAgent(id, name string, role AgentRole, tools []ToolPermission) *Agent {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := &Agent{ID: id, Name: name, Role: role, Tools: tools, Enabled: true}
	m.agents[id] = a
	return a
}

// GetAgent returns an agent by ID.
func (m *RBACManager) GetAgent(agentID string) (*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if !a.Enabled {
		return nil, fmt.Errorf("agent is disabled: %s", agentID)
	}
	return a, nil
}

// CreateSession creates a session for an agent.
func (m *RBACManager) CreateSession(agentID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[agentID]
	if !ok {
		return "", fmt.Errorf("agent not found: %s", agentID)
	}
	if !a.Enabled {
		return "", fmt.Errorf("agent is disabled: %s", agentID)
	}
	sid, err := generateSessionID()
	if err != nil {
		return "", err
	}
	m.sessions[sid] = &rbacSession{
		ID:        sid,
		AgentID:   agentID,
		Agent:     a,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	return sid, nil
}

// GetSession returns a session by ID.
func (m *RBACManager) GetSession(sessionID string) (*rbacSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("invalid session: %s", sessionID)
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, fmt.Errorf("session expired: %s", sessionID)
	}
	return s, nil
}

// AuthorizeToolCall checks if a session's agent can call a tool.
func (m *RBACManager) AuthorizeToolCall(ctx context.Context, sessionID, toolName string) (*AuthorizationDecision, error) {
	s, err := m.GetSession(sessionID)
	if err != nil {
		return &AuthorizationDecision{Allowed: false, Reason: err.Error()}, nil
	}
	if s.Agent == nil {
		return &AuthorizationDecision{Allowed: false, Reason: "agent not found"}, nil
	}
	if !s.Agent.CanExecuteTool(toolName) {
		return &AuthorizationDecision{
			Allowed:     false,
			Reason:      fmt.Sprintf("role '%s' cannot execute tool '%s'", s.Agent.Role, toolName),
			RiskScore:   calculateRiskScore(toolName, s.Agent.Role),
			MatchedRule: string(s.Agent.Role),
		}, nil
	}
	return &AuthorizationDecision{
		Allowed:     true,
		Reason:      "Authorized by RBAC",
		RiskScore:   calculateRiskScore(toolName, s.Agent.Role),
		MatchedRule: string(s.Agent.Role),
	}, nil
}

// RBACAuthorizer implements ToolAuthorizer using RBACManager.
type RBACAuthorizer struct {
	manager *RBACManager
}

// NewRBACAuthorizer creates a new RBAC authorizer.
func NewRBACAuthorizer(manager *RBACManager) *RBACAuthorizer {
	return &RBACAuthorizer{manager: manager}
}

// Authorize implements ToolAuthorizer.
func (a *RBACAuthorizer) Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error) {
	if call.SessionID == "" {
		return &AuthorizationDecision{Allowed: false, Reason: "session ID is required"}, nil
	}
	return a.manager.AuthorizeToolCall(ctx, call.SessionID, call.Name)
}

func calculateRiskScore(toolName string, role AgentRole) int {
	highRisk := map[string]bool{"shell_command": true, "code_execute": true, "db_query": true, "file_delete": true}
	mediumRisk := map[string]bool{"file_write": true, "http_request": true, "code_execute_go": true, "code_execute_py": true}

	base := 10
	if highRisk[toolName] {
		base = 80
	} else if mediumRisk[toolName] {
		base = 50
	}
	switch role {
	case RoleAdmin:
		base /= 2
	case RolePrivileged:
		base = base * 3 / 4
	case RoleRestricted:
		base = base * 4 / 3
	}
	return base
}
