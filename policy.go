// SPDX-License-Identifier: Apache-2.0
// Policy Engine — rule-based security policies for MCP tool calls.
// Ported from AegisGate Platform upstream/aegisguard/pkg/policy/engine.go.
// Zero external dependencies (only context and regexp).

package mcpsecurity

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ============================================================
// Policy Types
// ============================================================

// PolicyRule represents a single security rule.
type PolicyRule struct {
	ID          string
	Name        string
	Description string
	Condition   RuleCondition
	Action      RuleAction
	Priority    int
	Enabled     bool
}

// RuleCondition defines when a rule applies.
type RuleCondition struct {
	ToolNames     []string          // exact match or "*" for all
	AgentIDs      []string          // restrict to specific agents
	AgentRoles    []AgentRole       // restrict to specific roles
	RiskAbove     int               // match if tool risk > this value
	ParamPatterns map[string]string // param name → regex pattern
	TimeWindows   []TimeWindow      // time-based restrictions
	CustomMatcher func(context.Context, *PolicyEvalContext) bool
}

// TimeWindow defines a time-based condition.
type TimeWindow struct {
	Start string // "HH:MM" format
	End   string
	Days  []int // 0=Sunday, 6=Saturday
}

// RuleAction defines what happens when a rule matches.
type RuleAction struct {
	Allow        bool
	DenyReason   string
	LogLevel     string
	RiskModifier int
}

// Policy is a named collection of rules.
type Policy struct {
	ID          string
	Name        string
	Description string
	Version     string
	Rules       []PolicyRule
	Enabled     bool
}

// PolicyEvalContext is the input to policy evaluation.
type PolicyEvalContext struct {
	ToolName  string
	SessionID string
	AgentID   string
	AgentRole AgentRole
	RiskScore int
	Params    map[string]interface{}
	Timestamp time.Time
}

// PolicyDecision is the output of policy evaluation.
type PolicyDecision struct {
	Allowed      bool
	Reason       string
	MatchedRules []string
	ModifiedRisk int
}

// ============================================================
// Policy Engine
// ============================================================

// PolicyEngine evaluates security policies against MCP tool calls.
// Rules are evaluated in priority order (highest first). The first
// matching deny rule blocks the call. Allow rules can override
// lower-priority deny rules.
type PolicyEngine struct {
	rules    []PolicyRule
	policies map[string]*Policy
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		rules:    make([]PolicyRule, 0),
		policies: make(map[string]*Policy),
	}
}

// AddRule adds a standalone rule to the engine.
func (e *PolicyEngine) AddRule(rule PolicyRule) {
	e.rules = append(e.rules, rule)
	e.sortRules()
}

// AddPolicy adds a policy (collection of rules) to the engine.
func (e *PolicyEngine) AddPolicy(policy Policy) {
	for i := range policy.Rules {
		policy.Rules[i].Enabled = policy.Enabled
	}
	e.policies[policy.ID] = &policy
	e.rules = append(e.rules, policy.Rules...)
	e.sortRules()
}

// sortRules sorts rules by priority (highest first).
func (e *PolicyEngine) sortRules() {
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
}

// Evaluate evaluates all applicable rules and returns a decision.
func (e *PolicyEngine) Evaluate(ctx context.Context, evalCtx *PolicyEvalContext) PolicyDecision {
	matchedRules := make([]string, 0)
	modifiedRisk := 0
	allow := true
	reason := "allowed by default"
	decisionMade := false

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if e.matchesCondition(ctx, &rule.Condition, evalCtx) {
			matchedRules = append(matchedRules, rule.ID)
			modifiedRisk += rule.Action.RiskModifier

			if !decisionMade {
				// First (highest priority) matching rule makes the decision
				if !rule.Action.Allow {
					allow = false
					reason = rule.Action.DenyReason
					if reason == "" {
						reason = "denied by policy rule: " + rule.ID
					}
				} else {
					allow = true
					reason = "allowed by policy rule: " + rule.ID
				}
				decisionMade = true
			}
		}
	}

	return PolicyDecision{
		Allowed:      allow,
		Reason:       reason,
		MatchedRules: matchedRules,
		ModifiedRisk: modifiedRisk,
	}
}

// matchesCondition checks if an evaluation context matches a rule condition.
func (e *PolicyEngine) matchesCondition(ctx context.Context, cond *RuleCondition, evalCtx *PolicyEvalContext) bool {
	// Check tool names
	if len(cond.ToolNames) > 0 {
		found := false
		for _, name := range cond.ToolNames {
			if name == "*" || name == evalCtx.ToolName {
				found = true
				break
			}
			// Support glob-style wildcards (e.g. "file_*")
			if strings.Contains(name, "*") {
				pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(name), "\\*", ".*") + "$"
				if matched, _ := regexp.MatchString(pattern, evalCtx.ToolName); matched {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	// Check agent IDs
	if len(cond.AgentIDs) > 0 {
		found := false
		for _, id := range cond.AgentIDs {
			if id == evalCtx.AgentID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check agent roles
	if len(cond.AgentRoles) > 0 {
		found := false
		for _, role := range cond.AgentRoles {
			if role == evalCtx.AgentRole {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check risk score
	if cond.RiskAbove > 0 && evalCtx.RiskScore <= cond.RiskAbove {
		return false
	}

	// Check parameter patterns
	for paramName, pattern := range cond.ParamPatterns {
		val, ok := evalCtx.Params[paramName]
		if !ok {
			return false
		}
		strVal := fmt.Sprintf("%v", val)
		matched, err := regexp.MatchString(pattern, strVal)
		if err != nil || !matched {
			return false
		}
	}

	// Check time windows
	if len(cond.TimeWindows) > 0 {
		ts := evalCtx.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		matched := false
		for _, tw := range cond.TimeWindows {
			if e.matchesTimeWindow(tw, ts) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check custom matcher
	if cond.CustomMatcher != nil {
		return cond.CustomMatcher(ctx, evalCtx)
	}

	return true
}

// matchesTimeWindow checks if a timestamp falls within a time window.
func (e *PolicyEngine) matchesTimeWindow(tw TimeWindow, ts time.Time) bool {
	// Check day of week
	if len(tw.Days) > 0 {
		dayMatched := false
		wday := int(ts.Weekday())
		for _, d := range tw.Days {
			if d == wday {
				dayMatched = true
				break
			}
		}
		if !dayMatched {
			return false
		}
	}

	// Check time range
	if tw.Start == "" || tw.End == "" {
		return true
	}
	startTime, errS := time.Parse("15:04", tw.Start)
	endTime, errE := time.Parse("15:04", tw.End)
	if errS != nil || errE != nil {
		return false
	}
	// Compare only the time-of-day portion
	nowMinutes := ts.Hour()*60 + ts.Minute()
	startMinutes := startTime.Hour()*60 + startTime.Minute()
	endMinutes := endTime.Hour()*60 + endTime.Minute()
	return nowMinutes >= startMinutes && nowMinutes <= endMinutes
}

// ============================================================
// Policy Management
// ============================================================

// GetPolicy retrieves a policy by ID.
func (e *PolicyEngine) GetPolicy(id string) (*Policy, bool) {
	p, ok := e.policies[id]
	return p, ok
}

// DeletePolicy removes a policy and its rules from the engine.
func (e *PolicyEngine) DeletePolicy(id string) error {
	policy, ok := e.policies[id]
	if !ok {
		return fmt.Errorf("policy not found: %s", id)
	}
	// Remove rules belonging to this policy
	ruleIDs := make(map[string]bool)
	for _, r := range policy.Rules {
		ruleIDs[r.ID] = true
	}
	filtered := make([]PolicyRule, 0, len(e.rules))
	for _, r := range e.rules {
		if !ruleIDs[r.ID] {
			filtered = append(filtered, r)
		}
	}
	e.rules = filtered
	delete(e.policies, id)
	return nil
}

// ListPolicies returns all policy IDs.
func (e *PolicyEngine) ListPolicies() []string {
	ids := make([]string, 0, len(e.policies))
	for id := range e.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// DisableRule disables a rule by ID.
func (e *PolicyEngine) DisableRule(ruleID string) {
	for i := range e.rules {
		if e.rules[i].ID == ruleID {
			e.rules[i].Enabled = false
		}
	}
}

// EnableRule enables a rule by ID.
func (e *PolicyEngine) EnableRule(ruleID string) {
	for i := range e.rules {
		if e.rules[i].ID == ruleID {
			e.rules[i].Enabled = true
		}
	}
}

// RuleCount returns the total number of rules.
func (e *PolicyEngine) RuleCount() int {
	return len(e.rules)
}

// ============================================================
// PolicyAuthorizer — adapts PolicyEngine to ToolAuthorizer interface
// ============================================================

// PolicyAuthorizer wraps a PolicyEngine to implement ToolAuthorizer.
// It evaluates policies before RBAC, allowing fine-grained rules like
// "agent A can only call file_read with paths matching /opt/ics/*".
type PolicyAuthorizer struct {
	Engine   *PolicyEngine
	Fallback ToolAuthorizer // consulted when no policy rules match
	Registry *ToolRegistry  // for risk level lookups
}

// NewPolicyAuthorizer creates a policy-based authorizer.
// If fallback is nil, calls with no matching policy rules are allowed.
func NewPolicyAuthorizer(engine *PolicyEngine, fallback ToolAuthorizer, registry *ToolRegistry) *PolicyAuthorizer {
	return &PolicyAuthorizer{
		Engine:   engine,
		Fallback: fallback,
		Registry: registry,
	}
}

// Authorize implements ToolAuthorizer.
func (p *PolicyAuthorizer) Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error) {
	if p.Engine == nil || p.Engine.RuleCount() == 0 {
		// No policy rules — use fallback
		if p.Fallback != nil {
			return p.Fallback.Authorize(ctx, call)
		}
		return &AuthorizationDecision{Allowed: true, Reason: "no policy rules configured"}, nil
	}

	riskScore := 0
	if p.Registry != nil {
		riskScore = p.Registry.GetRiskLevel(call.Name)
	}

	evalCtx := &PolicyEvalContext{
		ToolName:  call.Name,
		SessionID: call.SessionID,
		AgentID:   call.AgentID,
		RiskScore: riskScore,
		Params:    call.Parameters,
		Timestamp: time.Now(),
	}

	decision := p.Engine.Evaluate(ctx, evalCtx)

	result := &AuthorizationDecision{
		Allowed:     decision.Allowed,
		Reason:      decision.Reason,
		RiskScore:   riskScore + decision.ModifiedRisk,
		MatchedRule: strings.Join(decision.MatchedRules, ","),
	}

	// If policy allowed but we have a fallback, also check it
	if decision.Allowed && p.Fallback != nil && len(decision.MatchedRules) == 0 {
		fbDecision, err := p.Fallback.Authorize(ctx, call)
		if err != nil {
			return nil, err
		}
		return fbDecision, nil
	}

	return result, nil
}

// ============================================================
// Common Policy Rules
// ============================================================

// DefaultPolicyRules returns a set of common security rules for OT/ICS.
func DefaultPolicyRules() []PolicyRule {
	return []PolicyRule{
		{
			ID:          "block-shell-commands",
			Name:        "Block Shell Commands",
			Description: "Block direct shell command execution for non-admin agents",
			Condition: RuleCondition{
				ToolNames:  []string{"shell_command", "bash", "exec", "cmd", "terminal"},
				AgentRoles: []AgentRole{RoleRestricted, RoleStandard, RolePrivileged},
			},
			Action: RuleAction{
				Allow:      false,
				DenyReason: "Shell commands require admin role",
				LogLevel:   "warn",
			},
			Priority: 100,
			Enabled:  true,
		},
		{
			ID:          "block-file-delete",
			Name:        "Block File Deletion",
			Description: "Block file deletion for restricted and standard agents",
			Condition: RuleCondition{
				ToolNames:  []string{"file_delete", "rm", "unlink", "remove"},
				AgentRoles: []AgentRole{RoleRestricted, RoleStandard},
			},
			Action: RuleAction{
				Allow:      false,
				DenyReason: "File deletion requires privileged or admin role",
				LogLevel:   "warn",
			},
			Priority: 90,
			Enabled:  true,
		},
		{
			ID:          "block-network-write",
			Name:        "Block Network Write Operations",
			Description: "Block outbound network writes for restricted agents",
			Condition: RuleCondition{
				ToolNames:  []string{"http_request", "web_search", "fetch_url", "curl", "wget"},
				AgentRoles: []AgentRole{RoleRestricted},
			},
			Action: RuleAction{
				Allow:      false,
				DenyReason: "Network operations not allowed for restricted agents",
				LogLevel:   "warn",
			},
			Priority: 80,
			Enabled:  true,
		},
		{
			ID:          "alert-high-risk",
			Name:        "High Risk Alert",
			Description: "Flag high-risk operations (risk > 70)",
			Condition: RuleCondition{
				RiskAbove: 70,
			},
			Action: RuleAction{
				Allow:        true,
				LogLevel:     "alert",
				RiskModifier: 10,
			},
			Priority: 50,
			Enabled:  true,
		},
	}
}
