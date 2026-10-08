// SPDX-License-Identifier: Apache-2.0
// Audit Logger — logs all MCP actions for compliance and security auditing.
// Based on AegisGate Platform upstream/aegisguard/pkg/audit/logger.go.

package mcpsecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditAction represents an auditable MCP action.
type AuditAction struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "initialize", "tool_success", "tool_denied", "tool_error"
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"sessionId,omitempty"`
	AgentID   string    `json:"agentId,omitempty"`
	ToolName  string    `json:"toolName,omitempty"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason,omitempty"`
	RiskScore int       `json:"riskScore,omitempty"`
	// Tamper-evident fields: PrevHash is the hash of the previous entry,
	// Hash is the SHA-256 of (PrevHash || canonical fields). Together
	// they form a hash chain — modifying or deleting any entry breaks it.
	PrevHash string `json:"prevHash,omitempty"`
	Hash     string `json:"hash"`
}

// AuditLoggerImpl is a thread-safe audit logger that writes to a file
// and retains entries in memory for querying.
type AuditLoggerImpl struct {
	mu         sync.RWMutex
	output     *os.File
	encoder    *json.Encoder
	entries    []AuditAction
	maxEntries int
	retention  time.Duration
	lastHash   string // last hash in the chain (for tamper-evidence)
}

// NewAuditLogger creates a new audit logger writing to the specified file.
// If path is empty, logs are only kept in memory.
func NewAuditLogger(path string, maxEntries int) (*AuditLoggerImpl, error) {
	l := &AuditLoggerImpl{
		maxEntries: maxEntries,
	}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log: %w", err)
		}
		l.output = f
		l.encoder = json.NewEncoder(f)
	}
	return l, nil
}

// Log implements the AuditLogger interface.
func (l *AuditLoggerImpl) Log(ctx context.Context, entry *AuditEntry) error {
	action := AuditAction{
		ID:        fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		Type:      entry.Type,
		Timestamp: time.Now(),
		SessionID: entry.SessionID,
		AgentID:   entry.AgentID,
		ToolName:  entry.ToolName,
		Reason:    entry.Error,
		RiskScore: entry.RiskScore,
		Allowed:   entry.Type == "tool_success",
	}
	return l.LogAction(ctx, &action)
}

// LogAction logs a full audit action.
func (l *AuditLoggerImpl) LogAction(ctx context.Context, action *AuditAction) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Compute hash chain for tamper-evidence
	action.PrevHash = l.lastHash
	action.Hash = computeAuditHash(l.lastHash, action)

	// Write to file if configured
	if l.encoder != nil {
		if err := l.encoder.Encode(action); err != nil {
			return fmt.Errorf("failed to write audit log: %w", err)
		}
	}

	// Keep in memory
	l.entries = append(l.entries, *action)
	if l.maxEntries > 0 && len(l.entries) > l.maxEntries {
		l.entries = l.entries[len(l.entries)-l.maxEntries:]
	}

	// Update last hash in chain
	l.lastHash = action.Hash
	return nil
}

// computeAuditHash computes SHA-256(prevHash || canonical fields) for tamper-evidence.
// Only the essential fields are included — not the Hash/PrevHash themselves.
func computeAuditHash(prevHash string, action *AuditAction) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(action.ID))
	h.Write([]byte(action.Type))
	h.Write([]byte(action.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(action.SessionID))
	h.Write([]byte(action.AgentID))
	h.Write([]byte(action.ToolName))
	h.Write([]byte(action.Reason))
	fmt.Fprintf(h, "%d%t", action.RiskScore, action.Allowed)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain checks the integrity of the in-memory audit log hash chain.
// Returns true if all entries' hashes are valid and the chain is unbroken.
func (l *AuditLoggerImpl) VerifyChain() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	prevHash := ""
	for _, entry := range l.entries {
		if entry.PrevHash != prevHash {
			return false
		}
		expected := computeAuditHash(prevHash, &entry)
		if entry.Hash != expected {
			return false
		}
		prevHash = entry.Hash
	}
	return true
}

// Query retrieves audit entries matching the filter.
func (l *AuditLoggerImpl) Query(filter AuditFilter) []AuditAction {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var result []AuditAction
	for _, a := range l.entries {
		if filter.matches(a) {
			result = append(result, a)
		}
	}
	return result
}

// AuditFilter filters audit log queries.
type AuditFilter struct {
	SessionID  string
	AgentID    string
	ToolName   string
	ActionType string
	Allowed    *bool
	FromTime   *time.Time
	ToTime     *time.Time
}

func (f AuditFilter) matches(a AuditAction) bool {
	if f.SessionID != "" && a.SessionID != f.SessionID {
		return false
	}
	if f.AgentID != "" && a.AgentID != f.AgentID {
		return false
	}
	if f.ToolName != "" && a.ToolName != f.ToolName {
		return false
	}
	if f.ActionType != "" && a.Type != f.ActionType {
		return false
	}
	if f.Allowed != nil && a.Allowed != *f.Allowed {
		return false
	}
	if f.FromTime != nil && a.Timestamp.Before(*f.FromTime) {
		return false
	}
	if f.ToTime != nil && a.Timestamp.After(*f.ToTime) {
		return false
	}
	return true
}

// Close closes the audit log file.
func (l *AuditLoggerImpl) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.output != nil {
		return l.output.Close()
	}
	return nil
}

// EntryCount returns the number of in-memory entries.
func (l *AuditLoggerImpl) EntryCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}
