// SPDX-License-Identifier: Apache-2.0
// STDIO Command Validation — prevents shell metacharacter injection via MCP STDIO transport.
// Based on AegisGate Platform pkg/mcpserver/stdio_validation.go.
// Addresses OX Security "Mother of All AI Supply Chains" advisory and MCP SDK CVEs.

package mcpsecurity

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Allowlist: ^[a-zA-Z0-9/._-]+$
// Permits standard binary paths (e.g., /usr/bin/node, npx@1.2.3)
// but rejects all shell metacharacters that enable injection.
var stdioAllowlist = regexp.MustCompile(`^[a-zA-Z0-9/._@-]+$`)

// Blocklist patterns (from OX Security article).
var stdioBlocklist = map[string]*regexp.Regexp{
	"pipe_chaining":        regexp.MustCompile(`\|`),
	"command_separator":    regexp.MustCompile(`;`),
	"logical_chaining":     regexp.MustCompile(`&&|\|\|`),
	"command_substitution": regexp.MustCompile(`\$\(|\)`),
	"backtick_exec":        regexp.MustCompile("`"),
	"redirect":             regexp.MustCompile(`>|<|>>`),
	"newline_injection":    regexp.MustCompile(`\n|\r`),
	"wildcard_expansion":   regexp.MustCompile(`\*|\?`),
	"variable_expansion":   regexp.MustCompile(`\$[a-zA-Z_]|\$\{`),
	"home_expansion":       regexp.MustCompile(`~`),
	"background_exec":      regexp.MustCompile(`&`),
}

var stdioBlocklistDesc = map[string]string{
	"pipe_chaining":        "pipe/command chaining",
	"command_separator":    "command separator",
	"logical_chaining":     "logical AND/OR chaining",
	"command_substitution": "command substitution/subshell",
	"backtick_exec":        "backtick command substitution",
	"redirect":             "file redirect",
	"newline_injection":    "newline injection",
	"wildcard_expansion":   "wildcard expansion",
	"variable_expansion":   "variable expansion",
	"home_expansion":       "home directory expansion",
	"background_exec":      "background execution",
}

// StdioValidator validates MCP STDIO commands for shell injection.
type StdioValidator struct {
	mu           sync.RWMutex
	totalChecks  int64
	blockedCount int64
}

// NewStdioValidator creates a new STDIO validator.
func NewStdioValidator() *StdioValidator {
	return &StdioValidator{}
}

// ValidationResult holds the result of STDIO command validation.
type ValidationResult struct {
	Valid   bool
	Command string
	Reason  string
}

// ValidateCommand validates a command string against the allowlist and blocklist.
func (v *StdioValidator) ValidateCommand(command string) *ValidationResult {
	atomic.AddInt64(&v.totalChecks, 1)

	command = strings.TrimSpace(command)
	if command == "" {
		return &ValidationResult{Valid: false, Command: command, Reason: "empty command"}
	}

	// Check allowlist first
	if !stdioAllowlist.MatchString(command) {
		atomic.AddInt64(&v.blockedCount, 1)
		// Find which blocklist pattern matched
		for name, pattern := range stdioBlocklist {
			if pattern.MatchString(command) {
				return &ValidationResult{
					Valid:   false,
					Command: command,
					Reason:  fmt.Sprintf("blocked: %s", stdioBlocklistDesc[name]),
				}
			}
		}
		return &ValidationResult{
			Valid:   false,
			Command: command,
			Reason:  "command contains disallowed characters (not in allowlist)",
		}
	}

	return &ValidationResult{Valid: true, Command: command}
}

// ValidateCommandArgs validates command arguments (more permissive than the command itself).
func (v *StdioValidator) ValidateCommandArgs(args []string) *ValidationResult {
	atomic.AddInt64(&v.totalChecks, 1)
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		// Args can contain spaces and quotes but not shell metacharacters
		for name, pattern := range stdioBlocklist {
			if pattern.MatchString(arg) {
				atomic.AddInt64(&v.blockedCount, 1)
				return &ValidationResult{
					Valid:   false,
					Command: strings.Join(args, " "),
					Reason:  fmt.Sprintf("blocked in args: %s", stdioBlocklistDesc[name]),
				}
			}
		}
	}
	return &ValidationResult{Valid: true, Command: strings.Join(args, " ")}
}

// Stats returns STDIO validation statistics.
func (v *StdioValidator) Stats() map[string]int64 {
	return map[string]int64{
		"total_checks":  atomic.LoadInt64(&v.totalChecks),
		"blocked_count": atomic.LoadInt64(&v.blockedCount),
	}
}
