// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate MCP — Tool Code Scanner
// =========================================================================
//
// Scans MCP tool handler source code for dangerous functions, prompt
// injection, and other security issues. This extends the existing tool
// description screening (validateToolNotPoisoned) to also screen the
// actual implementation code, not just the metadata.
//
// I2: Scanner ↔ MCP tool code scanning.
//
// Uses the existing ContentScanner patterns (zero external deps).
// For full 268-pattern scanning, build with -tags aegisgate_scanner
// to enable the optional Scanner pkg/detectors integration.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.
// =========================================================================

package mcpsecurity

import (
	"fmt"
	"log/slog"
	"strings"
)

// ToolCodeFinding represents a security issue found in tool source code.
type ToolCodeFinding struct {
	ToolName   string   `json:"tool_name"`
	RuleName   string   `json:"rule_name"`
	Category   Category `json:"category"`
	Severity   Severity `json:"severity"`
	Line       int      `json:"line"`
	Column     int      `json:"column"`
	Message    string   `json:"message"`
	Suggestion string   `json:"suggestion,omitempty"`
}

// ToolCodeScanResult contains the results of scanning a tool's source code.
type ToolCodeScanResult struct {
	ToolName string            `json:"tool_name"`
	Passed   bool              `json:"passed"`
	Findings []ToolCodeFinding `json:"findings,omitempty"`
}

// ScanToolCode scans the source code of an MCP tool handler for security issues.
// sourceCode is the raw Go (or other language) source of the tool handler.
// toolName is the name of the tool being scanned.
//
// This function uses the ContentScanner's existing patterns (prompt injection,
// dangerous functions, secrets, PII, XSS, compliance) to detect issues in
// the implementation code itself — not just the description.
//
// Returns a ToolCodeScanResult with all findings at or above SeverityHigh.
func ScanToolCode(scanner *ContentScanner, toolName, sourceCode string) *ToolCodeScanResult {
	result := &ToolCodeScanResult{
		ToolName: toolName,
		Passed:   true,
	}

	if scanner == nil {
		return result
	}

	if sourceCode == "" {
		return result
	}

	// Run the existing scanner against the source code
	contentFindings := scanner.Scan(sourceCode)

	// Convert to ToolCodeFinding, filtering for high+ severity
	for _, cf := range contentFindings {
		if cf.Pattern.Severity < SeverityHigh {
			continue
		}

		line, col := positionToLineCol(sourceCode, cf.Position)

		finding := ToolCodeFinding{
			ToolName:   toolName,
			RuleName:   cf.Pattern.Name,
			Category:   cf.Pattern.Category,
			Severity:   cf.Pattern.Severity,
			Line:       line,
			Column:     col,
			Message:    cf.Pattern.Description,
			Suggestion: getSuggestion(cf.Pattern.Category),
		}
		result.Findings = append(result.Findings, finding)
	}

	if len(result.Findings) > 0 {
		result.Passed = false
		lineCount := strings.Count(sourceCode, "\n") + 1
		slog.Warn("tool code scan failed",
			"tool", toolName,
			"findings", len(result.Findings),
			"lines_scanned", lineCount)
	}

	return result
}

// positionToLineCol converts a byte offset into a 1-based line and column.
func positionToLineCol(s string, pos int) (line, col int) {
	line = 1
	col = 1
	for i := 0; i < pos && i < len(s); i++ {
		if s[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return
}

// ScanToolCodeBatch scans multiple tool source files in a single call.
// Returns a slice of ToolCodeScanResult, one per tool.
func ScanToolCodeBatch(scanner *ContentScanner, tools map[string]string) []*ToolCodeScanResult {
	results := make([]*ToolCodeScanResult, 0, len(tools))
	for name, source := range tools {
		results = append(results, ScanToolCode(scanner, name, source))
	}
	return results
}

// ScanToolCodeFile reads a file and scans its contents.
// This is a convenience function for scanning tool handler files on disk.
// The readFile function is injected for testability.
func ScanToolCodeFile(scanner *ContentScanner, toolName string, readFile func(string) (string, error), filePath string) (*ToolCodeScanResult, error) {
	source, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tool source file %s: %w", filePath, err)
	}
	return ScanToolCode(scanner, toolName, source), nil
}

// HasCriticalFindings returns true if any finding is SeverityCritical.
func (r *ToolCodeScanResult) HasCriticalFindings() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasDangerousFunctions returns true if any finding is in the DangerousFunction category.
func (r *ToolCodeScanResult) HasDangerousFunctions() bool {
	for _, f := range r.Findings {
		if f.Category == CatDangerousFunction {
			return true
		}
	}
	return false
}

// Summary returns a human-readable summary of the scan results.
func (r *ToolCodeScanResult) Summary() string {
	if r.Passed {
		return fmt.Sprintf("tool %q: passed (no high-severity findings)", r.ToolName)
	}
	critical := 0
	high := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			critical++
		} else if f.Severity == SeverityHigh {
			high++
		}
	}
	return fmt.Sprintf("tool %q: FAILED (%d critical, %d high, %d total findings)",
		r.ToolName, critical, high, len(r.Findings))
}

// getSuggestion returns a remediation suggestion for a given category.
func getSuggestion(cat Category) string {
	switch cat {
	case CatDangerousFunction:
		return "Avoid eval/exec/system calls. Use safe alternatives or sandboxed execution."
	case CatPrompt:
		return "Remove prompt injection patterns from tool code. Tools should not contain instructions for the LLM."
	case CatCredential:
		return "Do not hardcode credentials in tool source. Use environment variables or a secrets manager."
	case CatXSS:
		return "Sanitize output to prevent XSS. Use proper HTML escaping."
	case CatPII:
		return "Do not expose PII in tool code. Implement data minimization."
	case CatCompliance:
		return "Review for compliance violations. Ensure regulatory requirements are met."
	case CatNetwork:
		return "Validate and sanitize all network endpoints. Avoid hardcoded internal URLs."
	case CatCryptographic:
		return "Use established cryptographic libraries. Do not implement custom crypto."
	default:
		return "Review the finding and remediate according to your security policy."
	}
}
