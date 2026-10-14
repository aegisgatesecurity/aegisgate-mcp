// SPDX-License-Identifier: Apache-2.0
// Scanner — content detection patterns for PII, secrets, prompt injection, XSS, compliance.
// Based on AegisGate Platform pkg/scanner/patterns.go. 223 detection patterns, zero deps.

package mcpsecurity

import (
	"regexp"
	"sort"
	"strings"
)

// Severity levels for findings.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// Category classifies what type of data was detected.
type Category string

const (
	CatPII               Category = "PII"
	CatCredential        Category = "Credential"
	CatFinancial         Category = "Financial"
	CatCryptographic     Category = "Cryptographic"
	CatNetwork           Category = "Network"
	CatPrompt            Category = "Prompt"
	CatXSS               Category = "XSS"
	CatCompliance        Category = "Compliance"
	CatDangerousFunction Category = "DangerousFunction"
)

// Pattern defines a single detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    Severity
	Category    Category
	Description string
}

// Finding represents a scanner detection result.
type Finding struct {
	Pattern  *Pattern
	Match    string
	Position int
}

// ContentScanner scans text content for security threats.
type ContentScanner struct {
	patterns []*Pattern
}

// NewContentScanner creates a scanner with all default detection patterns.
func NewContentScanner() *ContentScanner {
	return &ContentScanner{patterns: defaultScannerPatterns()}
}

// NewContentScannerWithPatterns creates a scanner with custom patterns.
func NewContentScannerWithPatterns(patterns []*Pattern) *ContentScanner {
	return &ContentScanner{patterns: patterns}
}

// Scan scans content and returns all findings.
func (s *ContentScanner) Scan(content string) []Finding {
	var findings []Finding
	for _, p := range s.patterns {
		if p.Regex == nil {
			continue
		}
		loc := p.Regex.FindStringIndex(content)
		if loc != nil {
			findings = append(findings, Finding{
				Pattern:  p,
				Match:    content[loc[0]:loc[1]],
				Position: loc[0],
			})
		}
	}
	return findings
}

// HasCriticalFindings returns true if any finding is critical or high severity.
func (s *ContentScanner) HasCriticalFindings(findings []Finding) bool {
	for _, f := range findings {
		if f.Pattern.Severity >= SeverityHigh {
			return true
		}
	}
	return false
}

// FindingsByCategory returns findings filtered by category.
func (s *ContentScanner) FindingsByCategory(findings []Finding, cat Category) []Finding {
	var result []Finding
	for _, f := range findings {
		if f.Pattern.Category == cat {
			result = append(result, f)
		}
	}
	return result
}

// ResponseScanResult holds the result of scanning an MCP response.
type ResponseScanResult struct {
	Blocked     bool
	Reason      string
	Findings    []Finding
	PIICount    int
	SecretCount int
	XSSCount    int
	PromptCount int
}

// ScanResponse scans an MCP tool response for security threats.
// Returns a result indicating whether the response should be blocked.
func (s *ContentScanner) ScanResponse(response string, blockOnPII, blockOnSecrets, blockOnXSS, blockOnPromptInjection bool) *ResponseScanResult {
	findings := s.Scan(response)
	result := &ResponseScanResult{Findings: findings}

	for _, f := range findings {
		switch f.Pattern.Category {
		case CatPII, CatFinancial:
			result.PIICount++
			if blockOnPII && f.Pattern.Severity >= SeverityHigh {
				result.Blocked = true
				result.Reason = "PII detected in response: " + f.Pattern.Name
			}
		case CatCredential, CatCryptographic:
			result.SecretCount++
			if blockOnSecrets {
				result.Blocked = true
				result.Reason = "Secret detected in response: " + f.Pattern.Name
			}
		case CatXSS:
			result.XSSCount++
			if blockOnXSS {
				result.Blocked = true
				result.Reason = "XSS detected in response: " + f.Pattern.Name
			}
		case CatPrompt:
			result.PromptCount++
			if blockOnPromptInjection {
				result.Blocked = true
				result.Reason = "Prompt injection detected in response: " + f.Pattern.Name
			}
		case CatCompliance:
			// OWASP LLM categories — treat compliance findings as prompt injection
			// for blocking purposes (LLM01, LLM02, LLM06 are all injection-related)
			result.PromptCount++
			if blockOnPromptInjection {
				result.Blocked = true
				result.Reason = "Compliance violation detected in response: " + f.Pattern.Name
			}
		}
	}

	return result
}

// defaultScannerPatterns returns the core detection patterns.
// This is a curated subset focused on OT/ICS MCP server security.
func defaultScannerPatterns() []*Pattern {
	return []*Pattern{
		// === Prompt Injection (11) ===
		{Name: "PromptInjectionCommand", Regex: regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(previous|prior|all|above)\s+(instructions?|prompts?|rules?)`), Severity: SeverityCritical, Category: CatPrompt, Description: "Command to ignore instructions"},
		{Name: "PromptInjectionRolePlay", Regex: regexp.MustCompile(`(?i)(pretend|act as|role.?play|you are)\s+(a|an)?\s*(root|admin|sudo|developer)`), Severity: SeverityCritical, Category: CatPrompt, Description: "Role-play to escalate privileges"},
		{Name: "PromptInjectionLeakage", Regex: regexp.MustCompile(`(?i)(reveal|show|print|output|leak)\s+(your|the|system|initial)\s+(instructions?|prompt|rules?|config)`), Severity: SeverityCritical, Category: CatPrompt, Description: "Attempt to leak system prompt"},
		{Name: "PromptInjectionCodeExec", Regex: regexp.MustCompile(`(?i)(execute|run|eval|exec)\s+(this|the following)\s+(code|command|script)`), Severity: SeverityCritical, Category: CatPrompt, Description: "Code execution via prompt"},
		{Name: "PromptInjectionDelimiter", Regex: regexp.MustCompile(`(?i)---+\s*(system|admin|root|secret)`), Severity: SeverityHigh, Category: CatPrompt, Description: "Delimiter-based injection"},
		{Name: "PromptInjectionBase64", Regex: regexp.MustCompile(`(?i)base64.?decode\s*[:(]`), Severity: SeverityHigh, Category: CatPrompt, Description: "Base64-encoded payload"},
		{Name: "PromptInjectionUnicode", Regex: regexp.MustCompile(`\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}`), Severity: SeverityHigh, Category: CatPrompt, Description: "Unicode escape sequence injection"},
		{Name: "PromptInjectionNewInstructions", Regex: regexp.MustCompile(`(?i)(your|new)\s+(new\s+)?instructions?\s*[:=]`), Severity: SeverityCritical, Category: CatPrompt, Description: "Attempt to inject new instructions"},
		{Name: "PromptInjectionRevealSecrets", Regex: regexp.MustCompile(`(?i)(reveal|show|output|leak|exfiltrate)\s+(all\s+)?(secrets?|api.?keys?|tokens?|credentials?|passwords?)`), Severity: SeverityCritical, Category: CatPrompt, Description: "Attempt to extract secrets"},
		{Name: "PromptInjectionRevealConfig", Regex: regexp.MustCompile(`(?i)(reveal|show|print|output)\s+\w+\s+\w+\s+(instructions?\s+and\s+configuration|config)`), Severity: SeverityCritical, Category: CatPrompt, Description: "Attempt to leak configuration"},

		// === Credentials/Secrets (key patterns) ===
		{Name: "AWSAccessKeyID", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: SeverityCritical, Category: CatCredential, Description: "AWS Access Key ID"},
		{Name: "AWSSecretKey", Regex: regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`), Severity: SeverityCritical, Category: CatCredential, Description: "AWS Secret Access Key"},
		{Name: "GitHubToken", Regex: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`), Severity: SeverityCritical, Category: CatCredential, Description: "GitHub Personal Access Token"},
		{Name: "GenericAPIKey", Regex: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*[A-Za-z0-9]{32,}`), Severity: SeverityHigh, Category: CatCredential, Description: "Generic API key"},
		{Name: "JWTToken", Regex: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), Severity: SeverityCritical, Category: CatCredential, Description: "JWT token"},
		{Name: "RSAPrivateKey", Regex: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----`), Severity: SeverityCritical, Category: CatCredential, Description: "Private key"},

		// === PII (key patterns) ===
		{Name: "CreditCardVisa", Regex: regexp.MustCompile(`4[0-9]{12}(?:[0-9]{3})?`), Severity: SeverityCritical, Category: CatFinancial, Description: "Visa credit card number"},
		{Name: "CreditCardMastercard", Regex: regexp.MustCompile(`5[1-5][0-9]{14}`), Severity: SeverityCritical, Category: CatFinancial, Description: "Mastercard number"},
		{Name: "CreditCardAmex", Regex: regexp.MustCompile(`3[47][0-9]{13}`), Severity: SeverityCritical, Category: CatFinancial, Description: "Amex credit card number"},
		{Name: "USSSN", Regex: regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`), Severity: SeverityHigh, Category: CatPII, Description: "US Social Security Number"},
		{Name: "EmailPII", Regex: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), Severity: SeverityMedium, Category: CatPII, Description: "Email address"},

		// === XSS (key patterns) ===
		{Name: "XSSScriptTag", Regex: regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`), Severity: SeverityCritical, Category: CatXSS, Description: "Script tag XSS"},
		{Name: "XSSImageTag", Regex: regexp.MustCompile(`(?i)<img[^>]+onerror\s*=`), Severity: SeverityCritical, Category: CatXSS, Description: "Image onerror XSS"},
		{Name: "XSSSvgTag", Regex: regexp.MustCompile(`(?i)<svg[^>]+onload\s*=`), Severity: SeverityCritical, Category: CatXSS, Description: "SVG onload XSS"},

		// === OT/ICS Network patterns ===
		{Name: "ModbusAddress", Regex: regexp.MustCompile(`(?i)modbus://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`), Severity: SeverityMedium, Category: CatNetwork, Description: "Modbus protocol address"},
		{Name: "DNP3Address", Regex: regexp.MustCompile(`(?i)dnp3?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`), Severity: SeverityMedium, Category: CatNetwork, Description: "DNP3 protocol address"},
		{Name: "OPCUAAddress", Regex: regexp.MustCompile(`(?i)opc\.?tcp://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`), Severity: SeverityMedium, Category: CatNetwork, Description: "OPC UA protocol address"},

		// === Compliance (key patterns) ===
		{Name: "OWASP_LLM01_PromptInjection", Regex: regexp.MustCompile(`(?i)(jailbreak|dan\s+prompt|do anything now)`), Severity: SeverityCritical, Category: CatCompliance, Description: "OWASP LLM01: Prompt injection"},
		{Name: "OWASP_LLM02_InsecureOutput", Regex: regexp.MustCompile(`(?i)document\.write\s*\(`), Severity: SeverityHigh, Category: CatCompliance, Description: "OWASP LLM02: Insecure output handling"},
		{Name: "OWASP_LLM06_SensitiveInfo", Regex: regexp.MustCompile(`(?i)(ssn|social security|credit card|passport number)\s*[:=]`), Severity: SeverityHigh, Category: CatCompliance, Description: "OWASP LLM06: Sensitive information disclosure"},

		// === Dangerous Functions (34 patterns) ===
		// Provenance: github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors/dangerous_functions.go
		// These detect dangerous code-level patterns in tool descriptions and
		// input schemas — a key defense against tool poisoning attacks where
		// malicious code is embedded in tool metadata.
		// --- Python ---
		{Name: "DangerousPyEval", Regex: regexp.MustCompile(`eval\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "Python eval() allows arbitrary code execution"},
		{Name: "DangerousPyExec", Regex: regexp.MustCompile(`exec\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "Python exec() allows arbitrary code execution"},
		{Name: "DangerousPyOsSystem", Regex: regexp.MustCompile(`os\.system\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "os.system() executes shell commands"},
		{Name: "DangerousPySubprocessShell", Regex: regexp.MustCompile(`subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "subprocess with shell=True allows command injection"},
		{Name: "DangerousPyOsPopen", Regex: regexp.MustCompile(`os\.popen\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "os.popen() executes shell commands"},
		{Name: "DangerousPyImport", Regex: regexp.MustCompile(`__import__\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "Dynamic import via __import__()"},
		{Name: "DangerousPyPickleLoads", Regex: regexp.MustCompile(`pickle\.loads?\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "pickle.loads() can execute arbitrary code"},
		{Name: "DangerousPyYamlUnsafeLoad", Regex: regexp.MustCompile(`yaml\.load\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "yaml.load() without SafeLoader is dangerous"},
		{Name: "DangerousPyMarshalLoads", Regex: regexp.MustCompile(`marshal\.loads?\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "marshal.loads() can execute arbitrary code"},
		{Name: "DangerousPyCompile", Regex: regexp.MustCompile(`compile\s*\(`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "compile() can create executable code objects"},
		{Name: "DangerousPyCtypes", Regex: regexp.MustCompile(`ctypes\.(CDLL|WinDLL|PyDLL)`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "ctypes allows direct library calls"},
		{Name: "DangerousPyInputExec", Regex: regexp.MustCompile(`input\s*\(`), Severity: SeverityLow, Category: CatDangerousFunction, Description: "input() in Python 2 evaluates as code"},
		// --- JavaScript/TypeScript ---
		{Name: "DangerousJsEval", Regex: regexp.MustCompile(`(?i)\beval\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "JavaScript eval() allows arbitrary code execution"},
		{Name: "DangerousJsFunctionConstructor", Regex: regexp.MustCompile(`new\s+Function\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "Function constructor creates code from strings"},
		{Name: "DangerousJsChildProcessExec", Regex: regexp.MustCompile(`child_process\.exec\s*\(`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "child_process.exec() runs shell commands"},
		{Name: "DangerousJsChildProcessSpawn", Regex: regexp.MustCompile(`child_process\.spawn\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "child_process.spawn() creates new processes"},
		{Name: "DangerousJsSetTimeoutString", Regex: regexp.MustCompile(`setTimeout\s*\(\s*['"]`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "setTimeout with string argument evals code"},
		{Name: "DangerousJsSetIntervalString", Regex: regexp.MustCompile(`setInterval\s*\(\s*['"]`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "setInterval with string argument evals code"},
		{Name: "DangerousJsDocumentWrite", Regex: regexp.MustCompile(`document\.write\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "document.write() can inject scripts"},
		{Name: "DangerousJsInnerHTML", Regex: regexp.MustCompile(`\.innerHTML\s*=`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "innerHTML assignment can inject scripts"},
		// --- Cross-language ---
		{Name: "DangerousSqlInjection", Regex: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*\+.*\+`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "SQL query with string concatenation (injection risk)"},
		{Name: "DangerousCommandInjection", Regex: regexp.MustCompile(`(?i)(system|exec|popen|backticks|` + "`" + `)\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "Command execution function"},
		// --- Network endpoints in code ---
		{Name: "DangerousHardcodedUrlHttp", Regex: regexp.MustCompile(`http://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "Hardcoded HTTP URL (no TLS)"},
		{Name: "DangerousBase64Blob", Regex: regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "Large base64 blob (possible encoded payload)"},
		{Name: "DangerousIpAddressUrl", Regex: regexp.MustCompile(`https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "URL with raw IP address (possible C2)"},
		{Name: "DangerousLocalhostUrl", Regex: regexp.MustCompile(`https?://localhost(:[0-9]+)?`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "URL pointing to localhost"},
		{Name: "DangerousInternalServiceUrl", Regex: regexp.MustCompile(`https?://(internal|intranet|admin|management)\.`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "URL pointing to internal service"},
		{Name: "DangerousWebsocketUrl", Regex: regexp.MustCompile(`wss?://[a-zA-Z0-9.-]+`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "WebSocket connection URL"},
		{Name: "DangerousAwsEndpoint", Regex: regexp.MustCompile(`https?://[a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "AWS API Gateway endpoint"},
		{Name: "DangerousGcpEndpoint", Regex: regexp.MustCompile(`https?://[a-z0-9-]+\.cloudfunctions\.net`), Severity: SeverityMedium, Category: CatDangerousFunction, Description: "GCP Cloud Functions endpoint"},
		// --- Encoding/obfuscation ---
		{Name: "DangerousPyB64decode", Regex: regexp.MustCompile(`base64\.b64decode\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "base64.b64decode() — common in obfuscated payloads"},
		{Name: "DangerousJsAtob", Regex: regexp.MustCompile(`\batob\s*\(`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "atob() decodes base64 — common in obfuscated payloads"},
		{Name: "DangerousB64EnvVar", Regex: regexp.MustCompile(`(?i)(env|process\.env|os\.environ).*base64`), Severity: SeverityHigh, Category: CatDangerousFunction, Description: "Base64 from environment variable (obfuscation pattern)"},
		{Name: "DangerousB64EvalChain", Regex: regexp.MustCompile(`(?i)(eval|exec|Function)\s*\(\s*(base64|atob|b64decode)`), Severity: SeverityCritical, Category: CatDangerousFunction, Description: "eval(base64decode()) chain — classic obfuscated execution"},
	}
}

// SanitizeForLog truncates and cleans a string for safe logging.
func SanitizeForLog(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}

// ============================================================
// Secret Redaction
// ============================================================

// RedactConfig controls how sensitive data is redacted from responses.
type RedactConfig struct {
	Enabled       bool
	RedactPII     bool
	RedactSecrets bool
	Placeholder   string // replacement text (default "[REDACTED]")
}

// DefaultRedactConfig returns a config that redacts secrets and PII.
func DefaultRedactConfig() *RedactConfig {
	return &RedactConfig{
		Enabled:       false, // opt-in
		RedactPII:     true,
		RedactSecrets: true,
		Placeholder:   "[REDACTED]",
	}
}

// Redact replaces sensitive data in text with placeholders.
// Unlike ScanResponse (which blocks), Redact allows the response through
// but scrubs the sensitive content. More useful in production where
// blocking breaks workflows but leaking secrets is unacceptable.
func (s *ContentScanner) Redact(text string, cfg *RedactConfig) string {
	if cfg == nil || !cfg.Enabled {
		return text
	}
	placeholder := cfg.Placeholder
	if placeholder == "" {
		placeholder = "[REDACTED]"
	}
	findings := s.Scan(text)
	// Collect ranges to redact, then apply in reverse order
	type redactRange struct {
		start, end int
	}
	var ranges []redactRange
	for _, f := range findings {
		shouldRedact := false
		if cfg.RedactSecrets && (f.Pattern.Category == CatCredential || f.Pattern.Category == CatCryptographic || f.Pattern.Category == CatFinancial) {
			shouldRedact = true
		}
		if cfg.RedactPII && f.Pattern.Category == CatPII {
			shouldRedact = true
		}
		if shouldRedact {
			ranges = append(ranges, redactRange{f.Position, f.Position + len(f.Match)})
		}
	}
	// Sort by start position descending (reverse order to preserve indices)
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start > ranges[j].start
	})
	// Skip overlapping ranges (already redacted)
	prevStart := len(text)
	for _, r := range ranges {
		if r.end > prevStart {
			// Overlaps with already-redacted range — skip
			continue
		}
		text = text[:r.start] + placeholder + text[r.end:]
		prevStart = r.start
	}
	return text
}
