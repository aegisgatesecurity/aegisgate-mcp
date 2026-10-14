// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate MCP — Platform Forwarder
// =========================================================================
//
// Forwards MCP detection metadata to AegisGate Platform for SIEM
// integration, attestation, and audit trail. Only metadata is sent —
// never prompt text, PII values, or credentials.
//
// I3: MCP → Platform forwarding.
//
// Privacy (non-negotiable):
//   - No prompt text is sent — only detection metadata
//   - No PII values sent — only categories and rule names
//   - No credentials sent
//   - Platform forwarding is opt-in (requires platform_url in config)
//   - Air-gap compatible — if platform_url is empty, forwarding is disabled
//
// This package maintains MCP's zero-external-dependency constraint.
// Event types mirror pkg/contracts (github.com/aegisgatesecurity/
// aegisgate-platform/pkg/contracts) but are defined locally.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.
// =========================================================================

package mcpsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// === Canonical Event Types (mirror pkg/contracts) ===

// PlatformEventSource identifies which product generated an event.
type PlatformEventSource string

const (
	PlatformSourceLens     PlatformEventSource = "lens"
	PlatformSourceRampart  PlatformEventSource = "rampart"
	PlatformSourceScanner  PlatformEventSource = "scanner"
	PlatformSourceMCP      PlatformEventSource = "mcp"
	PlatformSourcePlatform PlatformEventSource = "platform"
)

// PlatformEventDirection indicates the event direction.
type PlatformEventDirection string

const (
	PlatformDirRequest  PlatformEventDirection = "request"
	PlatformDirResponse PlatformEventDirection = "response"
	PlatformDirScan     PlatformEventDirection = "scan"
	PlatformDirRealtime PlatformEventDirection = "realtime"
)

// PlatformEvent is the metadata-only payload sent to Platform.
// Mirrors contracts.Event from pkg/contracts.
type PlatformEvent struct {
	ID              string                 `json:"id"`
	Source          PlatformEventSource    `json:"source"`
	SourceVersion   string                 `json:"source_version"`
	Timestamp       time.Time              `json:"timestamp"`
	SchemaVersion   string                 `json:"schema_version"`
	Direction       PlatformEventDirection `json:"direction,omitempty"`
	Host            string                 `json:"host,omitempty"`
	Path            string                 `json:"path,omitempty"`
	Artifact        string                 `json:"artifact,omitempty"`
	HashedDomain    string                 `json:"hashed_domain,omitempty"`
	TotalDetections int                    `json:"total_detections"`
	Blocked         bool                   `json:"blocked"`
	Action          string                 `json:"action,omitempty"`
	Findings        []PlatformEventFinding `json:"findings,omitempty"`
	Categories      []string               `json:"categories,omitempty"`
	Severities      []string               `json:"severities,omitempty"`
	Rules           []string               `json:"rules,omitempty"`
	PIICategories   []string               `json:"pii_categories,omitempty"`
	SecretTypes     []string               `json:"secret_types,omitempty"`
	MLScore         float64                `json:"ml_score,omitempty"`
	CorrelationID   string                 `json:"correlation_id,omitempty"`
	InstallationID  string                 `json:"installation_id,omitempty"`
}

// PlatformEventFinding is a single detection finding (metadata-only).
type PlatformEventFinding struct {
	RuleID     string  `json:"rule_id"`
	Category   string  `json:"category"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence,omitempty"`
	Message    string  `json:"message,omitempty"`
	Line       int     `json:"line,omitempty"`
	Column     int     `json:"column,omitempty"`
	EndLine    int     `json:"end_line,omitempty"`
	EndColumn  int     `json:"end_column,omitempty"`
}

// PlatformEventBatch is a batch of events sent in a single HTTP request.
type PlatformEventBatch struct {
	SchemaVersion string              `json:"schema_version"`
	Source        PlatformEventSource `json:"source"`
	Events        []PlatformEvent     `json:"events"`
}

// PlatformEventAck is the response from the receiver.
type PlatformEventAck struct {
	Accepted  int    `json:"accepted"`
	Rejected  int    `json:"rejected"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// === Forwarder ===

// PlatformForwarder pushes MCP detection events to AegisGate Platform.
//
// Air-gap compatible: if the platform URL is empty, all forwarding
// operations are no-ops. Uses a background goroutine for HTTP sends
// so it never blocks the MCP request pipeline.
type PlatformForwarder struct {
	url     string
	apiKey  string
	version string
	client  *http.Client
	enabled bool

	mu  sync.Mutex
	buf []PlatformEvent

	nowFunc func() time.Time
}

// NewPlatformForwarder creates a Platform forwarder. If url is empty,
// forwarding is disabled (air-gap compatible).
func NewPlatformForwarder(platformURL string) *PlatformForwarder {
	return NewPlatformForwarderWithAPIKey(platformURL, "")
}

// NewPlatformForwarderWithAPIKey creates a Platform forwarder with API key auth.
func NewPlatformForwarderWithAPIKey(platformURL, apiKey string) *PlatformForwarder {
	enabled := platformURL != ""
	if enabled {
		masked := maskPlatformURL(platformURL)
		log.Printf("mcp: platform forwarding enabled → %s", masked)
	} else {
		log.Printf("mcp: platform forwarding disabled (no platform_url configured)")
	}

	return &PlatformForwarder{
		url:     platformURL,
		apiKey:  apiKey,
		version: "0.1.0",
		client:  &http.Client{Timeout: 10 * time.Second},
		enabled: enabled,
		nowFunc: time.Now,
	}
}

// SetVersion sets the MCP version included in forwarded events.
func (f *PlatformForwarder) SetVersion(v string) {
	f.version = v
}

// Enabled returns whether forwarding is active.
func (f *PlatformForwarder) Enabled() bool {
	return f.enabled
}

// ForwardToolScreening forwards a tool screening result to Platform.
// This is called when a tool fails screening (tool poisoning detected).
func (f *PlatformForwarder) ForwardToolScreening(toolName string, findings []ToolCodeFinding, blocked bool) {
	if !f.enabled || len(findings) == 0 {
		return
	}
	event := toolScreeningToEvent(toolName, findings, blocked, f.version, f.nowFunc())
	go f.sendEvent(event)
}

// ForwardContentScan forwards a content scan result to Platform.
// This is called when the MCP scanner detects threats in a response.
func (f *PlatformForwarder) ForwardContentScan(direction string, findings []Finding, blocked bool) {
	if !f.enabled || len(findings) == 0 {
		return
	}
	event := contentScanToEvent(direction, findings, blocked, f.version, f.nowFunc())
	go f.sendEvent(event)
}

// ForwardBatch sends a pre-constructed event batch to Platform.
func (f *PlatformForwarder) ForwardBatch(batch PlatformEventBatch) error {
	if !f.enabled {
		return nil
	}
	return f.sendBatchSync(batch)
}

// Flush sends any buffered events.
func (f *PlatformForwarder) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.buf) == 0 {
		return nil
	}
	batch := PlatformEventBatch{
		SchemaVersion: "v1",
		Source:        PlatformSourceMCP,
		Events:        f.buf,
	}
	f.buf = f.buf[:0]
	return f.sendBatchSync(batch)
}

// HeartbeatResult contains the result of a Platform connectivity check.
type PlatformHeartbeatResult struct {
	Success   bool          `json:"success"`
	Latency   time.Duration `json:"latency_ms"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// Heartbeat performs a connectivity check to Platform's /api/v1/healthz.
func (f *PlatformForwarder) Heartbeat() PlatformHeartbeatResult {
	result := PlatformHeartbeatResult{Timestamp: f.nowFunc()}

	if !f.enabled {
		result.Error = "platform forwarding disabled"
		return result
	}

	healthURL := platformHealthzURL(f.url)
	start := f.nowFunc()

	req, err := http.NewRequest(http.MethodGet, healthURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}
	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("connectivity check failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Latency = f.nowFunc().Sub(start)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	result.Success = true
	return result
}

// StartHeartbeatLoop begins periodic heartbeat checks to Platform.
func (f *PlatformForwarder) StartHeartbeatLoop(ctx context.Context, interval time.Duration) <-chan PlatformHeartbeatResult {
	results := make(chan PlatformHeartbeatResult, 1)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(results)

		for {
			select {
			case <-ctx.Done():
				log.Printf("mcp: platform heartbeat loop stopped")
				return
			case <-ticker.C:
				result := f.Heartbeat()
				if result.Success {
					log.Printf("mcp: platform heartbeat OK (latency: %v)", result.Latency)
				} else {
					log.Printf("mcp: platform heartbeat FAILED: %s", result.Error)
				}
				select {
				case results <- result:
				default:
				}
			}
		}
	}()

	return results
}

// String implements fmt.Stringer.
func (f *PlatformForwarder) String() string {
	if !f.enabled {
		return "platform forwarding disabled"
	}
	return fmt.Sprintf("platform forwarding → %s", maskPlatformURL(f.url))
}

// === Internal methods ===

func (f *PlatformForwarder) sendEvent(event PlatformEvent) {
	batch := PlatformEventBatch{
		SchemaVersion: "v1",
		Source:        PlatformSourceMCP,
		Events:        []PlatformEvent{event},
	}
	if err := f.sendBatchSync(batch); err != nil {
		log.Printf("mcp: platform forward error: %v", err)
	}
}

func (f *PlatformForwarder) sendBatchSync(batch PlatformEventBatch) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("send error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("platform rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}

// === Converters ===

// toolScreeningToEvent converts tool code scan findings to a PlatformEvent.
func toolScreeningToEvent(toolName string, findings []ToolCodeFinding, blocked bool, version string, ts time.Time) PlatformEvent {
	eventFindings := make([]PlatformEventFinding, 0, len(findings))
	cats := make(map[string]struct{})
	sevs := make(map[string]struct{})
	rules := make(map[string]struct{})

	for _, f := range findings {
		ef := PlatformEventFinding{
			RuleID:   f.RuleName,
			Category: string(f.Category),
			Severity: f.Severity.String(),
			Message:  f.Message,
			Line:     f.Line,
			Column:   f.Column,
		}
		eventFindings = append(eventFindings, ef)
		cats[string(f.Category)] = struct{}{}
		sevs[f.Severity.String()] = struct{}{}
		rules[f.RuleName] = struct{}{}
	}

	action := "flagged"
	if blocked {
		action = "blocked"
	}

	return PlatformEvent{
		ID:              fmt.Sprintf("mcp-screen-%d", ts.UnixNano()),
		Source:          PlatformSourceMCP,
		SourceVersion:   version,
		Timestamp:       ts,
		SchemaVersion:   "v1",
		Direction:       PlatformDirRealtime,
		Artifact:        toolName,
		TotalDetections: len(findings),
		Blocked:         blocked,
		Action:          action,
		Findings:        eventFindings,
		Categories:      mapKeysStr(cats),
		Severities:      mapKeysStr(sevs),
		Rules:           mapKeysStr(rules),
	}
}

// contentScanToEvent converts content scan findings to a PlatformEvent.
func contentScanToEvent(direction string, findings []Finding, blocked bool, version string, ts time.Time) PlatformEvent {
	eventFindings := make([]PlatformEventFinding, 0, len(findings))
	cats := make(map[string]struct{})
	sevs := make(map[string]struct{})
	rules := make(map[string]struct{})

	for _, f := range findings {
		if f.Pattern == nil {
			continue
		}
		ef := PlatformEventFinding{
			RuleID:   f.Pattern.Name,
			Category: string(f.Pattern.Category),
			Severity: f.Pattern.Severity.String(),
			Message:  f.Pattern.Description,
		}
		eventFindings = append(eventFindings, ef)
		cats[string(f.Pattern.Category)] = struct{}{}
		sevs[f.Pattern.Severity.String()] = struct{}{}
		rules[f.Pattern.Name] = struct{}{}
	}

	action := "warned"
	if blocked {
		action = "blocked"
	}

	dir := PlatformDirResponse
	if direction == "request" {
		dir = PlatformDirRequest
	}

	return PlatformEvent{
		ID:              fmt.Sprintf("mcp-scan-%d", ts.UnixNano()),
		Source:          PlatformSourceMCP,
		SourceVersion:   version,
		Timestamp:       ts,
		SchemaVersion:   "v1",
		Direction:       dir,
		TotalDetections: len(eventFindings),
		Blocked:         blocked,
		Action:          action,
		Findings:        eventFindings,
		Categories:      mapKeysStr(cats),
		Severities:      mapKeysStr(sevs),
		Rules:           mapKeysStr(rules),
	}
}

// === Helpers ===

func mapKeysStr(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func maskPlatformURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}
	return u.Scheme + "://" + u.Hostname() + "/..."
}

func platformHealthzURL(telemetryURL string) string {
	u, err := url.Parse(telemetryURL)
	if err != nil {
		return telemetryURL
	}
	u.Path = "/api/v1/healthz"
	return u.String()
}
