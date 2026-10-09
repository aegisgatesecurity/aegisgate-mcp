# AegisGate MCP Administrator Guide

**Product:** AegisGate MCP  
**Trademarks:** AegisGate MCP is a product of AegisGate Security, LLC  
**License:** Apache-2.0  
**Version:** 1.4.2  
**Runtime:** Go 1.26+ (zero external dependencies)  
**Audience:** System administrators managing AegisGate MCP in production  

---

## Table of Contents

1. [Overview](#1-overview)
2. [Authentication Configuration](#2-authentication-configuration)
3. [RBAC (Role-Based Access Control)]#3-rbac-role-based-access-control)
4. [Policy Engine](#4-policy-engine)
5. [Audit Logging](#5-audit-logging)
6. [Rate Limiting and Guardrails](#6-rate-limiting-and-guardrails)
7. [Response Scanning and Redaction](#7-response-scanning-and-redaction)
8. [Health Monitoring](#8-health-monitoring)
9. [Signature Verification (Anti-Forgery)](#9-signature-verification-anti-forgery)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

AegisGate MCP is a security-first Model Context Protocol (MCP) server designed for secure AI agent tool use across any environment. As an administrator, you are responsible for the configuration, maintenance, and monitoring of the following subsystems:

| Subsystem | Responsibility |
|-----------|---------------|
| **Authentication** | Validate client identity via bearer tokens or API keys |
| **RBAC** | Enforce role-based permissions per agent |
| **Policy Engine** | Evaluate custom and built-in rules against tool calls |
| **Audit Logging** | Record all session and tool activity for compliance |
| **Rate Limiting** | Protect the server from runaway or excessive requests |
| **Response Scanning** | Detect and redact PII, secrets, XSS, and prompt injection in tool output |
| **Health Monitoring** | Expose health, readiness, and statistics endpoints for observability |

Each subsystem is independently configurable through CLI flags, environment variables, or a JSON configuration file. This guide covers all three configuration methods for every subsystem.

---

## 2. Authentication Configuration

AegisGate MCP supports two authentication mechanisms: **Bearer Token** and **API Key**. Both are presented by clients during the MCP `initialize` handshake. Authentication is mandatory—unauthenticated connections are refused.

### 2.1 Bearer Token Auth

The simplest authentication method. A single shared token is configured on the server and presented by all clients.

**Configuration:**

| Method | Example |
|--------|---------|
| CLI flag | `--token "my-secret-token"` |
| Environment variable | `MCP_AUTH_TOKEN=my-secret-token` |
| Config JSON | `{"AuthToken": "my-secret-token"}` |

**Client flow:**

1. Client sends `initialize` with `params.auth.token` set to the bearer token.
2. Server compares the provided token against the configured token using `crypto/subtle.ConstantTimeCompare`, which prevents timing-based side-channel attacks.
3. If the token matches, the connection is authenticated and proceeds to the `initialized` notification.
4. If the token does not match, a failed-attempt counter is incremented for that connection.

> **Security note:** The constant-time comparison ensures that an attacker cannot determine the correct token by measuring response latency. Always use a high-entropy token (minimum 32 characters of random data).

### 2.2 API Key Auth

For multi-agent deployments, API key authentication provides per-agent identity. A map of agent IDs to API keys is configured on the server.

**Configuration (Go library):**

```go
config := mcp.ServerConfigV2{
    APIKeys: map[string]string{
        "agent-001": "key-alpha-9f2a...",
        "agent-002": "key-beta-3c7e...",
        "agent-003": "key-gamma-1d4b...",
    },
}
```

**Configuration (config JSON):**

```json
{
  "APIKeys": {
    "agent-001": "key-alpha-9f2a...",
    "agent-002": "key-beta-3c7e...",
    "agent-003": "key-gamma-1d4b..."
  }
}
```

**Client flow:**

1. Client sends `initialize` with `params.auth.agent_id` and `params.auth.api_key`.
2. Server looks up the agent ID in the API key map and compares the provided key using constant-time comparison.
3. If the agent ID is not found or the key does not match, a failed-attempt counter is incremented.

### 2.3 Auth Lockout

To prevent brute-force attacks, AegisGate MCP enforces a per-connection lockout after repeated authentication failures.

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxAuthAttempts` | 5 | Maximum failed authentication attempts before the connection is blocked |

**Key characteristics:**

- Lockout is **per-connection**, not global. A blocked connection does not affect other clients.
- After the threshold is reached, the connection is immediately closed and no further requests are processed.
- A new connection from the same client (or any client) starts with a fresh attempt counter.
- The threshold is configurable via `ServerConfigV2.MaxAuthAttempts` in the Go library.

> **Operational note:** Because lockout is per-connection, a distributed brute-force attack across many connections will not be halted by this mechanism alone. Deploy network-level controls (firewall rules, IP allow-listing) in OT environments to complement this feature.

---

## 3. RBAC (Role-Based Access Control)

RBAC assigns each authenticated agent a role that determines which tools it may invoke. Roles are hierarchical—higher roles inherit all permissions of lower roles. Individual tool permissions can be overridden per agent.

### 3.1 Role Hierarchy

| Role | Level | Permissions |
|------|-------|-------------|
| `restricted` | 1 | Read-only: `ping`, `system_info`, `file_exists`, `git_status`, `git_log` |
| `standard` | 2 | Read + low-risk write: `file_read`, `code_search`, `web_search`, `file_copy` |
| `privileged` | 3 | Everything **except**: `shell_command`, `code_execute` |
| `admin` | 4 | All tools (unrestricted) |

Roles are enforced at the `tool_call` stage. When an agent invokes a tool, the server checks the agent's role and any per-tool overrides before dispatching the call.

### 3.2 Registering Agents

Agents must be registered with the server before they can authenticate. Registration assigns the agent an ID, a human-readable name, a role, and an optional set of per-tool permissions.

```go
agent := srv.RegisterAgent("agent-001", "Plant Floor Agent", mcp.RoleStandard, []mcp.ToolPermission{
    {ToolName: "ping",         Allowed: true},
    {ToolName: "system_info",  Allowed: true},
    {ToolName: "echo",         Allowed: true},
})
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `agentID` | `string` | Unique identifier for the agent (must match API key map entry) |
| `name` | `string` | Human-readable name for logging and audit |
| `role` | `mcp.Role` | One of `RoleRestricted`, `RoleStandard`, `RolePrivileged`, `RoleAdmin` |
| `permissions` | `[]mcp.ToolPermission` | Optional per-tool allow/deny overrides |

### 3.3 Custom Tool Permissions

Each agent can have per-tool allow/deny lists that override the role default. This allows fine-grained control without creating new roles.

```go
// Allow a restricted agent to also use code_search
agent := srv.RegisterAgent("analyst-01", "Threat Analyst", mcp.RoleRestricted, []mcp.ToolPermission{
    {ToolName: "code_search", Allowed: true},
})

// Deny an admin agent from using shell_command (break-glass restriction)
agent := srv.RegisterAgent("admin-01", "Break-Glass Admin", mcp.RoleAdmin, []mcp.ToolPermission{
    {ToolName: "shell_command", Allowed: false},
})
```

**Evaluation order:**

1. Per-tool permissions are checked first. If a tool has an explicit `Allowed: true` or `Allowed: false`, that decision is final.
2. If no per-tool permission exists for the requested tool, the role's default permission set is applied.
3. If neither the per-tool list nor the role grants access, the tool call is denied.

> **Best practice:** Use per-tool deny entries to enforce break-glass restrictions on otherwise unrestricted roles. Log all `Allowed: false` overrides in the audit log for review.

---

## 4. Policy Engine

The policy engine is a rule-based evaluation layer that runs **after** RBAC but **before** tool execution. It allows administrators to define dynamic, context-aware rules that go beyond static role permissions.

### 4.1 How It Works

The policy engine evaluates rules in **priority order** (lower number = higher priority). The first matching rule determines the outcome. Each rule can match on one or more of the following conditions:

| Condition Field | Type | Description |
|-----------------|------|-------------|
| `ToolName` | `string` | Tool name with wildcard support (e.g., `shell_*`, `*exec*`) |
| `AgentID` | `string` | Match a specific agent |
| `AgentRole` | `mcp.Role` | Match agents of a specific role |
| `RiskScore` | `int` | Match when the tool's risk score exceeds the threshold |
| `ParamPatterns` | `map[string]string` | Regex patterns matched against tool parameters |
| `TimeWindow` | `*mcp.TimeWindow` | Only match during specified time ranges |
| `CustomMatch` | `func(...) bool` | Custom Go function for arbitrary logic |

A rule matches only if **all** specified conditions in the rule are satisfied. Conditions that are not set (zero value) are ignored.

### 4.2 Built-in Rules

Built-in rules are loaded automatically when you call `LoadDefaultPolicies()`. They provide baseline protection for common security threats.

| Rule | Priority | Action | Condition |
|------|----------|--------|-----------|
| `block-shell-commands` | 10 | Deny | Tool name matches `shell_*` or `*exec*` |
| `block-file-delete` | 20 | Deny | Tool name matches `*delete*` or `*remove*` |
| `block-network-write` | 30 | Deny | Tool name = `http_request` with write params |
| `alert-high-risk` | 100 | Allow + log | Risk score > 70 |

```go
srv.LoadDefaultPolicies()
```

> **Recommendation:** Always call `LoadDefaultPolicies()` during server initialization, then add custom rules on top. The built-in rules are designed to be non-overlapping with typical custom rules.

### 4.3 Adding Custom Rules

Custom rules extend the policy engine to address site-specific requirements.

#### Time-Based Rule (After-Hours Blocking)

```go
srv.AddPolicyRule(mcp.PolicyRule{
    Name:     "block-after-hours",
    Priority: 15,
    Action:   mcp.PolicyDeny,
    Condition: mcp.Condition{
        TimeWindow: &mcp.TimeWindow{
            Start: "18:00",
            End:   "06:00",
            Days:  []string{"Sat", "Sun"},
        },
    },
})
```

This rule denies all tool calls outside of business hours on weekends. The priority of 15 places it between `block-shell-commands` (10) and `block-file-delete` (20), so it is evaluated early.

#### Parameter-Based Rule (Block Internal IPs)

```go
srv.AddPolicyRule(mcp.PolicyRule{
    Name:     "block-internal-ips",
    Priority: 25,
    Action:   mcp.PolicyDeny,
    Condition: mcp.Condition{
        ToolName: "http_request",
        ParamPatterns: map[string]string{
            "url": `^192\.168\..*`,
        },
    },
})
```

This rule denies `http_request` calls whose `url` parameter matches a `192.168.x.x` address. The regex is anchored with `^` to match the beginning of the URL string.

### 4.4 Policy Actions

| Action | Constant | Behavior |
|--------|----------|----------|
| Allow | `mcp.PolicyAllow` | Request proceeds to tool execution |
| Deny | `mcp.PolicyDeny` | Request is rejected with a policy denial message |
| Allow + Log | `mcp.PolicyAllow` with `Log: true` | Request proceeds, but an audit entry is written for review |

### 4.5 Policy Evaluation Order

```
Client request
    │
    ▼
RBAC check (role + per-tool permissions)
    │  ─── Deny ──▶ Reject
    ▼  ─── Allow ──▶ Continue
Policy engine (rules in priority order)
    │  ─── Deny ──▶ Reject + audit log
    ▼  ─── Allow ──▶ Continue
Tool execution
    │
    ▼
Response scanning (PII, secrets, XSS, prompt injection)
    │  ─── Block ──▶ Replace response with error
    ▼  ─── Pass ──▶ Deliver response to client
```

---

## 5. Audit Logging

The audit log is the primary record of all activity on the AegisGate MCP server. It captures every session lifecycle event and tool call outcome in a tamper-evident, append-only format.

### 5.1 Configuration

| Method | Example |
|--------|---------|
| CLI flag | `--audit /var/log/mcp/audit.json` |
| Environment variable | `MCP_AUDIT_LOG=/var/log/mcp/audit.json` |
| Config JSON | `{"AuditLogPath": "/var/log/mcp/audit.json"}` |

| Setting | Default | Description |
|---------|---------|-------------|
| `AuditLogPath` | (none) | File path for the audit log. If not set, auditing is in-memory only. |
| `MaxAuditEntries` | 10,000 | Size of the in-memory ring buffer. Oldest entries are evicted when full. |

The log file is written in **JSON Lines** format—one JSON object per line. This format is optimized for streaming parsers (`jq`, `grep`, log shippers) and avoids the need to load the entire file into memory.

### 5.2 Audit Entry Types

| Type | When |
|------|------|
| `initialize` | Client sends `initialize` request |
| `initialized` | Client sends `notifications/initialized` |
| `tool_success` | Tool executed successfully |
| `tool_denied` | Tool call denied by RBAC or policy engine |
| `tool_error` | Tool execution returned an error |
| `tool_timeout` | Tool execution exceeded the timeout and was killed |
| `tool_invalid_params` | Required parameters were missing or invalid |

### 5.3 Reading the Audit Log

The JSON Lines format is easily queried with `jq`:

```bash
# All entries (pretty-printed)
cat /var/log/mcp/audit.json | jq .

# Denied tool calls
cat /var/log/mcp/audit.json | jq 'select(.type == "tool_denied")'

# Tool errors and timeouts
cat /var/log/mcp/audit.json | jq 'select(.type == "tool_error" or .type == "tool_timeout")'

# Specific session
cat /var/log/mcp/audit.json | jq 'select(.sessionId == "conn-1234567890")'

# All activity for a specific agent
cat /var/log/mcp/audit.json | jq 'select(.agentId == "agent-001")'
```

### 5.4 Programmatic Query (Go Library)

For integration with monitoring dashboards or SIEM systems, the audit logger can be queried programmatically:

```go
entries := srv.auditLogger.Query(&mcp.AuditFilter{
    Type:      "tool_denied",
    StartTime: time.Now().Add(-1 * time.Hour),
})
```

**AuditFilter fields:**

| Field | Type | Description |
|-------|------|-------------|
| `Type` | `string` | Filter by entry type (e.g., `"tool_denied"`) |
| `StartTime` | `time.Time` | Only entries at or after this time |
| `EndTime` | `time.Time` | Only entries at or before this time |
| `SessionID` | `string` | Filter by session ID |
| `AgentID` | `string` | Filter by agent ID |
| `ToolName` | `string` | Filter by tool name |

> **Compliance tip:** In regulated environments subject to NERC CIP or IEC 62443, retain audit logs for a minimum of 90 days (or per your regulatory requirement). Use a log rotation tool (e.g., `logrotate`) to manage file growth, and forward logs to a centralized SIEM for correlation.

---

## 6. Rate Limiting and Guardrails

Rate limiting and guardrails protect the server from resource exhaustion and runaway agent behavior.

### 6.1 Rate Limiting

Limits the number of tool calls per minute on a per-connection basis.

| Method | Example |
|--------|---------|
| CLI flag | `--rate-limit 60` |
| Environment variable | `MCP_RATE_LIMIT_RPM=60` |
| Config JSON | `{"RateLimitRPM": 60}` |

| Setting | Default | Description |
|---------|---------|-------------|
| `RateLimitRPM` | 60 | Maximum requests per minute, per connection |

When the limit is exceeded, the server returns a JSON-RPC error:

```
Error code: -32002 (ErrorRateLimited)
Message:    "rate limit exceeded: <N> requests in <window>"
```

The rate limiter uses a sliding window algorithm. The counter resets continuously—there is no fixed window boundary—so bursts are smoothed over time.

### 6.2 Session Limits

Limits the number of concurrent connections to the server.

| Method | Example |
|--------|---------|
| CLI flag | `--max-sessions 50` |
| Environment variable | `MCP_MAX_SESSIONS=50` |
| Config JSON | `{"MaxSessions": 50}` |

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxSessions` | 50 | Maximum concurrent connections |

Excess connections are rejected immediately during the `initialize` handshake. The client receives an error response indicating that the server is at capacity.

### Connection Limits

Limits the number of concurrent TCP connections to the server (separate from session limits).

| Method | Example |
|--------|---------|
| CLI flag | `--max-connections 1000` |
| Environment variable | `MCP_MAX_CONNECTIONS=1000` |
| Config JSON | `{"MaxConnections": 1000}` |

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxConnections` | 1000 | Maximum concurrent TCP connections. Set to -1 for unlimited (use with network-level controls). |

When the connection limit is reached, new connections are immediately closed. The event is logged at `WARN` level with the active and max connection counts.

### 6.3 Tool Call Limits

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxToolsPerSession` | 100 | Maximum tool calls per session (lifetime of the connection) |

This guardrail prevents runaway agents that enter infinite loops or generate excessive tool calls. When the limit is reached, all subsequent tool calls for that session are rejected.

### 6.4 Execution Timeout

| Method | Example |
|--------|---------|
| CLI flag | `--exec-timeout 30` |
| Environment variable | `MCP_EXEC_TIMEOUT=30` |
| Config JSON | `{"ExecTimeout": 30}` |

| Setting | Default | Description |
|---------|---------|-------------|
| `ExecTimeout` | 30 seconds | Maximum execution time per tool call |

If a tool call exceeds the timeout, it is terminated and a `tool_timeout` audit entry is recorded. The client receives a JSON-RPC error indicating the timeout.

### 6.5 Guardrail Summary

| Guardrail | Scope | Default | Error on Exceed |
|-----------|-------|---------|-----------------|
| Rate limit | Per connection | 60 RPM | `-32002 ErrorRateLimited` |
| Max sessions | Global | 50 | Connection rejected |
| Max connections | Global | 1000 | Connection closed + log |
| Max tools per session | Per session | 100 | Tool call rejected |
| Exec timeout | Per tool call | 30s | `tool_timeout` audit entry + error |

---

## 7. Response Scanning and Redaction

AegisGate MCP scans tool responses before delivering them to the client. This prevents sensitive data leakage, injection attacks, and prompt manipulation—all important in security-sensitive environments where tool output may contain configuration secrets, network diagrams, or operational data.

### 7.1 Response Scanning

Response scanning is **enabled by default**. The scanner checks for four categories of sensitive or malicious content:

| Category | Detected Patterns |
|----------|-------------------|
| **PII** | Email addresses, phone numbers, Social Security Numbers (SSN), credit card numbers |
| **Secrets** | API keys, bearer tokens, AWS access keys, private keys (PEM blocks) |
| **XSS** | `<script>` tags, inline event handlers (`onload`, `onerror`), `javascript:` URIs |
| **Prompt injection** | "ignore previous instructions", system prompt extraction attempts, role override patterns |

### 7.2 Block vs Redact

AegisGate MCP offers two independent response modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Block** (default) | The entire response is replaced with an error message. The client receives no data. | High-security environments where any sensitive data exposure is unacceptable. |
| **Redact** | Sensitive data within the response is replaced with a `[REDACTED]` placeholder. The rest of the response is delivered normally. | Environments where partial responses are still useful (e.g., log analysis, debugging). |

Both modes can be enabled simultaneously. When both are active, block rules are evaluated first. If no block rule matches, redaction rules are applied to the remaining content.

### 7.3 Configuration

| Flag | Default | Effect |
|------|---------|--------|
| `--scan-responses` | `true` | Enable response scanning |
| `--block-pii` | `true` | Block responses containing PII |
| `--block-secrets` | `true` | Block responses containing secrets |
| `--block-xss` | `true` | Block responses containing XSS |
| `--block-prompt-inject` | `true` | Block responses containing prompt injection |
| `--redact` | `false` | Enable redaction mode |
| `--redact-pii` | `false` | Redact PII patterns in responses |
| `--redact-secrets` | `true` | Redact secret patterns in responses |
| `--redact-placeholder` | `[REDACTED]` | Placeholder text used for redacted content |

**Example: Enable redaction for secrets only, block everything else:**

```bash
./mcp-server \
  --scan-responses \
  --block-pii \
  --block-xss \
  --block-prompt-inject \
  --redact \
  --redact-secrets
```

> **Security recommendation:** In production OT environments, enable all block modes (`--block-pii --block-secrets --block-xss --block-prompt-inject`) and leave redaction disabled. This provides the strictest data protection. Enable redaction only in development or staging environments where debugging requires partial output.

---

## 7a. ML Threat Detection (L3 — Neural)

AegisGate MCP includes a CharCNN-BiLSTM v13 neural model that detects
semantic attacks and evasion variants that regex pattern matching cannot
catch. This is the same model used by AegisGate Platform and Rampart,
vendored with zero external module dependencies.

### 7a.1 How It Works

The model runs on every tool input parameter (string values) and on every
tool response. It produces a threat score from 0.0 to 1.0. Two-tier
blocking prevents false positives:

| Tier | Score Range | Behavior |
|------|-------------|----------|
| **Tier 1** | ≥ 0.95 | Block independently — no corroboration needed |
| **Tier 2** | 0.50 – 0.94 | Block only if L1 (regex) or L2 (input scanner) also flagged the content |
| **Alert** | < 0.50 | No action (below threshold) |

### 7a.2 Configuration

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--ml` | `MCP_ML_ENABLED` | `false` | Enable neural threat detection |
| `--ml-shadow` | `MCP_ML_SHADOW` | `false` | Log predictions but never block |
| `--ml-threshold` | `MCP_ML_THRESHOLD` | `0.50` | Threat score threshold |
| `--ml-model` | `MCP_ML_MODEL` | `./models/threat_cnn_bilstm.onnx` | ONNX model path |

**Docker defaults:** ML is enabled by default in the Docker image
(`MCP_ML_ENABLED=true`). For CLI/binary deployments, pass `--ml` or set
`MCP_ML_ENABLED=true`.

### 7a.3 Shadow Mode

Shadow mode logs all ML predictions to the audit log without blocking any
requests. Use this for a 7-day calibration period before enabling blocking
in production:

```bash
./mcp-server --ml --ml-shadow --token your-token --demo
```

### 7a.4 Audit Entries

ML blocks are recorded in the audit log with type `ml_input_blocked` or
`ml_response_blocked`:

```json
{
  "type": "ml_input_blocked",
  "reason": "neural threat detected (score: 1.000, high confidence)",
  "toolName": "echo",
  "allowed": false
}
```

### 7a.5 Build Modes

| Mode | Build Command | Features |
|------|---------------|----------|
| **CGO (full)** | `CGO_ENABLED=1 CGO_LDFLAGS="-Llib -lonnxruntime"` | Neural + heuristic + NFKC |
| **Non-CGO (lite)** | `CGO_ENABLED=0` | Heuristic + NFKC only (no ONNX) |

When CGO is unavailable or the model fails to load, the server automatically
falls back to heuristic-only detection.

---

## 8. Health Monitoring

AegisGate MCP exposes an HTTP health and stats endpoint for integration with load balancers, Kubernetes probes, and monitoring systems.

### 8.1 Enabling the Health Endpoint

| Method | Example |
|--------|---------|
| CLI flag | `--health-addr :8082` |
| Environment variable | `MCP_HEALTH_ADDR=:8082` |
| Config JSON | `{"HealthAddr": ":8082"}` |

If `HealthAddr` is not configured, the health endpoint is disabled.

### 8.2 Endpoints

| Endpoint | Method | Success Response | Failure Response |
|----------|--------|------------------|------------------|
| `/healthz` | GET | `200` + `{"status":"ok","version":"1.4.2"}` | — |
| `/readyz` | GET | `200` + `{"status":"ready"}` | `503` + `{"status":"not ready"}` |
| `/stats` | GET | `200` + JSON stats object | — |

**`/healthz`** — Liveness probe. Always returns 200 if the server process is running. Use this for Kubernetes `livenessProbe`.

**`/readyz`** — Readiness probe. Returns 200 when the server is ready to accept connections, 503 during startup or shutdown. Use this for Kubernetes `readinessProbe`.

**`/stats`** — Operational statistics. Returns a JSON object with real-time server metrics.

### 8.3 Stats Response Example

```json
{
  "tools_registered": 3,
  "active_sessions": 2,
  "active_connections": 5,
  "max_connections": 1000,
  "guardrails": {
    "rate_limit_rpm": 60,
    "max_sessions": 50,
    "active_rate_limits": 2
  },
  "audit_entries": 1542,
  "stdio_checks": 0,
  "trusted_keys": 1,
  "policy_rules": 4
}
```

**Field reference:**

| Field | Description |
|-------|-------------|
| `tools_registered` | Number of tools registered on the server |
| `active_sessions` | Current number of connected and authenticated clients |
| `active_connections` | Current number of active TCP connections |
| `max_connections` | Configured maximum concurrent TCP connections |
| `guardrails.rate_limit_rpm` | Configured rate limit (requests per minute) |
| `guardrails.max_sessions` | Configured maximum concurrent sessions |
| `guardrails.active_rate_limits` | Number of connections currently being rate-limited |
| `audit_entries` | Total number of audit entries recorded (in-memory + file) |
| `stdio_checks` | Number of stdio integrity checks performed |
| `trusted_keys` | Number of trusted public keys registered for signature verification |
| `policy_rules` | Number of policy rules currently loaded in the engine |

### 8.4 Monitoring Integration

**Prometheus scrape example (via JSON exporter):**

```yaml
scrape_configs:
  - job_name: 'aegisgate-mcp'
    metrics_path: /stats
    static_configs:
      - targets: ['localhost:8082']
```

**Kubernetes probes:**

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8082
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: 8082
  initialDelaySeconds: 3
  periodSeconds: 5
```

### 8.5 Prometheus Metrics

When the health endpoint is enabled with `--health-addr`, AegisGate MCP exposes Prometheus-format metrics at `/metrics`:

```
# Available metrics:
aegisgate_mcp_up                       # Server running (1)
aegisgate_mcp_tools_registered         # Number of registered tools
aegisgate_mcp_active_sessions          # Number of active sessions
aegisgate_mcp_active_connections       # Number of active TCP connections
aegisgate_mcp_max_connections          # Maximum concurrent TCP connections
aegisgate_mcp_audit_entries            # Total audit log entries
aegisgate_mcp_trusted_keys             # Trusted signature verification keys
aegisgate_mcp_policy_rules             # Loaded policy rules
aegisgate_mcp_rate_limit_rpm           # Configured rate limit per minute
aegisgate_mcp_max_sessions             # Maximum concurrent sessions
```

**Prometheus scrape config:**

```yaml
scrape_configs:
  - job_name: 'aegisgate-mcp'
    static_configs:
      - targets: ['localhost:8082']
    metrics_path: /metrics
```

---

## 9. Signature Verification (Anti-Forgery)

Signature verification provides cryptographic assurance that a request originated from a known, trusted client. This is an additional layer on top of authentication—it prevents a compromised token or API key from being used by an unauthorized actor, because the attacker would also need the client's private signing key.

### 9.1 Adding Trusted Keys

The server maintains a registry of trusted public keys. Each key is identified by a `KeyID` string chosen by the administrator.

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
)

// Generate a P-256 key pair for the client
privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
pubKeySEC1 := elliptic.Marshal(elliptic.P256(), privKey.X, privKey.Y)

// Register the public key on the server
srv.AddTrustedKey("client-key-1", pubKeySEC1)
```

> **Key management:** Store the private key securely on the client side (e.g., in a TPM, HSM, or sealed secret). The public key can be freely shared—it is only used for verification. Rotate keys periodically and update the server registry accordingly.

### 9.2 How It Works

1. **Client signs the request:** The client constructs the canonical JSON of their request (parameters sorted, whitespace removed) and signs it with their ECDSA P-256 private key.
2. **Signature is transmitted:** The signature is included in the `JSONRPCRequest.Signature` field as a hex-encoded ASN.1 DER string. The `KeyID` field identifies which trusted key the server should use for verification.
3. **Server verifies:** The server looks up the public key by `KeyID`, reconstructs the canonical JSON from the received request, and verifies the signature.
4. **Rejection on failure:** If the signature is missing, invalid, or does not match the canonical request, the request is rejected with a verification error before any tool logic is executed.

### 9.3 Signature Verification Flow

```
Client                                    Server
  │                                          │
  │  1. Build canonical JSON of request      │
  │  2. Sign with ECDSA P-256 private key    │
  │  3. Attach Signature + KeyID to request  │
  │                                          │
  │ ──────── JSONRPCRequest ──────────────▶  │
  │                                          │
  │                          4. Look up public key by KeyID
  │                          5. Reconstruct canonical JSON
  │                          6. Verify signature
  │                                          │
  │  ◀──── Verification result ───────────── │
  │     (proceed or reject)                  │
```

> **Security recommendation:** Enable signature verification for all agents with `privileged` or `admin` roles. These roles have the broadest tool access, making them the highest-value targets for token theft or request forgery.

---

## 10. Troubleshooting

### 10.1 Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `"not authenticated"` error | No `initialize` sent, or wrong token/API key | Send `initialize` with correct auth credentials before calling tools |
| `"Tool call denied"` | RBAC or policy engine blocked the tool | Check the agent's role, per-tool permissions, and active policy rules |
| `"Rate limited"` | Exceeded RPM limit | Increase `--rate-limit` or reduce request frequency |
| `"Tool execution timed out"` | Tool exceeded the execution timeout | Increase `--exec-timeout` or investigate why the tool is slow |
| `"Missing required parameters"` | Required `inputSchema` fields not provided | Check the tool's `inputSchema` for required fields and provide all of them |
| `"Method not found"` | Unsupported or misspelled MCP method | Verify the method name is in the supported method list |
| Connection refused | Server not running, or wrong address | Check `--addr` flag and verify the server process is active |
| TLS handshake failure | Certificate or key issues | Verify certificate and key file paths, formats (PEM), and expiration dates |

### 10.2 Log Levels

AegisGate MCP uses Go's `slog` (structured logging) for operational logs. Control verbosity with environment variables:

```bash
# Verbose (debug-level logs including policy evaluation, auth attempts, scan results)
GODEBUG=slog=debug ./mcp-server

# Normal (default — info-level logs including startup, errors, warnings)
./mcp-server

# Quiet (warning-level and above only)
GODEBUG=slog=warn ./mcp-server
```

Structured logs are emitted as JSON objects to stderr by default. Key fields include:

| Field | Description |
|-------|-------------|
| `time` | ISO 8601 timestamp |
| `level` | Log level (`DEBUG`, `INFO`, `WARN`, `ERROR`) |
| `msg` | Human-readable message |
| `sessionId` | Connection session ID (when applicable) |
| `agentId` | Agent ID (when authenticated) |
| `toolName` | Tool name (for tool-related events) |

### 10.3 Checking Audit Logs for Security Events

The audit log is the primary source of truth for security investigations. Below are common queries for incident response and routine review.

```bash
# Count denied tool calls in the last hour
cat /var/log/mcp/audit.json | jq 'select(.type == "tool_denied")' | wc -l

# Find all timeouts
cat /var/log/mcp/audit.json | jq 'select(.type == "tool_timeout")'

# Most frequently denied tools (top 10)
cat /var/log/mcp/audit.json | jq -r 'select(.type == "tool_denied") | .toolName' | sort | uniq -c | sort -rn | head -10

# All activity from a specific agent
cat /var/log/mcp/audit.json | jq 'select(.agentId == "agent-001")'

# Authentication failures (initialize events that did not result in initialized)
cat /var/log/mcp/audit.json | jq 'select(.type == "initialize" and .success == false)'

# All events in a time range (example: 2026-10-07 09:00 to 10:00)
cat /var/log/mcp/audit.json | jq 'select(.timestamp >= "2026-10-07T09:00:00Z" and .timestamp < "2026-10-07T10:00:00Z")'
```

### 10.4 Diagnostic Checklist

When investigating an issue, work through this checklist in order:

1. **Check the health endpoint:** `curl http://localhost:8082/healthz` — Is the server running?
2. **Check the stats endpoint:** `curl http://localhost:8082/stats` — Are sessions active? Are rate limits being hit?
3. **Check the audit log:** Query for `tool_denied` and `tool_error` entries related to the issue.
4. **Check the operational logs:** Run with `GODEBUG=slog=debug` to capture detailed policy evaluation and auth attempts.
5. **Verify configuration:** Ensure CLI flags, environment variables, and config JSON are not conflicting. Config JSON takes precedence over defaults, CLI flags override config JSON, and environment variables are evaluated per-flag.
6. **Verify network connectivity:** Confirm the client can reach the server address and that TLS certificates (if used) are valid.

### 10.5 Getting Support

| Resource | Description |
|----------|-------------|
| Audit log | First source of truth for all operational and security events |
| Stats endpoint (`/stats`) | Real-time server state for quick diagnostics |
| Structured logs (`slog`) | Detailed runtime information at adjustable verbosity |
| GitHub issues | Report bugs and request features at the AegisGate MCP repository |
| Apache-2.0 license | No warranty is provided; review the `LICENSE` file for terms |

---

## Appendix A: Quick Reference — All Configuration Options

| Flag | Env Var | Config JSON Key | Default | Section |
|------|---------|-----------------|---------|---------|
| `--token` | `MCP_AUTH_TOKEN` | `AuthToken` | (none) | §2.1 |
| `--audit` | `MCP_AUDIT_LOG` | `AuditLogPath` | (none) | §5.1 |
| `--rate-limit` | `MCP_RATE_LIMIT_RPM` | `RateLimitRPM` | 60 | §6.1 |
| `--max-sessions` | `MCP_MAX_SESSIONS` | `MaxSessions` | 50 | §6.2 |
| `--max-connections` | `MCP_MAX_CONNECTIONS` | `MaxConnections` | 1000 | §6.2 |
| `--exec-timeout` | `MCP_EXEC_TIMEOUT` | `ExecTimeout` | 30 | §6.4 |
| `--scan-responses` | — | — | `true` | §7.3 |
| `--block-pii` | — | — | `true` | §7.3 |
| `--block-secrets` | — | — | `true` | §7.3 |
| `--block-xss` | — | — | `true` | §7.3 |
| `--block-prompt-inject` | — | — | `true` | §7.3 |
| `--redact` | — | — | `false` | §7.3 |
| `--redact-pii` | — | — | `false` | §7.3 |
| `--redact-secrets` | — | — | `true` | §7.3 |
| `--redact-placeholder` | — | — | `[REDACTED]` | §7.3 |
| `--health-addr` | `MCP_HEALTH_ADDR` | `HealthAddr` | (disabled) | §8.1 |
| `--ml` | `MCP_ML_ENABLED` | `MLEnabled` | `false` | §7a.2 |
| `--ml-shadow` | `MCP_ML_SHADOW` | `MLShadowMode` | `false` | §7a.2 |
| `--ml-threshold` | `MCP_ML_THRESHOLD` | `MLThreshold` | `0.50` | §7a.2 |
| `--ml-model` | `MCP_ML_MODEL` | `MLModelPath` | `./models/threat_cnn_bilstm.onnx` | §7a.2 |

---

## Appendix B: Recommended Production Configuration

```bash
#!/bin/bash
# AegisGate MCP production startup script

./mcp-server \
  --token "$(cat /etc/mcp/secrets/auth-token)" \
  --audit /var/log/mcp/audit.json \
  --rate-limit 60 \
  --max-sessions 50 \
  --max-connections 1000 \
  --exec-timeout 30 \
  --scan-responses \
  --block-pii \
  --block-secrets \
  --block-xss \
  --block-prompt-inject \
  --ml \
  --health-addr :8082
```

**Production hardening checklist:**

- [ ] Use a high-entropy bearer token (≥ 32 random bytes, base64-encoded)
- [ ] Store the auth token in a secrets manager, not in a plaintext file
- [ ] Enable the audit log and forward to a centralized SIEM
- [ ] Configure log rotation for the audit log file
- [ ] Enable all response scanning block modes
- [ ] Load default policies (`LoadDefaultPolicies()`) at startup
- [ ] Add custom policy rules for site-specific time and parameter restrictions
- [ ] Enable signature verification for `privileged` and `admin` agents
- [ ] Configure Kubernetes liveness and readiness probes against `/healthz` and `/readyz`
- [ ] Set up a Prometheus scrape for `/stats`
- [ ] Restrict network access to the MCP server using firewall rules (security best practice)
- [ ] Run the server as a non-root user with minimal filesystem permissions
- [ ] Review denied tool calls in the audit log daily

---

*This document is the definitive reference for administering AegisGate MCP v1.4.2. For API and development documentation, refer to the Go package documentation and the project repository.*

*AegisGate MCP is a product of AegisGate Security, LLC. Licensed under Apache-2.0.*