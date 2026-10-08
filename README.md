# AegisGate MCP

**A security-first Model Context Protocol (MCP) server for AI agents in any environment.**

![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-success)
![Coverage](https://img.shields.io/badge/Coverage-92.3%25-brightgreen)
![Docker](https://img.shields.io/badge/Docker-DebianSlim-135MB-blue)
![ML](https://img.shields.io/badge/ML-CharCNN--BiLSTM_v13-purple)
![Arch](https://img.shields.io/badge/Arch-amd64%20%7C%20arm64-orange)

> **AegisGate Security™** is a trademark of AegisGate Security, LLC, filed with the USPTO.
> "AegisGate MCP" is an unregistered product name. See [Trademark](#trademark) below.

---

## Overview

AegisGate MCP is a hardened, zero-dependency MCP server written in pure Go.
It sits between AI agents and the tools they call, applying **21 layers of
defense** to every request — from authentication and RBAC to neural threat
detection and chain analysis.

Standard MCP servers assume a trusted local environment. In production —
whether that's a cloud SaaS platform, an enterprise data pipeline, or an
OT/ICS plant network — agents may execute commands, query databases, or
interact with critical systems. A single unauthorized or malicious tool call
can cause data exfiltration, process disruption, or worse. AegisGate MCP
wraps every tool call in defense-in-depth, all with zero external module
dependencies so it can run air-gapped.

| | |
|---|---|
| **Version** | 1.1.0 |
| **License** | Apache-2.0 |
| **Go version** | 1.26+ |
| **Module deps** | Zero (no `require` directives — all third-party code vendored) |
| **Docker image** | `debian:bookworm-slim`, ~135 MB (ML-enabled) or ~8 MB (heuristic-only) |
| **Architectures** | amd64, arm64 |
| **ML model** | CharCNN-BiLSTM v13, 1.6M params, <1ms CPU inference |
| **Tests** | 337+ tests, 10 benchmarks, 92.3% coverage (both CGO and non-CGO) |

---

## Quick Start

### Build

```bash
go build -o mcp-server ./cmd/mcp-server
```

### Run

```bash
# Basic TCP server on :8081
./mcp-server

# With authentication and audit logging
./mcp-server --token my-secret --audit /var/log/mcp-audit.json

# With demo tools (ping, system_info, echo)
./mcp-server --demo

# stdio mode for local MCP clients (Claude Desktop, Cursor)
./mcp-server --transport stdio --demo

# TLS + mutual TLS
./mcp-server --tls --tls-cert server.pem --tls-key server.key --tls-client-ca ca.pem

# Config file + health endpoint
./mcp-server --config /etc/mcp/config.json --health-addr :8082
```

### Docker

```bash
# Build and run (ML-enabled, ~135 MB)
docker build -t aegisgate-mcp .
docker run -p 8081:8081 aegisgate-mcp --demo

# With authentication and audit logging
docker run -p 8081:8081 \
  -e MCP_AUTH_TOKEN=your-secret-token \
  -e MCP_DEMO_TOOLS=true \
  aegisgate-mcp

# Heuristic-only build (no CGO, ~8 MB)
docker build --build-arg CGO_ENABLED=0 -t aegisgate-mcp:lite .
docker run -p 8081:8081 aegisgate-mcp:lite --demo
```

The default Docker image uses `debian:bookworm-slim` with CGO enabled,
including the vendored ONNX Runtime and CharCNN-BiLSTM v13 model for
full neural threat detection. A `--build-arg CGO_ENABLED=0` variant
produces a smaller heuristic-only image. Multi-arch builds support
both `linux/amd64` and `linux/arm64`.

### ML Threat Detection (L3)

AegisGate MCP includes the same CharCNN-BiLSTM v13 neural model used by
AegisGate Platform and Rampart — vendored with zero external module
dependencies. The model provides:

- **Semantic attack detection** — catches prompt injection and jailbreak
  attempts that bypass regex pattern matching
- **Evasion resistance** — detects obfuscation techniques (leetspeak,
  Unicode homoglyphs, character transposition, vowel deletion, word reversal)
- **Two-tier blocking** — scores ≥0.95 block independently; scores 0.50–0.94
  block only if L1 (regex) or L2 (input scanner) corroboration is present
- **Shadow mode** — log predictions without blocking (for calibration)
- **Heuristic fallback** — when CGO is unavailable, heuristic scoring
  provides baseline detection without ONNX

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--ml` | `MCP_ML_ENABLED` | `false` (CLI) / `true` (Docker) | Enable neural threat detection |
| `--ml-shadow` | `MCP_ML_SHADOW` | `false` | Log predictions but never block |
| `--ml-threshold` | `MCP_ML_THRESHOLD` | `0.50` | Threat score threshold (0.0–1.0) |
| `--ml-model` | `MCP_ML_MODEL` | `./models/threat_cnn_bilstm.onnx` | Path to ONNX model file |

### Library Usage

AegisGate MCP can be embedded as a Go library:

```go
package main

import (
    "context"
    "log"
    mcp "github.com/aegisgatesecurity/aegisgate-mcp"
)

func main() {
    cfg := mcp.DefaultServerConfig()
    cfg.AuthToken = "my-secret-token"
    cfg.AuditLogPath = "/var/log/mcp-audit.json"
    cfg.RateLimitRPM = 120
    cfg.ScanResponses = true

    server, err := mcp.NewSecuredMCPServer(cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Register a custom tool
    server.RegisterTool("my_tool", "Does something useful", 40, map[string]interface{}{
        "type": "object",
        "properties": map[string]interface{}{
            "param1": map[string]interface{}{"type": "string"},
        },
        "required": []interface{}{"param1"},
    })
    server.RegisterToolHandler("my_tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        return "result", nil
    })

    // Load built-in policy rules
    server.LoadDefaultPolicies()

    // Start the server
    if err := server.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
    defer server.Stop()
}
```

---

## Security Layers

AegisGate MCP applies 21 security layers to every request, in order:

| # | Layer | Description | Source |
|---|-------|-------------|--------|
| 1 | **Authentication** | Bearer token + API key, constant-time comparison, automatic lockout on repeated failures | `auth.go` |
| 2 | **Signature Verification** | ECDSA P-256 anti-forgery — verifies message signatures against trusted public keys | `auth.go` |
| 3 | **Session Management** | 256-bit cryptographically random session IDs, expiry, anti-hijacking checks | `session.go` |
| 4 | **RBAC** | 4-tier role hierarchy (restricted → standard → privileged → admin), per-tool permissions | `rbac.go` |
| 5 | **Policy Engine** | Allow/deny rules with conditions, priorities, time windows, and parameter patterns | `policy.go` |
| 6 | **Guardrails** | Per-session tool call limits and rate limiting | `guardrails.go` |
| 7 | **Chain Analysis** | Detects privilege escalation, data exfiltration chains, and repeated dangerous tool calls | `guardrails.go` |
| 8 | **Token Bucket Rate Limiting** | Sliding-window rate limiting with token bucket algorithm (RPM + burst capacity) | `guardrails.go` |
| 9 | **Input Scanning** | Scans tool *parameters* for prompt injection before execution (~30 patterns) | `handler.go`, `scanner.go` |
| 10 | **Response Scanning** | Scans tool *responses* for PII, secrets, XSS, and prompt injection (~30 detection patterns) | `scanner.go` |
| 11 | **Secret Redaction** | Scrubs sensitive data (PII, secrets) from responses before returning to the client | `scanner.go` |
| 12 | **Tool Execution Timeout** | Configurable per-call timeout prevents hanging or runaway tools | `handler.go` |
| 13 | **STDIO Validation** | Shell injection prevention via allowlist + blocklist for stdio transport commands | `stdio_guard.go` |
| 14 | **Audit Logging** | All MCP actions logged to file + in-memory, queryable for compliance, tamper-evident hash chain | `audit.go` |
| 15 | **TLS / mTLS Transport** | Encrypted TCP connections with optional mutual TLS | `config.go`, `server.go` |
| 16 | **stdio Transport** | Standard MCP client transport for Claude Desktop, Cursor, and other local integrations | `transport.go` |
| 17 | **Health Endpoint** | HTTP `/healthz`, `/readyz`, `/stats` endpoints on a separate listener | `transport.go` |
| 18 | **Parameter Validation** | Required fields checked against each tool's `inputSchema` before execution | `handler.go` |
| 19 | **Neural Threat Detection (L3)** | CharCNN-BiLSTM v13 model scores semantic attacks and evasion variants that regex misses. Two-tier blocking: ≥0.95 blocks independently, 0.50–0.94 requires L1/L2 corroboration | `internal/ml/` |
| 20 | **Heuristic Evasion Detection** | Detects transposition, vowel deletion, word reversal, leetspeak, encoding, splitting, and zero-width character obfuscation | `internal/ml/evasion_resistance.go` |
| 21 | **NFKC Unicode Normalization** | Maps Unicode compatibility characters to canonical forms before scanning — defeats homoglyph and ligature attacks (full-width `Ｉｇｎｏｒｅ` → `ignore`) | `internal/ml/normalizer.go` |

---

<details>
<summary><strong>⚙️ Configuration</strong></summary>

### Configuration Priority

Configuration is resolved in order of **highest to lowest priority**:

1. **CLI flags** — override everything
2. **Environment variables** — override config file
3. **JSON config file** (`--config`) — overrides built-in defaults
4. **Built-in defaults**

### CLI Flags

All CLI flags have environment variable equivalents:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `MCP_SERVER_ADDR` | `:8081` | Listen address (TCP mode) |
| `--transport` | `MCP_TRANSPORT` | `tcp` | Transport mode: `tcp` or `stdio` |
| `--token` | `MCP_AUTH_TOKEN` | _(empty)_ | Bearer token for authentication |
| `--audit` | `MCP_AUDIT_LOG` | _(empty)_ | Audit log file path |
| `--max-sessions` | `MCP_MAX_SESSIONS` | `50` | Max concurrent sessions |
| `--max-connections` | `MCP_MAX_CONNECTIONS` | `1000` | Max concurrent TCP connections (-1 = unlimited) |
| `--rate-limit` | `MCP_RATE_LIMIT_RPM` | `60` | Rate limit (requests/min) |
| `--exec-timeout` | `MCP_EXEC_TIMEOUT` | `30` | Tool execution timeout (seconds) |
| `--scan-responses` | `MCP_SCAN_RESPONSES` | `true` | Enable response scanning |
| `--block-pii` | `MCP_BLOCK_PII` | `true` | Block responses containing PII |
| `--block-secrets` | `MCP_BLOCK_SECRETS` | `true` | Block responses containing secrets |
| `--block-xss` | `MCP_BLOCK_XSS` | `true` | Block responses containing XSS |
| `--block-prompt-inject` | `MCP_BLOCK_PROMPT_INJECT` | `true` | Block responses containing prompt injection |
| `--redact` | `MCP_REDACT_ENABLED` | `false` | Enable secret/PII redaction |
| `--redact-pii` | `MCP_REDACT_PII` | `false` | Redact PII from responses |
| `--redact-secrets` | `MCP_REDACT_SECRETS` | `true` | Redact secrets from responses |
| `--redact-placeholder` | `MCP_REDACT_PLACEHOLDER` | `[REDACTED]` | Redaction placeholder text |
| `--tls` | `MCP_TLS_ENABLED` | `false` | Enable TLS transport |
| `--tls-cert` | `MCP_TLS_CERT` | _(empty)_ | Server certificate file (PEM) |
| `--tls-key` | `MCP_TLS_KEY` | _(empty)_ | Server private key file (PEM) |
| `--tls-client-ca` | `MCP_TLS_CLIENT_CA` | _(empty)_ | CA bundle for client certs (enables mTLS) |
| `--tls-min-version` | `MCP_TLS_MIN_VERSION` | `1.2` | Minimum TLS version: `1.2` or `1.3` |
| `--health-addr` | `MCP_HEALTH_ADDR` | _(empty)_ | Health endpoint listen address (empty = disabled) |
| `--config` | `MCP_CONFIG_FILE` | _(empty)_ | JSON config file path |
| `--demo` | `MCP_DEMO_TOOLS` | `false` | Register demo tools (ping, system_info, echo) |
| `--ml` | `MCP_ML_ENABLED` | `false` | Enable neural threat detection (L3, requires CGO build) |
| `--ml-shadow` | `MCP_ML_SHADOW` | `false` | ML shadow mode: log predictions but never block |
| `--ml-threshold` | `MCP_ML_THRESHOLD` | `0.50` | ML threat score threshold (0.0–1.0) |
| `--ml-model` | `MCP_ML_MODEL` | `./models/threat_cnn_bilstm.onnx` | Path to ONNX model file |

### JSON Config File

```json
{
  "address": ":8081",
  "auth_token": "my-secret-token",
  "audit_log_path": "/var/log/mcp-audit.json",
  "max_sessions": 100,
  "max_connections": 1000,
  "rate_limit_rpm": 120,
  "exec_timeout_seconds": 30,
  "scan_responses": true,
  "block_on_pii": true,
  "block_on_secrets": true,
  "block_on_xss": true,
  "block_on_prompt_inject": true,
  "redact_enabled": true,
  "redact_pii": true,
  "redact_secrets": true,
  "redact_placeholder": "[REDACTED]",
  "tls_enabled": true,
  "tls_cert_file": "/etc/ssl/mcp/server.pem",
  "tls_key_file": "/etc/ssl/mcp/server.key",
  "tls_client_ca_file": "/etc/ssl/mcp/ca.pem",
  "tls_min_version": "1.3",
  "demo_tools": true
}
```

### Transport Modes

| Mode | Flag | Description |
|------|------|-------------|
| `tcp` | `--transport tcp` (default) | TCP listener, supports TLS/mTLS encryption for network deployments |
| `stdio` | `--transport stdio` | Standard MCP stdin/stdout transport for local clients (Claude Desktop, Cursor) |

### Health Endpoints

When `--health-addr` is set, a separate HTTP listener provides observability endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | `GET` | Liveness probe — returns `200 OK` if the server process is running |
| `/readyz` | `GET` | Readiness probe — returns `200 OK` if the server is ready to accept requests |
| `/stats` | `GET` | Server statistics as JSON (sessions, rate limits, tool calls, `active_connections`, `max_connections`) |

</details>

---

<details>
<summary><strong>🔐 RBAC & Policy Engine</strong></summary>

## RBAC Roles

AegisGate MCP enforces a 4-tier role hierarchy. Roles are ordered: `restricted < standard < privileged < admin`.

| Role | Level | Access | Example Tools |
|------|-------|--------|---------------|
| `restricted` | 0 | Read-only tools only | `ping`, `system_info`, `file_exists`, `git_status`, `git_log` |
| `standard` | 1 | Read + low-risk write | `file_read`, `code_search`, `web_search`, `file_copy` |
| `privileged` | 2 | Everything except high-risk execution | All tools except `shell_command`, `code_execute` |
| `admin` | 3 | All tools, no restrictions | All registered tools |

Role comparison uses `AgentRole.AtLeast()` — a `privileged` agent can access any tool that requires `standard` or `restricted`, but not tools that require `admin`.

## Policy Engine

The Policy Engine evaluates allow/deny rules before any tool executes. Rules support:

- **Tool name matching** — exact names and wildcard patterns
- **Agent role conditions** — apply rules only to specific roles
- **Risk score thresholds** — trigger on `RiskAbove` values
- **Priorities** — higher-priority rules evaluated first
- **Time windows** — restrict tools to specific time ranges
- **Parameter patterns** — match against tool call parameters
- **Actions** — allow, deny (with reason), log level, risk modifiers

### Built-in Policy Rules

Loaded via `LoadDefaultPolicies()`:

| Rule ID | Priority | Action | Condition | Description |
|---------|----------|--------|-----------|-------------|
| `block-shell-commands` | 100 | **Deny** | Tool names: `shell_command`, `bash`, `exec`, `cmd`, `terminal`; Roles: restricted, standard, privileged | Shell commands require admin role |
| `block-file-delete` | 90 | **Deny** | Tool names: `file_delete`, `rm`, `unlink`, `remove`; Roles: restricted, standard | File deletion requires privileged or admin role |
| `block-network-write` | 80 | **Deny** | Tool names: `http_request`, `web_search`, `fetch_url`, `curl`, `wget`; Roles: restricted | Network operations not allowed for restricted agents |
| `alert-high-risk` | 50 | **Allow + Alert** | Risk score > 70 | Flags high-risk operations for audit logging |

Custom rules can be added programmatically:

```go
server.AddPolicyRule(mcp.PolicyRule{
    ID:          "block-after-hours",
    Name:        "Block Dangerous Tools After Hours",
    Description: "No high-risk tools outside business hours",
    Condition: mcp.RuleCondition{
        ToolNames: []string{"shell_command", "file_delete"},
        TimeWindow: &mcp.TimeWindow{
            Start: "08:00",
            End:   "18:00",
        },
    },
    Action: mcp.RuleAction{
        Allow:      false,
        DenyReason: "High-risk tools only available during business hours",
        LogLevel:   "warn",
    },
    Priority: 75,
    Enabled:   true,
})
```

## Chain Analysis

The Chain Analyzer tracks sequences of tool calls within a session (rolling window of 20 calls) and flags suspicious patterns:

| Detection | Flag | Trigger |
|-----------|------|---------|
| **Privilege Escalation** | `privilege_escalation` | Low-risk tool call followed by a high-risk tool (`shell_command`, `file_delete`, `db_query`) |
| **Data Exfiltration** | `data_exfiltration_chain` | Read of sensitive data (`file_read`, `db_query`, `code_search`) followed by an external write (`http_request`, `file_write`, `web_search`) |
| **Repeated Dangerous Tools** | `repeated_dangerous_tools` | 3+ high-risk tool calls within the analysis window |

When any flag is raised, the chain risk is set to **High** and the event is logged at `WARN` level with the session ID, flags, and call count.

</details>

---

<details>
<summary><strong>✍️ Signature Verification</strong></summary>

AegisGate MCP supports ECDSA P-256 message signing to prevent request forgery and tampering.
Clients sign the canonical JSON of each request (with `Signature` and `KeyID` fields zeroed out)
and include the signature in the request header.

### Server Setup

```go
server, _ := mcp.NewSecuredMCPServer(cfg)

// Register a trusted client public key (SEC1 encoded)
server.AddTrustedKey("agent-001", clientPubKeySEC1)
```

### Client Signing (example)

```go
import (
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/rand"
    "encoding/hex"
)

func signRequest(privKey *ecdsa.PrivateKey, canonicalJSON []byte) string {
    hash := sha256.Sum256(canonicalJSON)
    sig, _ := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
    return hex.EncodeToString(sig)
}
```

The server verifies the signature using `ecdsa.VerifyASN1` against the trusted public key.
If no `KeyID` or `Signature` is present, verification is skipped — allowing interoperability
with unsigned clients while enforcing signatures for clients that provide them.

</details>

---

<details>
<summary><strong>🧪 Testing & Performance</strong></summary>

## Test Coverage

| Category | Tests | Coverage |
|----------|-------|----------|
| Unit + integration (non-CGO) | 337 | 92.3% |
| Unit + integration (CGO + ML) | 341 | 93.1% |
| Load / break / soak (build tag: `load`) | 10 | — |
| Benchmarks | 10 | — |

### Running Tests

```bash
# Non-CGO test suite (heuristic-only, no ONNX)
CGO_ENABLED=0 go test ./... -count=1 -timeout 120s

# CGO test suite (full ML, requires libonnxruntime.so)
CGO_ENABLED=1 CGO_LDFLAGS="-L$(pwd)/lib/amd64 -lonnxruntime" go test ./... -count=1 -timeout 120s

# With race detector (CGO only — -race requires CGO)
CGO_ENABLED=1 CGO_LDFLAGS="-L$(pwd)/lib/amd64 -lonnxruntime" go test -race -count=1 -timeout 180s ./...

# Load/break/soak tests (behind build tag)
go test -tags=load -count=1 -timeout 120s -v ./...

# Benchmarks (regression tracking)
go test -bench=. -benchmem -benchtime=5s ./...

# Fuzz testing (run for 60 seconds per target)
go test -fuzz=FuzzHandleRequest -fuzztime=60s ./...
```

### Performance Characteristics

Validated via the load test suite (`//go:build load`):

| Metric | Value | Test |
|--------|-------|------|
| Sustained throughput | 14,427 req/sec | `TestLoadSustainedThroughput` |
| p50 latency (100 concurrent) | 34 ms | `TestLoadConcurrentConnections` |
| p99 latency (100 concurrent) | 46 ms | `TestLoadConcurrentConnections` |
| Connection churn rate | 2,662 conn/sec | `TestConnectionChurn` |
| Goroutine leaks (10s soak) | 0 | `TestSoakStability` |
| Graceful shutdown under load | 1.6 ms | `TestShutdownUnderLoad` |

</details>

---

<details>
<summary><strong>📦 Zero Module Dependencies</strong></summary>

AegisGate MCP has **zero external module dependencies**. The `go.mod` file contains
no `require` directives. All third-party code (ONNX Runtime bindings, Unicode
normalization, ML model) is vendored into `internal/`, `lib/`, and `models/`.

```
module github.com/aegisgatesecurity/aegisgate-mcp

go 1.26.6

// Zero external module dependencies (no `require` directives).
// All third-party code is vendored into internal/ — see NOTICE for details.
```

**Vendored components** (see `NOTICE` for full attribution):

| Component | License | Location |
|-----------|---------|----------|
| onnxruntime_go (Go bindings) | MIT | `internal/onnxruntime_go/` |
| libonnxruntime.so (Microsoft) | MIT | `lib/amd64/`, `lib/arm64/` |
| golang.org/x/text (Unicode norm) | BSD-3-Clause | `internal/textnorm/` |
| CharCNN-BiLSTM v13 model | Apache-2.0 | `models/` |

**Why this matters:**

- **Air-gapped deployment** — no `go mod download` needed, no supply chain risk
- **No transitive dependencies** — nothing to audit beyond vendored code
- **Reproducible builds** — the binary is identical across builds
- **Minimal attack surface** — all third-party code is visible and auditable
- **Fast compilation** — no dependency resolution overhead

</details>

---

<details>
<summary><strong>🏗️ Architecture & Protocol</strong></summary>

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AegisGate MCP Server                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  TCP Mode:                                                              │
│  ┌──────────┐    ┌──────────────┐    ┌───────────┐    ┌──────────────┐  │
│  │ TCP      │───▶│ Auth         │───▶│ Guardrails│───▶│ Response     │  │
│  │ Client   │    │ Middleware   │    │ (Rate +   │    │ Scan         │  │
│  │          │    │ (Token +     │    │  Chain)   │    │ (PII/Secrets │  │
│  │ (TLS/    │    │  Signature + │    │           │    │  /XSS/Inject)│  │
│  │  mTLS)   │    │  Session)    │    │           │    │              │  │
│  └──────────┘    └──────────────┘    └───────────┘    └──────┬───────┘  │
│                                                             │          │
│                                                             ▼          │
│  stdio Mode:                                    ┌──────────────────────┐ │
│  ┌──────────┐    (same security chain,          │   Request Handler    │ │
│  │ stdin /  │     stdin/stdout instead          │  ┌────────────────┐  │ │
│  │ stdout   │     of TCP)                      │  │  RBAC Check    │  │ │
│  └──────────┘                                  │  ├────────────────┤  │ │
│                                                 │  │  Policy Engine │  │ │
│                                                 │  ├────────────────┤  │ │
│                                                 │  │  Param Validate│  │ │
│                                                 │  ├────────────────┤  │ │
│                                                 │  │  Tool Registry │  │ │
│                                                 │  │  + Exec Timeout│  │ │
│                                                 │  └────────────────┘  │ │
│                                                 └──────────────────────┘ │
│                                                                         │
│  Health Endpoint (separate HTTP listener):                              │
│  ┌────────────────────────────────────────┐                             │
│  │  GET /healthz  → liveness              │                             │
│  │  GET /readyz   → readiness             │                             │
│  │  GET /stats    → server statistics     │                             │
│  └────────────────────────────────────────┘                             │
│                                                                         │
│  Audit Log: all MCP actions → file + in-memory (queryable)              │
└─────────────────────────────────────────────────────────────────────────┘
```

**Request flow:**

1. **TCP Client** connects (optionally over TLS/mTLS) or **stdio** sends JSON-RPC via stdin
2. **Auth Middleware** validates bearer token/API key (constant-time), verifies ECDSA signature, creates/validates session
3. **Guardrails** enforce rate limits, session limits, and run chain analysis
4. **Response Scan** (pre-execution parameter validation happens in handler)
5. **Request Handler** checks RBAC permissions, evaluates Policy Engine rules, validates required parameters against `inputSchema`, executes tool with timeout
6. **Response Scan** (post-execution) scans tool output for PII, secrets, XSS, prompt injection; redacts if enabled
7. **Audit Log** records the complete action chain

## MCP Protocol Support

AegisGate MCP implements the following JSON-RPC methods:

| Method | Type | Description |
|--------|------|-------------|
| `initialize` | Request | Parses `clientInfo`, returns `serverInfo` + server capabilities |
| `notifications/initialized` | Notification | Handled silently — no response sent (per MCP spec) |
| `tools/list` | Request | Returns all registered tools with descriptions and `inputSchema` |
| `tools/call` | Request | Executes a tool after passing all security layers |
| `ping` | Request | Health check — returns empty success response |

</details>

---

<details>
<summary><strong>🏭 Use Cases & Deployment Scenarios</strong></summary>

AegisGate MCP serves any environment where AI agents interact with tools — from cloud
SaaS platforms to enterprise data pipelines to OT/ICS plant networks. The same 21
security layers apply regardless of deployment context.

### General Deployments

- **Cloud SaaS** — protect user-facing AI features from prompt injection and data exfiltration
- **Enterprise data access** — enforce RBAC and audit logging on agent-driven database queries
- **CI/CD automation** — restrict what AI-assisted pipelines can execute
- **Air-gapped networks** — zero dependencies means the server runs with no internet access

### OT/ICS Environments

In an OT/ICS environment, AegisGate MCP sits between AI agents and critical infrastructure tools:

```
AI Agent (Claude, Cursor, custom)
    │
    ▼
┌──────────────────┐
│  AegisGate MCP   │  ← 21 security layers
│  (TLS/mTLS)      │
└────────┬─────────┘
         │
    ┌────┼────┬────┬────┐
    ▼    ▼    ▼    ▼    ▼
  SCADA  PLC  Hist  Tag  Log
  Read  Status Query DB  Analyzer
```

**Typical deployment scenarios:**

- **Read-only monitoring agent** — `restricted` role, can query SCADA status and historian data but cannot issue commands
- **Maintenance agent** — `standard` role, can read files and search code during troubleshooting
- **Operations agent** — `privileged` role, can interact with most tools but cannot execute shell commands
- **Admin agent** — `admin` role, full access for authorized maintenance windows

**Security features particularly relevant to OT/ICS:**

- **TLS/mTLS** encrypts all traffic on the plant network
- **Time-window policies** restrict high-risk tools to maintenance windows
- **Chain analysis** detects if an agent reads sensitive process data then attempts an external network write (exfiltration)
- **Audit logging** provides a complete chain of custody for compliance (NERC CIP, IEC 62443)
- **Air-gapped operation** — zero dependencies means the server can be deployed on isolated networks with no internet access

</details>

---

## Demo Tools

Enable demo tools with the `--demo` flag or by calling `RegisterDemoTools()` in library mode.
These are safe, read-only tools that do not access the filesystem, network, or any external resources.

| Tool | Risk Level | Required Params | Description |
|------|-----------|-----------------|-------------|
| `ping` | 10 | _(none)_ | Returns `"pong"` — health check tool |
| `system_info` | 30 | _(none)_ | Returns Go version, OS, arch, CPU count, goroutine count, timestamp |
| `echo` | 20 | `message` (string) | Echoes back the provided message |

**Example — `system_info` response:**

```json
{
  "go_version": "go1.26.6",
  "os": "linux",
  "arch": "amd64",
  "cpus": 8,
  "goroutines": 12,
  "timestamp": "2026-10-08T08:58:00Z"
}
```

---

## Documentation

Detailed documentation is available in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [`docs/getting-started.md`](docs/getting-started.md) | Installation, first run, and basic configuration |
| [`docs/deployment-guide.md`](docs/deployment-guide.md) | Production deployment: Docker, TLS, air-gapped setups |
| [`docs/admin-guide.md`](docs/admin-guide.md) | Administration: sessions, audit logs, RBAC management, policies |
| [`docs/how-to-guides.md`](docs/how-to-guides.md) | Task-specific guides: custom tools, signature verification, mTLS setup |

---

## When to Upgrade to AegisGate Platform

AegisGate MCP is a standalone secure MCP server framework — perfect for building
and running MCP servers with security built in. It's free, open source, and has
zero external dependencies.

When your needs grow beyond a single server, **[AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform)**
is the natural upgrade path:

| Need | AegisGate MCP (free) | AegisGate Platform |
|---|---|---|
| Secure MCP server framework | ✅ 21 layers, zero deps | ✅ Embedded MCP server |
| ML threat detection | ✅ Capped at 100 inf/min (single-server) | ✅ Unlimited, org-wide |
| Proxy/gateway mode | ❌ Framework, not proxy | ✅ Sits between clients and all AI services |
| OAuth 2.0 / OIDC / SSO | ❌ Bearer tokens + API keys | ✅ SAML, OIDC, JWT |
| SIEM integration | ❌ File-based audit + Prometheus | ✅ Splunk, Elasticsearch, QRadar, Datadog (11 platforms) |
| Compliance frameworks | ❌ None | ✅ 31 frameworks (HIPAA, PCI, SOC 2, EU AI Act, NIST, etc.) |
| Multi-protocol (HTTP, A2A, ACP) | ❌ MCP only | ✅ 6 pillars |
| Enterprise scale | ⚠️ 250 connections, 25 sessions | ✅ Unlimited |

**Think of it this way:** AegisGate MCP is the secure foundation you build MCP
servers on. AegisGate Platform is the enterprise gateway that secures all AI
traffic across your organization — including MCP, HTTP, A2A, and ACP.

> **Other AegisGate products:**
> - **[AegisGate Rampart](https://github.com/aegisgatesecurity/aegisgate-rampart)** — Free local proxy for developers using Claude, Cursor, or Copilot
> - **[AegisGate Lens](https://github.com/aegisgatesecurity/aegisgate-lens)** — Free browser extension for everyday AI conversations

---

## License

Licensed under the **Apache License, Version 2.0**.

```
Copyright 2024-2026 AegisGate Security, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

See the [LICENSE](LICENSE) file for the full license text and [NOTICE](NOTICE) for attribution.

---

## Trademark

**AegisGate Security™** is a trademark of AegisGate Security, LLC, filed with the
United States Patent and Trademark Office (USPTO). The mark was published for
opposition on October 13, 2026.

**AegisGate MCP** is an unregistered product name of AegisGate Security, LLC.
The ™ symbol is not used for this product name, as it has not been separately
filed as a trademark application. Use of the "AegisGate Security" mark is
governed by the Lanham Act (15 U.S.C. § 1126) and applicable state trademark
law.

Permission is granted to use the AegisGate name and marks in connection with
the unmodified open-source software distribution as published on GitHub. Use
of the AegisGate name, logo, or other brand assets in derivative works,
commercial products, service offerings, or marketing materials requires prior
written permission from AegisGate Security, LLC.

Contact: legal@aegisgatesecurity.io