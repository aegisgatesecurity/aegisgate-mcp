# OWASP MCP Top 10 — AegisGate MCP Coverage

> The OWASP MCP Top 10 identifies the most critical security risks for
> Model Context Protocol (MCP) implementations. This document maps each
> risk to the specific defenses provided by AegisGate MCP.

## Summary

| # | OWASP MCP Risk | AegisGate MCP Coverage | Status |
|---|----------------|----------------------|--------|
| M1 | Tool Poisoning | Tool Poisoning Scanner (registration-time) | ✅ Full |
| M2 | Identity Spoofing / Auth Bypass | Bearer token + API key + constant-time + lockout | ✅ Full |
| M3 | Insecure Session Management | 256-bit random session IDs + expiry + anti-hijacking | ✅ Full |
| M4 | Excessive Autonomy / Privilege | 4-tier RBAC + Policy Engine + Chain Analysis | ✅ Full |
| M5 | Data Exfiltration | Response scanning + chain analysis + secret redaction | ✅ Full |
| M6 | Prompt Injection | 30 regex patterns + CharCNN-BiLSTM ML + input scanning | ✅ Full |
| M7 | Insecure Transport | TLS + mTLS support | ✅ Full |
| M8 | Missing Audit & Monitoring | Tamper-evident hash-chain audit log + health endpoints | ✅ Full |
| M9 | Supply Chain Risk | Zero external module dependencies (all vendored) | ✅ Full |
| M10 | DoS / Resource Exhaustion | Rate limiting + session limits + exec timeout + 1MB body cap | ✅ Full |

---

## Detailed Mapping

### M1: Tool Poisoning

**Risk:** Malicious tools embed prompt injection in their descriptions or
input schemas, tricking the LLM into executing unintended actions or
exfiltrating data.

**AegisGate Defense:**
- **Tool Poisoning Scanner** (`handler.go`) — scans every tool description
  and recursively scans `inputSchema` strings (description, enum, default
  fields) at registration time, before the tool is ever callable
- Uses the existing ContentScanner with 30 regex patterns to detect
  injection, exfiltration, and system-override attempts
- Returns `*ToolPoisoningError` with tool name, reason, and matched patterns
- `SecuredMCPServer.RegisterTool()` automatically applies scanning
- `SecuredMCPServer.ScanToolForPoisoning()` allows on-demand scanning

```go
// Automatic scanning at registration:
err := server.RegisterTool("my_tool", "Does something safe", 10, schema)
if err != nil {
    // err is *ToolPoisoningError if poisoning detected
    log.Fatal(err) // tool is NOT registered
}
```

### M2: Identity Spoofing / Authentication Bypass

**Risk:** Attackers forge credentials or bypass authentication to access
MCP servers.

**AegisGate Defense:**
- **Bearer token authentication** with constant-time comparison
  (`crypto/subtle.ConstantTimeCompare`) — prevents timing attacks
- **API key authentication** as alternative credential type
- **Automatic lockout** — configurable failed-attempt threshold with
  exponential backoff
- **ECDSA P-256 signature verification** — optional per-request signing
  with trusted public keys prevents message tampering
- Auth is enforced before any tool execution — no bypass paths

### M3: Insecure Session Management

**Risk:** Predictable session IDs, missing expiry, or session hijacking.

**AegisGate Defense:**
- **256-bit cryptographically random session IDs** — `crypto/rand`
- **Session expiry** — configurable TTL, expired sessions automatically cleaned
- **Anti-hijacking checks** — session IP and client fingerprint validation
- **Session limits** — configurable max concurrent sessions (default 50)
- Sessions tracked with `LastSeen` timestamps for liveness detection

### M4: Excessive Autonomy / Privilege Escalation

**Risk:** AI agents execute tools beyond their authorized scope, escalate
privileges, or chain calls to achieve unauthorized actions.

**AegisGate Defense:**
- **4-tier RBAC** — `restricted → standard → privileged → admin` hierarchy
  with per-tool role requirements
- **Policy Engine** — allow/deny rules with conditions: tool names, roles,
  risk scores, time windows, parameter patterns
- **Chain Analysis** — rolling window of 20 tool calls per session detects:
  - Privilege escalation (low-risk → high-risk transitions)
  - Data exfiltration chains (read sensitive → write external)
  - Repeated dangerous tool calls (3+ high-risk in window)
- **Per-tool risk scores** — tools tagged with risk levels (0-100)

### M5: Data Exfiltration

**Risk:** Sensitive data (PII, secrets, credentials) leaked through tool
responses.

**AegisGate Defense:**
- **Response scanning** — scans tool output for:
  - PII (email, phone, SSN, credit cards)
  - Secrets (API keys, tokens, private keys)
  - XSS payloads
  - Prompt injection in responses
- **Secret redaction** — configurable redaction replaces sensitive data
  with `[REDACTED]` before returning to client
- **Chain analysis** — flags read-sensitive → write-external patterns
  as `data_exfiltration_chain`
- **Configurable blocking** — per-category block/allow decisions

### M6: Prompt Injection

**Risk:** Malicious prompts embedded in tool parameters, resources, or
external data cause the LLM to execute unintended actions.

**AegisGate Defense:**
- **L1: Regex Pattern Matching** — 30 patterns detect known injection
  templates, jailbreak attempts, and override commands
- **L2: ATLAS Compliance Scanner** — input scanner with severity scoring
  (Low/Medium/High/Critical)
- **L3: Neural ML Detection** — CharCNN-BiLSTM v13 model (1.6M params,
  <1ms CPU inference) catches semantic attacks and evasion variants that
  regex misses:
  - Leetspeak, Unicode homoglyphs, character transposition
  - Vowel deletion, word reversal, encoding tricks
  - Zero-width character obfuscation
- **Two-tier blocking** — scores ≥0.95 block independently; scores
  0.50–0.94 require L1/L2 corroboration (prevents false positives)
- **NFKC Unicode Normalization** — defeats full-width and homoglyph attacks
  before scanning
- **Input parameter scanning** — scans tool *parameters* (not just
  descriptions) before execution

### M7: Insecure Transport

**Risk:** Unencrypted MCP traffic intercepted or modified.

**AegisGate Defense:**
- **TLS encryption** — configurable TLS 1.2/1.3 for TCP transport
- **Mutual TLS (mTLS)** — optional client certificate verification via
  CA bundle
- **Streamable HTTP** — MCP 2025-06-18 transport over HTTP (compatible
  with TLS-terminating reverse proxies)
- All transport modes (TCP, stdio, HTTP) pass through the same security
  chain — no mode is less protected

### M8: Missing Audit & Monitoring

**Risk:** No record of tool calls, security events, or system state for
incident response and compliance.

**AegisGate Defense:**
- **Tamper-evident audit log** — SHA-256 hash chain links consecutive
  entries, making post-hoc modification detectable
- **Dual logging** — file-based (`--audit`) and in-memory (queryable)
- **Comprehensive event types** — initialize, tool calls, auth events,
  policy decisions, chain analysis flags, ML predictions
- **Health endpoints** — `/healthz` (liveness), `/readyz` (readiness),
  `/stats` (real-time metrics: sessions, connections, tool calls)
- **Structured logging** — `slog` (Go 1.21+ structured logger) with
  JSON output for SIEM ingestion

### M9: Supply Chain Risk

**Risk:** Dependencies in the MCP server's dependency tree contain
vulnerabilities or malicious code.

**AegisGate Defense:**
- **Zero external module dependencies** — `go.mod` has zero `require`
  directives
- **All third-party code vendored** — ONNX Runtime bindings, Unicode
  normalization library, and ML model are all in `internal/`, `lib/`,
  and `models/`
- **Air-gapped deployment** — no `go mod download` needed, runs fully
  offline
- **Reproducible builds** — no dependency resolution means identical
  binaries across builds
- **Auditable surface** — all third-party code is visible in the repo,
  no transitive dependencies to chase

### M10: DoS / Resource Exhaustion

**Risk:** Attackers overwhelm the server with requests, exhaust sessions,
or trigger long-running tools.

**AegisGate Defense:**
- **Token bucket rate limiting** — configurable RPM + burst capacity
  (default 60 RPM)
- **Session limits** — max concurrent sessions (default 50)
- **Connection limits** — max TCP connections (default 1000, -1 = unlimited)
- **Tool execution timeout** — configurable per-call timeout (default 30s)
- **HTTP body size cap** — Streamable HTTP limits request bodies to 1MB
- **ML inference throttle** — 100 inferences/min, 10 burst/sec, 4 concurrent
  (prevents ML from becoming a DoS vector)
- **Read/write timeouts** — HTTP transport enforces 10s read header,
  30s read, 60s write, 5min idle timeouts