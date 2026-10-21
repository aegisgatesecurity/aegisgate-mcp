<!-- SPDX-License-Identifier: Apache-2.0 -->

# AegisGate MCP v1.6.1 — Threat Model

**Status:** v1.6.1 (all findings triaged; 24 mitigated, 2 residual, 1 accepted)  
**Date:** 2026-10-21  
**Audience:** Enterprise security buyers, SBIR reviewers, third-party auditors, design partners, security researchers  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Coverage:** Full MCP server architecture (23 security layers, 5 protocol methods, 2 deployment modes, ML detection)

This is the **public, product-level** threat model for AegisGate MCP. It covers the server's architecture, trust boundaries, and security controls. A more detailed package-by-package STRIDE analysis with test references is available internally.

---

## Purpose

This document catalogs threats to AegisGate MCP itself (distinct from threats the MCP server *detects* in AI traffic). The goal: enumerate realistic attack vectors, document current mitigations, and call out residual risks so an enterprise buyer, SBIR reviewer, or security auditor can independently verify the security posture.

**Key distinction:** This threat model covers *attacks on AegisGate MCP*, not *attacks detected by AegisGate MCP*. For the latter, see [`docs/owasp-mcp-top-10.md`](owasp-mcp-top-10.md) for the OWASP MCP Top 10 coverage map.

---

## Scope

### In-Scope

- **MCP server codebase** — Go server, JSON-RPC handler, transport layer (STDIO + HTTP+SSE), connection management
- **Authentication** — Bearer token, API key, constant-time comparison, brute-force lockout, ECDSA P-256 signature verification
- **Authorization** — 4-tier RBAC (admin, write, read, deny) with per-tool permissions
- **Session management** — 256-bit random session IDs, expiry, anti-hijacking, MaxSessions limit
- **Content scanning** — L1 regex (79 patterns), L2 MITRE ATLAS compliance, L3 CharCNN-BiLSTM v15 neural detection
- **Tool poisoning scanner** — Registration-time screening of tool descriptions and inputSchema (34 dangerous function patterns)
- **Chain analysis** — Multi-turn attack detection (EscalationChain, ExfilChain, ReconChain)
- **Guardrails** — Tool restrictions, exec timeout, MaxToolsPerSession, MaxCallsPerToolPerSession
- **Rate limiting** — Per-session RPM, per-tool overrides
- **Audit logging** — Tamper-evident SHA-256 hash chain, configurable retention
- **Platform forwarding** — Optional forwarding of events to AegisGate Platform
- **Deployment modes** — Standalone binary (default), Docker (ML: debian:bookworm-slim, Lite: distroless), air-gapped
- **Supply chain** — Zero external Go module dependencies (all vendored), ONNX model hash verification, Docker base images

### Out-of-Scope (Covered Elsewhere)

- **AegisGate Platform** — See [Platform THREAT-MODEL.md](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/docs/THREAT-MODEL.md)
- **AegisGate Rampart** — See [Rampart THREAT-MODEL.md](https://github.com/aegisgatesecurity/aegisgate-rampart/blob/main/THREAT-MODEL.md)
- **AegisGate Lens** — See [Lens THREAT-MODEL.md](https://github.com/aegisgatesecurity/aegisgate-lens/blob/main/docs/THREAT-MODEL.md)
- **MCP protocol specification** — The MCP protocol is defined by Anthropic; AegisGate MCP implements it securely
- **Client applications** (AI agents, IDE extensions) — Outside trust boundary
- **Operating system / kernel** — Assumed trusted (if compromised, game over)
- **Network infrastructure** — Server assumes hostile network (zero-trust design)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      AEGISGATE MCP SERVER                           │
│                                                                     │
│  ┌──────────────┐  ┌────────────────────────────────────────────┐  │
│  │ Transport    │  │         Security Pipeline (23 Layers)      │  │
│  │ - STDIO      │──│                                            │  │
│  │ - HTTP+SSE   │  │  Auth → RBAC → Rate Limit → Session       │  │
│  │ - TLS/mTLS   │  │    → Content Scan (L1→L2→L3)              │  │
│  └──────────────┘  │    → Chain Analysis → Guardrails           │  │
│                    │    → Tool Exec → Response Scan              │  │
│                    └────────────────────────────────────────────┘  │
│                                         │                           │
│                    ┌────────────────────┼────────────────────┐     │
│                    ▼                    ▼                    ▼     │
│            ┌──────────────┐    ┌──────────────┐    ┌──────────────┐│
│            │ Audit Log    │    │  Tool Exec   │    │ Platform     ││
│            │ (hash chain) │    │  (sandboxed) │    │ Forwarder    ││
│            └──────────────┘    └──────────────┘    └──────────────┘│
└─────────────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
    ┌──────────────┐              ┌──────────────┐
    │  MCP Client  │              │ AI Provider  │
    │  (AI Agent)  │              │ (upstream)   │
    └──────────────┘              └──────────────┘
```

---

## Trust Boundaries

| Boundary | Description | Enforcement |
|----------|-------------|-------------|
| **Client → MCP Server** | Untrusted zone. All client input is hostile until validated. | Bearer token/API key auth, JSON-RPC schema validation, 1MB body cap |
| **MCP Server → Tool** | Semi-trusted. Tools execute on the host system. | Exec timeout, tool restrictions (guardrails), per-tool rate limits, MaxCallsPerToolPerSession |
| **MCP Server → Platform** | Semi-trusted. Optional forwarding to AegisGate Platform. | TLS, configurable endpoint, disabled by default |
| **Admin → MCP Server** | Trusted but authenticated. Admin operations require RBAC. | Bearer token with admin role, audit logging of all admin actions |
| **ML Model → Runtime** | Trusted but verified. Model file must match expected hash. | SHA-256 hash verification on load (v15: `99187453...`) |

---

## Assets Protected

| Asset | Sensitivity | Why |
|-------|-------------|-----|
| **Audit log** | Critical | Forensic evidence, compliance, incident response. Tamper-evident via SHA-256 hash chain. |
| **ONNX model file** | High | Core IP (~1.6M params), supply chain attack vector |
| **Auth tokens / API keys** | Critical | Full server control if compromised |
| **Session state** | Medium | DoS target, could be used to bypass multi-turn detection |
| **Tool registry** | High | Malicious tool registration enables attack execution |
| **Configuration** | High | Security policy (RBAC roles, rate limits, enabled detectors) |
| **Rate limit state** | Low | Performance optimization; tampering causes over/under-limiting |

---

## Score

| Dimension | Score | What it means |
|-----------|-------|---------------|
| **Engineering posture** (code, tests, validation) | 9.5/10 | 92.0% test coverage (non-CGO), 611 unit/integration tests + 32 load/stress tests, 3 fuzz targets. Zero external module dependencies — entire supply chain is Go stdlib + vendored code. 0.5 deduction for residual session fixation risk in chain analyzer. |
| **Trust posture** (supply chain, deployment, ops) | 9.7/10 | Zero Go module dependencies (no `require` directives), ONNX hash verification, distroless Docker option (0 CVEs), gnutls purged in ML image. 0.3 deduction for not yet independently audited by third party. |
| **Validation rigor** (evasion tests, load tests) | 9.3/10 | 100/100 evasion resistance (full pipeline), OWASP MCP Top 10 full coverage (M1–M10), 32 load/stress tests. 0.7 deduction for production traffic validation still pending (shadow mode not yet deployed at scale for MCP-specific traffic patterns). |
| **Combined** | **9.5/10** | Weighted by exposure. Strongest posture is supply chain (zero deps). Weakest is production-scale validation (MCP-specific traffic patterns not yet validated at 8M+ request scale like Platform). |

---

## Findings (STRIDE)

Status legend: **MITIGATED** (control implemented and verified), **RESIDUAL** (inherent risk, accepted), **ACCEPTED** (business decision, documented), **OPEN** (work in progress)

### S — Spoofing

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| S-01 | Attacker uses stolen bearer token to authenticate | Medium | Critical | **MITIGATED** | Constant-time token comparison (no timing side-channel); brute-force lockout after configurable failures; tokens should be rotated by operator |
| S-02 | Attacker forges ECDSA signature to impersonate trusted client | Low | Critical | **MITIGATED** | ECDSA P-256 signature verification; private key never transmitted; signature includes timestamp + nonce to prevent replay |
| S-03 | Attacker replays captured authenticated request | Medium | High | **MITIGATED** | Session IDs are 256-bit random (crypto/rand); requests include session binding; nonce in signed requests prevents replay |
| S-04 | Fake ML model file served via supply chain attack | Medium | Critical | **MITIGATED** | SHA-256 hash verification on load; server refuses to start if hash mismatch |

### T — Tampering

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| T-01 | Modify RBAC roles or tool permissions at runtime | Low | High | **MITIGATED** | Roles configured at startup (compiled or config file); not runtime-modifiable via protocol |
| T-02 | Tamper with audit log entries | Low | Critical | **MITIGATED** | Tamper-evident SHA-256 hash chain — each entry's hash includes the previous entry's hash; deletion or modification breaks the chain |
| T-03 | Register malicious tool with poisoned description | Medium | Critical | **MITIGATED** | Tool Poisoning Scanner screens at registration time (34 dangerous function patterns + prompt injection detection); `SecuredMCPServer.RegisterTool()` auto-applies screening |
| T-04 | Tamper with ML model in transit | Low | Critical | **MITIGATED** | Model distributed via signed GitHub releases; hash verification on load |
| T-05 | Modify rate limit state to bypass throttling | Low | Low | **MITIGATED** | Rate limit state in-memory; not exposed via API; resets on restart |

### R — Repudiation

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| R-01 | Attacker denies making malicious tool call | Medium | Medium | **MITIGATED** | All tool calls logged in audit log with session ID, tool name, parameters, timestamp, and detection results |
| R-02 | Admin denies changing configuration | Low | Medium | **MITIGATED** | Admin actions logged with identity, timestamp, old/new values |
| R-03 | Attacker claims audit log was tampered | Low | High | **MITIGATED** | SHA-256 hash chain provides cryptographic proof of integrity; any tampering is detectable |

### I — Information Disclosure

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| I-01 | Audit log exposes sensitive tool call parameters | Medium | High | **MITIGATED** | Audit log stores tool name, detection findings, and metadata; full parameter logging is optional (compliance mode) |
| I-02 | ML model weights extracted | Low | Low | **ACCEPTED** | Model is open source (public); extraction not a concern |
| I-03 | Error messages reveal internal state | Low | Low | **MITIGATED** | JSON-RPC error responses use standard error codes; detailed errors logged server-side only |
| I-04 | Health endpoint exposes operational details | Low | Low | **MITIGATED** | Health endpoint returns minimal status (ok/not-ok); no sensitive data |
| I-05 | Tool description leaks during listing | Low | Low | **MITIGATED** | Tool descriptions are operator-controlled; tool poisoning scanner prevents injection at registration |

### D — Denial of Service

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| D-01 | Flood server with authentication attempts | High | Low | **MITIGATED** | Brute-force lockout after configurable failures; rate limiting per connection |
| D-02 | Exhaust sessions with many connections | Medium | Medium | **MITIGATED** | MaxSessions limit (default 1000); session timeout with cleanup; LRU eviction |
| D-03 | Call tools in rapid succession to exhaust resources | Medium | Medium | **MITIGATED** | Per-session RPM rate limiting; per-tool rate overrides; MaxCallsPerToolPerSession limit |
| D-04 | Send large JSON-RPC payloads | Medium | Medium | **MITIGATED** | 1MB body cap on HTTP transport; STDIO uses buffered reader with size limit |
| D-05 | Register many tools to exhaust memory | Low | Medium | **MITIGATED** | MaxToolsPerSession limit; tool registration requires auth |
| D-06 | Long-running tool execution blocks server | Medium | High | **MITIGATED** | Exec timeout (configurable, default 30s); tool execution runs in goroutine with context cancellation |
| D-07 | Chain analyzer memory exhaustion via many sessions | Low | Medium | **MITIGATED** | ChainWindow=20 entries per session; TTL=30min; automatic cleanup |
| D-08 | Slowloris attack on HTTP+SSE transport | Low | Medium | **MITIGATED** | ReadHeaderTimeout on HTTP server; connection idle timeout |

### E — Elevation of Privilege

| ID | Threat | Likelihood | Impact | Status | Mitigation |
|----|--------|------------|--------|--------|------------|
| E-01 | Attacker escalates from read to write role | Low | Critical | **MITIGATED** | 4-tier RBAC enforced at middleware layer; role checked before every tool call; roles not modifiable via protocol |
| E-02 | Attacker calls admin-restricted tool with lower role | Low | Critical | **MITIGATED** | Per-tool RBAC check; admin tools require admin role; denied calls logged in audit |
| E-03 | Bypass L3 ML blocking by manipulating score | Low | High | **MITIGATED** | L3 score from ONNX inference; threshold check is simple comparison; no user input affects score |
| E-04 | Bypass chain analysis by manipulating session ID | Medium | Medium | **RESIDUAL** | Session ID is client-provided; attacker could reset session by changing ID. Mitigated by short TTL (30min) and chain window (20 calls). L1/L2/L3 still block individual malicious calls. |
| E-05 | Register tool that bypasses poisoning scanner | Low | High | **MITIGATED** | 34 dangerous function patterns + recursive inputSchema screening; defense-in-depth with L1/L2/L3 runtime scanning of all tool calls |
| E-06 | Bypass guardrails by crafting benign-looking tool call | Low | High | **MITIGATED** | Guardrails check tool name against allowlist/denylist; content scanner inspects parameters; L3 ML catches semantic attacks regex misses |

---

## OWASP MCP Top 10 Coverage

AegisGate MCP provides full coverage of the OWASP MCP Top 10 (M1–M10). See [`docs/owasp-mcp-top-10.md`](owasp-mcp-top-10.md) for the detailed mapping.

| OWASP Risk | AegisGate Defense | Status |
|------------|-------------------|--------|
| M1: Tool Poisoning | Tool Poisoning Scanner (registration-time, 34 patterns) | ✅ Full |
| M2: Identity Spoofing | Bearer token + API key + constant-time + lockout | ✅ Full |
| M3: Insecure Session Mgmt | 256-bit random session IDs + expiry + anti-hijacking | ✅ Full |
| M4: Excessive Autonomy | 4-tier RBAC + Policy Engine + Chain Analysis | ✅ Full |
| M5: Data Exfiltration | Response scanning + chain analysis + secret redaction | ✅ Full |
| M6: Prompt Injection | 79 regex patterns + CharCNN-BiLSTM ML + input scanning | ✅ Full |
| M7: Insecure Transport | TLS + mTLS support | ✅ Full |
| M8: Missing Audit | Tamper-evident SHA-256 hash chain + health endpoints | ✅ Full |
| M9: Supply Chain Risk | Zero external module dependencies (all vendored) | ✅ Full |
| M10: DoS / Resource Exhaustion | Rate limiting + session limits + exec timeout + 1MB cap | ✅ Full |

---

## Validation Evidence

| Validation | Result | Details |
|------------|--------|---------|
| **Evasion Resistance** | 100.0/100 (0 misses) | 81 payloads × 50 transforms (full pipeline L1+L2+L3) |
| **ML Model Parity** | ✅ Verified | Same v15 ONNX model as Platform and Rampart (SHA-256: `99187453...`) |
| **Test Coverage** | 92.0% (non-CGO) / 91.9% (CGO) | 611 unit/integration + 32 load/stress = 643 total tests, 14 benchmarks, 3 fuzz targets |
| **OWASP MCP Top 10** | 10/10 covered | M1–M10 all fully mitigated (see owasp-mcp-top-10.md) |
| **Supply Chain** | Zero external deps | No `require` directives in go.mod; all third-party code vendored; distroless Docker option (0 CVEs) |
| **Dependabot** | 0 open alerts | All dependencies internal or vendored |

---

## Security Controls Summary

| Control | Status | Verification |
|---------|--------|--------------|
| **Authentication** (bearer token + API key) | ✅ Implemented | Constant-time comparison, lockout, unit tests |
| **ECDSA P-256 signatures** | ✅ Implemented | Signature verification with nonce + timestamp |
| **RBAC** (4-tier, per-tool) | ✅ Implemented | Middleware enforcement, integration tests |
| **Session management** | ✅ Implemented | 256-bit random IDs, expiry, MaxSessions, anti-hijacking |
| **Rate limiting** (per-session, per-tool) | ✅ Implemented | Token bucket, configurable overrides |
| **Content scanning** (L1+L2+L3) | ✅ Implemented | 79 regex patterns + ATLAS compliance + CharCNN-BiLSTM v15 |
| **Tool poisoning scanner** | ✅ Implemented | 34 dangerous function patterns, recursive inputSchema screening |
| **Chain analysis** | ✅ Implemented | Multi-turn detection, EscalationChain/ExfilChain/ReconChain |
| **Guardrails** | ✅ Implemented | Tool restrictions, exec timeout, MaxToolsPerSession |
| **Audit logging** (hash chain) | ✅ Implemented | Tamper-evident SHA-256 hash chain, configurable retention |
| **TLS/mTLS** | ✅ Implemented | Configurable TLS, mTLS with client cert verification |
| **ML model verification** | ✅ Implemented | SHA-256 hash verification on load |
| **Response scanning** | ✅ Implemented | L1/L2/L3 scan tool responses for PII/secrets/injection |
| **Platform forwarding** | ✅ Implemented | Optional, TLS, disabled by default |
| **Graceful degradation** | ✅ Implemented | ML unavailable → L1/L2 heuristics maintain coverage |

---

## Residual Risks (Accepted)

| Risk | Impact | Likelihood | Why Accepted |
|------|--------|------------|--------------|
| **Session fixation in chain analyzer** | Medium | Low | Session ID is client-provided; attacker could reset by changing ID. Impact limited to multi-turn bypass. L1/L2/L3 still block individual malicious calls. Short TTL (30min) limits window. |
| **No third-party audit** | High | Low | SBIR-gated ($15-30K pentest). Mitigated by open source (public scrutiny), 92% test coverage, OWASP MCP Top 10 full coverage, zero external dependencies. |
| **Production-scale MCP validation** | Medium | Low | Evasion suite validates attack detection, but production-scale MCP-specific benign traffic (8M+ requests) not yet validated like Platform. Shadow mode provides safety net. |

---

## Deployment Modes

### ML-Enabled (Default)

- **Docker image:** `debian:bookworm-slim` with `libgnutls30` purged
- **Size:** ~127 MB
- **CVEs:** 0 (gnutls purged eliminates all known CVEs)
- **ML:** CharCNN-BiLSTM v15 via vendored ONNX Runtime (CGO_ENABLED=1)
- **Use case:** Production deployments with full neural threat detection

### Lite (Heuristic-Only)

- **Docker image:** `gcr.io/distroless/static-debian12:nonroot`
- **Size:** ~10 MB
- **CVEs:** 0 (true distroless — no shell, no package manager, no OS libraries)
- **ML:** Disabled (CGO_ENABLED=0, pure Go binary)
- **Use case:** Air-gapped, resource-constrained, or heuristic-only deployments
- **Graceful degradation:** L1 (79 regex patterns) + L2 (ATLAS compliance) maintain detection coverage

---

## Reporting Vulnerabilities

**Preferred channel:** [GitHub Security Advisories](https://github.com/aegisgatesecurity/aegisgate-mcp/security/advisories) (private submission)

**Alternative:** Email security@aegisgatesecurity.io (PGP key on website)

**Response time:** 48 hours for initial response, 90 days for coordinated disclosure

**Bug bounty:** Not yet available (SBIR-gated). Recognition in SECURITY.md for responsible disclosures.

---

## Model Update Process

**AegisGate MCP does not support automatic model updates.** Model files must be manually deployed:

1. **Download** from signed GitHub release or copy from Platform release
2. **Verify hash**: `sha256sum models/threat_cnn_bilstm.onnx` → compare to `ExpectedModelHash` constant
3. **Deploy** to models directory (server will refuse to start if hash mismatch)
4. **Restart** server to load new model

The v15 ONNX model is shared across Platform, Rampart, Scanner, and MCP. Same file, same hash.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.6.1 | 2026-10-21 | Go 1.27.3 bump (GO-2026-6809 fix), trufflehog v3.99.2, setup-qemu-action v4. ML model updated to v15. |
| v1.6.0 | 2026-10-14 | Moat Deepening Release. 79 regex patterns, tool poisoning scanner (34 patterns), chain analysis, guardrails, platform forwarding. |
| v1.5.1 | 2026-10-11 | Performance optimizations, session management hardening. |
| v1.5.0 | 2026-10-09 | ML threat detection (L3), ECDSA signatures, mTLS support. |
| v1.3.0 | 2026-10-08 | Initial public release. RBAC, audit logging, rate limiting, content scanning (L1+L2). |

---

## Related Documents

- **OWASP MCP Top 10 Coverage:** [`docs/owasp-mcp-top-10.md`](owasp-mcp-top-10.md)
- **Model Card:** [`docs/model-card.md`](model-card.md)
- **Security Policy:** [`SECURITY.md`](../SECURITY.md) (vulnerability reporting)
- **Platform Threat Model:** [`aegisgate-platform/docs/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/docs/THREAT-MODEL.md)
- **Rampart Threat Model:** [`aegisgate-rampart/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-rampart/blob/main/THREAT-MODEL.md)
- **Lens Threat Model:** [`aegisgate-lens/docs/THREAT-MODEL.md`](https://github.com/aegisgatesecurity/aegisgate-lens/blob/main/docs/THREAT-MODEL.md)