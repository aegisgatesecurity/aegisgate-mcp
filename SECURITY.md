<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2024-2026 AegisGate Security, LLC -->

# Security Policy

## Supported Versions

AegisGate MCP follows semantic versioning.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Architecture

AegisGate MCP is a standalone Model Context Protocol (MCP) security server designed for
OT/ICS environments. It sits between MCP clients (AI agents) and MCP servers (tools),
providing 21 security layers:

| Layer | Protection | Tier |
|-------|-----------|------|
| L1 | Regex pattern matching (30 patterns) | Heuristic |
| L2 | MITRE ATLAS compliance + input scanner | Heuristic |
| L3 | CharCNN-BiLSTM neural threat detection (v13) | Neural |
| — | Bearer token / API key authentication | Core |
| — | HMAC-SHA256 signature verification | Core |
| — | Session management with limits | Core |
| — | RBAC policy engine | Core |
| — | Policy engine (allowlist/denylist) | Core |
| — | Guardrails (tool restrictions) | Core |
| — | Chain analysis (privilege escalation detection) | Core |
| — | Token bucket rate limiting | Core |
| — | Input scanning (prompt injection regex) | Core |
| — | Response scanning (PII, secrets, XSS, prompt injection) | Core |
| — | Secret redaction in responses | Core |
| — | Execution timeout | Core |
| — | STDIO validation (shell injection prevention) | Core |
| — | Audit logging (tamper-evident hash chain) | Core |
| — | TLS / mTLS transport | Core |
| — | STDIO transport | Core |
| — | Health endpoint | Core |
| — | Parameter validation | Core |
| — | Heuristic evasion detection | Heuristic |
| — | NFKC Unicode normalization | Core |

### Dual Build Modes

| Mode | CGO | ML | Binary Size | Docker Image |
|------|-----|----|-------------| ------------|
| Full | `CGO_ENABLED=1` | Neural (ONNX Runtime) | ~15MB | ~136MB (debian:bookworm-slim) |
| Lite | `CGO_ENABLED=0` | Heuristic-only | ~8MB | ~90MB (debian:bookworm-slim) |

### Two-Tier Neural Blocking (L3)

| Tier | Score | Action |
|------|-------|--------|
| High confidence | ≥ 0.95 | Block independently |
| Corroborated | 0.50–0.94 | Block only with L1/L2 corroboration |
| Alert-only | 0.50–0.94 (no corroboration) | Log alert, allow request |

### Supply Chain Security

- **Zero external module dependencies** (no `require` directives in go.mod)
- All third-party code vendored: onnxruntime_go (MIT), libonnxruntime.so (MIT, Microsoft), golang.org/x/text (BSD-3-Clause)
- Model integrity verified via SHA-256 hash at load time
- Tamper-evident audit log (SHA-256 hash chain)

## Security Features

| Tool | Purpose | Frequency |
|------|---------|-----------|
| **govulncheck** | Go vulnerability database | Every push |
| **gosec** | Static security analysis | Every push |
| **Trivy** | Container & filesystem scan | Every push + weekly |
| **Gitleaks** | Secret detection (git history) | Every push |
| **TruffleHog** | Verified secret detection | Every push |
| **go vet** | Standard Go analysis | Every push |
| **OPSEC scan** | Private paths, internal docs, secrets | Every push + pre-commit |
| **SBOM** | CycloneDX + SPDX generation | Every push + releases |

## Security Certifications

| Status | Item |
|--------|------|
| ✅ | **0 Known CVEs** in dependencies (zero external module deps) |
| ✅ | **SBOM Generation** (CycloneDX + SPDX) |
| ✅ | **Secret Scanning** (Gitleaks + TruffleHog + OPSEC) |
| ✅ | **92.3% Test Coverage** (non-CGO), 92.1% (CGO) |
| ✅ | **Tamper-Evident Audit Logging** |
| ✅ | **Air-gapped Capable** (zero network dependencies) |

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

Email: security@aegisgatesecurity.io

Please include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a fix or mitigation within
90 days. Valid vulnerability reports may be eligible for a bounty.

## Audit Log Data Handling

MCP audit logs store detection metadata including tool names, matched patterns,
severity levels, and ML threat scores. **Original secret values are never stored** —
they are redacted to `[REDACTED]` before any logging occurs. PII values are partially
masked before logging.

The audit log uses a tamper-evident SHA-256 hash chain: each entry includes the hash
of the previous entry, making silent tampering detectable.