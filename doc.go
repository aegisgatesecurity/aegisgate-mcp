// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate MCP — Standalone MCP Server Security Package
// =========================================================================
//
// A self-contained, zero-dependency MCP server with built-in security:
//   - Authentication (bearer token + API key, lockout, global rate limiting)
//   - Signature verification (anti-forgery, ECDSA P-256)
//   - Session management (anti-hijacking, expiry, tracking)
//   - RBAC (role-based access control per tool, 4-tier hierarchy)
//   - Policy engine (allow/deny rules with conditions, priorities, time windows)
//   - Guardrails (rate limiting, tool call limits, chain analysis)
//   - Tool call chain analysis (privilege escalation, exfil chain detection)
//   - Response scanning (PII, secrets, XSS, prompt injection detection)
//   - Secret redaction (scrub sensitive data from responses)
//   - Tool execution timeout (prevents hanging tools)
//   - STDIO command validation (shell injection prevention)
// - Tamper-evident audit logging (SHA-256 hash chain, tamper detection)
//   - TLS/mTLS transport (encrypted connections for secure networks)
//   - stdio transport (standard MCP client transport)
//   - Health endpoint (HTTP /healthz, /readyz, /stats, /metrics for Prometheus)
//   - Parameter validation (required fields checked against inputSchema)
//   - MCP spec compliance (initialize, notifications, tools, resources, prompts, logging, completion, ping)
//   - Functional resources and prompts with registration handlers
//   - Tool poisoning detection (scans descriptions/schemas at registration time)
//   - Streamable HTTP transport (MCP Spec 2025-06-18)
//   - ML model hot-swap (reload model at runtime without restart)
//
// Go standard library only. No external dependencies. Air-gapped capable.
//
// Based on AegisGate Platform v4.5.2 MCP security stack.
// =========================================================================

package mcpsecurity

// Version is the standalone package version.
const Version = "1.2.1"
