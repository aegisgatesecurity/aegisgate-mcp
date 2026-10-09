# Comparison: AegisGate MCP vs Other MCP Security Approaches

> **TL;DR:** AegisGate MCP is the only zero-dependency, ML-enhanced, 21-layer
> security framework for MCP servers. Everything else is either an unsecured
> SDK or a bolt-on wrapper.

## Feature Comparison

| Feature | Official MCP SDK (TS/Python) | mcpgate | mcp-shield | AegisGate MCP |
|---------|------------------------------|---------|------------|---------------|
| **Language** | TypeScript, Python | Go | Python | Go |
| **Protocol version** | 2025-06-18 | 2024-11-05 | 2024-11-05 | 2025-06-18 |
| **Transport: TCP** | ❌ | ✅ | ❌ | ✅ |
| **Transport: stdio** | ✅ | ✅ | ❌ | ✅ |
| **Transport: Streamable HTTP** | ✅ | ❌ | ❌ | ✅ |
| **Authentication** | ❌ Bring your own | ✅ Basic | ❌ | ✅ Bearer + API key + lockout |
| **Authorization (RBAC)** | ❌ | ❌ | ❌ | ✅ 4-tier hierarchy |
| **Policy engine** | ❌ | ❌ | ❌ | ✅ Allow/deny + conditions + time windows |
| **Audit logging** | ❌ | ❌ | ❌ | ✅ Tamper-evident hash chain |
| **Threat detection (regex)** | ❌ | ❌ | ✅ Basic | ✅ 30 patterns |
| **Threat detection (ML)** | ❌ | ❌ | ❌ | ✅ CharCNN-BiLSTM v13 |
| **Tool poisoning detection** | ❌ | ❌ | ❌ | ✅ Registration-time scan |
| **Response scanning** | ❌ | ❌ | ✅ Basic | ✅ PII + secrets + XSS + injection |
| **Secret redaction** | ❌ | ❌ | ❌ | ✅ Configurable |
| **Chain analysis** | ❌ | ❌ | ❌ | ✅ Escalation + exfiltration detection |
| **Signature verification** | ❌ | ❌ | ❌ | ✅ ECDSA P-256 |
| **Rate limiting** | ❌ | ✅ Basic | ❌ | ✅ Token bucket + burst |
| **Session management** | ❌ | ✅ Basic | ❌ | ✅ 256-bit IDs + anti-hijacking |
| **TLS / mTLS** | ❌ | ❌ | ❌ | ✅ |
| **Health endpoints** | ❌ | ✅ | ❌ | ✅ /healthz, /readyz, /stats |
| **Model hot-swap** | ❌ | ❌ | ❌ | ✅ Runtime ONNX reload |
| **External dependencies** | npm/pip (many) | Go modules | pip | **Zero** |
| **Air-gapped deployment** | ❌ | ❌ | ❌ | ✅ |
| **License** | MIT | MIT | MIT | Apache 2.0 |

## Architecture Comparison

### Official MCP SDK

The official SDKs (TypeScript and Python) provide protocol implementation
only — JSON-RPC handling, transport, and tool/resource/prompt primitives.
Security is entirely left to the developer:

- No authentication framework
- No authorization model
- No threat detection
- No audit trail
- No rate limiting
- Heavy dependency trees (npm/pip) create supply chain risk

**Result:** 38% of MCP servers built on the official SDKs have zero
authentication. The 3 critical CVEs in 6 months (including CVSS 9.8 RCE)
demonstrate the risk of these large dependency trees.

### Bolt-on Security Wrappers (mcp-shield, mcpgate)

These projects attempt to add security on top of the official SDKs:

- **mcp-shield** — Python proxy that adds basic prompt injection scanning.
  No authentication, no RBAC, no audit logging. Depends on the Python
  MCP SDK and its transitive dependencies.

- **mcpgate** — Go gateway with basic auth and rate limiting. No ML threat
  detection, no policy engine, no chain analysis, no response scanning.
  Still uses 2024-11-05 protocol version (no Streamable HTTP).

**Limitation:** Bolt-on wrappers can only inspect traffic at the protocol
level — they cannot enforce per-tool RBAC, scan tool registrations for
poisoning, or run chain analysis because they don't have access to the
server's internal state.

### AegisGate MCP

AegisGate MCP is built from the ground up as a security-first framework:

- **22 security layers** integrated into the request pipeline — not bolted on
- **Zero external dependencies** — no `require` directives in go.mod, all
  third-party code vendored into `internal/`
- **ML threat detection** — CharCNN-BiLSTM v13 neural model with <1ms CPU
  inference, the same model used by AegisGate Platform and Rampart
- **Tool poisoning detection** — scans tool descriptions and input schemas
  for prompt injection at registration time, before the tool is ever callable
- **Chain analysis** — tracks tool call sequences within sessions to detect
  privilege escalation and data exfiltration patterns
- **Protocol 2025-06-18** — full support for the current MCP spec including
  Streamable HTTP transport

## When to Use What

| Scenario | Recommendation |
|----------|----------------|
| Prototype / demo MCP server | Official MCP SDK (fastest to start) |
| Production MCP server needing security | **AegisGate MCP** |
| Air-gapped / OT-ICS deployment | **AegisGate MCP** (zero deps) |
| Enterprise gateway for all AI traffic | **AegisGate Platform** |
| Local developer proxy for AI APIs | **AegisGate Rampart** |
| Adding basic injection scanning to existing server | mcp-shield (as proxy) |

## Supply Chain Risk

| | Official SDK | Bolt-on wrappers | AegisGate MCP |
|---|---|---|---|
| Direct deps | 20-50+ | 10-30+ | **0** |
| Transitive deps | 200-500+ | 100-300+ | **0** |
| CVEs (6 months) | 3 critical | Inherited from SDK | **0** |
| `go mod download` needed | N/A (npm/pip) | N/A | **No** |

AegisGate MCP's `go.mod` has zero `require` directives. All third-party code
(ONNX Runtime bindings, Unicode normalization, ML model) is vendored into
`internal/`, `lib/`, and `models/`. This eliminates the entire class of
supply chain attacks that plague the npm/PyPI ecosystems.