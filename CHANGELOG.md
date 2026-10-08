# Changelog

All notable changes to AegisGate MCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-10-08

### Added

- **Protocol version 2025-06-18** — upgraded from 2024-11-05 to the current
  MCP specification version
- **Streamable HTTP transport** — MCP 2025-06-18 transport mode (`--transport http`).
  Clients POST JSON-RPC to a single `/mcp` endpoint. POST-only, 1MB body limit,
  `MCP-Protocol-Version` response header, notifications return 202 Accepted
- **Tool poisoning detection** — scans tool descriptions and `inputSchema`
  (recursively) for prompt injection at registration time. Returns
  `*ToolPoisoningError` with tool name, reason, and matched patterns.
  Applied automatically by `SecuredMCPServer.RegisterTool()`
- **Functional resources** — `RegisterResource()` with URI-based lookup,
  handler functions, and `ResourceContent` responses. Wired to
  `resources/list` and `resources/read` JSON-RPC methods
- **Functional prompts** — `RegisterPrompt()` with name-based lookup,
  argument support, and `GetPromptResult` responses. Wired to
  `prompts/list` and `prompts/get` JSON-RPC methods
- **ML model hot-swap** — `ReloadMLModel(path)` atomically swaps the ONNX
  model at runtime. Verifies SHA-256 hash, closes old session, loads new
- **OWASP MCP Top 10 mapping** — `docs/owasp-mcp-top-10.md` documents
  coverage for all 10 OWASP MCP security risks
- **Comparison document** — `docs/comparison.md` maps AegisGate MCP against
  the official MCP SDKs and bolt-on security wrappers
- **Example server** — `examples/simple-server/` demonstrates tool, resource,
  and prompt registration with all security features enabled
- Comprehensive test suite for all v1.2.0 features (`v120_test.go`)

### Changed

- Version bumped from 1.1.0 to 1.2.0
- `ProtocolVersion` constant updated from `2024-11-05` to `2025-06-18`
- `--transport` flag now accepts `http` in addition to `tcp` and `stdio`
- `initialize` response capabilities now include `resources` (with
  `subscribe` and `listChanged`) and `prompts` (with `listChanged`)
- `Stats()` now includes `resources_registered` and `prompts_registered`
- Test count: 388 (non-CGO) / 392 (CGO), coverage 90.5% (non-CGO) / 91.2% (CGO)

### Security

- Tool poisoning detection prevents malicious tools from being registered
  with prompt injection in their descriptions or input schemas
- Streamable HTTP transport enforces POST-only, 1MB body limit, and proper
  HTTP status codes (400/405/202) to prevent protocol abuse

## [1.1.0] — 2026-09-30

### Added

- ML inference throttle (100 inf/min, 10 burst/sec, 4 concurrent) to prevent
  Platform dilution
- Multi-arch ARM64 Docker support
- ML wiring tests and `.so` hash verification
- Cosign-signed release artifacts with SHA-256 checksums

### Changed

- Upgraded Go 1.25 → 1.26.6
- Documented accepted Debian CVEs in Docker image
- Resolved gosec/staticcheck CI findings
- Fixed CI coverage reporting

### Security

- Fixed gosec and staticcheck findings
- Added `.gitleaks.toml` to prevent Trivy self-scan false positives