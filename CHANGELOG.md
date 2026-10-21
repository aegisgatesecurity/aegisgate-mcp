# Changelog

All notable changes to AegisGate MCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.1] — 2026-10-21 - ML Model v15b Update

> **v1.6.1** updates MCP to the v15b ML model (256-char Latin-1) and restores MaxSeqLen=256.

### ML Model v15b
- Updated `ExpectedModelHash` in `internal/ml/detector.go` to v15b SHA-256: `99187453bedb2b8caf21500d2344f2bbe34272c0b3fd4c610c431378dc2f4fe7`
- Restored `MaxSeqLen = 256` and `VocabSize = 256` (Latin-1) in `internal/ml/normalizer.go`
- Updated ONNX model file `models/threat_cnn_bilstm.onnx` to v15b
- Test expectations updated from 128→256

---

## [1.6.0] — 2026-10-14 - Moat Deepening: RAG Patterns, Prompt Leakage, Dangerous Functions, Platform Interop

> **v1.6.0** extends MCP's detection coverage from 30 to 91 regex patterns, adds platform interop for pattern pulling and event forwarding, and enhances tool poisoning detection with dangerous function screening. All new features are air-gap compatible — platform interop is opt-in, outbound, config-driven, and fully disabled when `platform_url` is empty.

### Added — Detection Pattern Expansion (30 → 91 patterns)

- **Dangerous function detection (28 patterns)** — Scans tool parameters and descriptions for dangerous code patterns: `eval()`, `exec()`, `os.system()`, `subprocess(shell=True)`, `pickle.loads()`, `__import__()`, `child_process.exec()`, `innerHTML`, `Function()`, `document.write()`, base64 decode chains, hardcoded URLs, internal service URLs, and more. Imported from AegisGate Scanner's `pkg/detectors/dangerous_functions.go`.
- **RAG attack patterns (9 patterns)** — Detects vector store injection, RAG smuggling (metadata, HTML comments), retrieval bypass, RAG poisoning (conditional instructions, embedding manipulation), and knowledge base data injection.
- **Prompt leakage patterns (7 patterns)** — Detects system prompt leakage in responses: `<system>` tag content, meta-instruction references, internal tool list disclosure, instruction repeats, and raw config dumps.
- **OT/ICS protocol patterns (3 patterns)** — OPC UA, Modbus, and DNP3 protocol address detection.
- **Additional credential patterns** — JWT tokens, GitHub PATs, generic API keys, RSA private keys.
- **Additional compliance patterns** — OWASP LLM01 (prompt injection), LLM02 (insecure output), LLM06 (sensitive info disclosure).

### Added — Platform Interop

- **Pattern pull**: MCP can pull canonical detection patterns from Platform's telemetry endpoint (`GET /api/v1/patterns/latest`) with ETag caching. Air-gap compatible — no-op when `platform_url` is empty.
- **Event forwarding**: MCP forwards security events to Platform's telemetry receiver (`POST /api/v1/events`) in canonical contract format. Air-gap compatible — no-op when `platform_url` is empty.
- **Tool description screening**: Enhanced tool registration screening now checks for dangerous function patterns in addition to prompt injection. Maps to OWASP MCP Top 10 MCP03 (Tool Poisoning).

### Security Layers

- Still 23 security layers (detection enhancements are within existing Layer 9 Input Scanning and Layer 10 Response Scanning)
- Layer 22 (Tool Poisoning Detection) now screens for 34 dangerous function patterns in addition to prompt injection patterns

### Testing

- 22 new tests (Phase 3 interop + Phase 4 OWASP gaps)
- Overall coverage: 93.4%
- All existing tests continue to pass

### Version Bumps

- MCP VERSION: 1.5.0 → 1.6.0
- `doc.go`: version constant updated
- README badges updated to v1.6.0

---

## [1.5.1] — 2026-10-11

### Changed

- **Distroless Docker images.** Rewrote Dockerfile with two runtime targets:
  - `ml` (default): Debian bookworm-slim with libgnutls30 purged (`.so` files
    + dpkg metadata removed). Eliminates all 6 Trivy CVEs. 127 MB
  - `lite`: True distroless (`gcr.io/distroless/static-debian12:nonroot`).
    10.1 MB, zero CVEs, zero OS packages
- **`--health-check` CLI flag.** Binary performs HTTP GET to `/healthz` and
  exits 0/1. Eliminates need for wget/curl in Docker HEALTHCHECK

### Fixed

- **MCP Registry compliance.** Shortened `server.json` description to fit
  100-character limit (#46)
- **gosec G118 false positive.** Annotated intentional `context.Background()`
  in graceful shutdown goroutine with `// #nosec G118` directive (#47, #51)
- **GitHub Stars badge.** `style=social` renders "invalid" on GitHub.
  Replaced with `style=flat` and social-matching colors (#48, #49)
- **Audit log directory creation.** Added `os.MkdirAll` for parent directory
  in audit logger, preventing failure when `/tmp/mcp-audit/` doesn't exist

## [1.5.0] — 2026-10-10

### Added

- **Evasion Detection (L2.5).** Wired the `EvasionDetector` into the live
  request pipeline as layer 23, between L1 regex scanning and L3 neural
  detection. Detects 15 evasion patterns across 4 categories: encoding
  (base64, URL, unicode, HTML entities), splitting (zero-width chars,
  interleaving, word splitting), obfuscation (leet speak, CamelCase,
  padding, markup injection), and semantic evasion (role-play framing,
  instruction override, context manipulation, output constraint bypass).
  Score ≥ 0.8 blocks independently; ≥ 0.3 logs warning. Pure Go, no CGO
  required. Brings security layer count from 22 to 23
- **`completion/complete` implementation.** Replaced empty stub with
  functional completion handler per MCP spec 2025-06-18. `ref/prompt`
  validates prompt and argument existence. `ref/resource` matches partial
  URI against registered resources and templates, capped at 100 results
  with `hasMore` flag
- **Per-session SSE multiplexing.** Changed `sseConns` from single to
  multiple connections per session. Supports parallel SSE streams and
  reconnection while old connection is still open. Uses pointer-based
  connection removal
- **`Last-Event-ID` reconnection support.** Implements SSE reconnection
  per spec. Monotonic event IDs, bounded ring buffer (100 events), replay
  on reconnection. Events include `id:` field for client tracking
- **Per-tool rate limiting.** `MaxCallsPerToolPerSession` limits total
  calls to a single tool per session (atomic counter). `ToolRateOverrides`
  sets per-tool RPM overrides (e.g., `{"exec": 5, "read_file": 120}`)
- **Elicitation support.** `elicitation` capability advertised in
  initialize response. `ElicitInput()` and `SetElicitationCallback()`
  methods on `SecuredMCPServer` allow tool handlers to request information
  from the client/user via `elicitation/create`. Fully wired across all
  three transports: HTTP/SSE (async correlation via pending request
  registry, response arrives as separate POST), TCP (synchronous
  request-response on bidirectional connection), and stdio (same
  synchronous pattern via stdin/stdout pipes). `ElicitationRegistry`
  manages pending requests with 30s default timeout, monotonic IDs,
  and concurrent-safe resolution
- **Startup chain validation logging.** `wireHandlerChain()` logs active
  security chain execution order and layer count at startup
- **HTTP transport benchmarks.** `BenchmarkHTTPPing` and
  `BenchmarkMiddlewareChain` added. `BENCHMARKS.md` published with 12
  benchmark results, methodology, and reproduction instructions
- **3 new chain order tests** (`chain_order_test.go`): auth blocks,
  evasion detector wired, evasion stats in `Stats()`
- **`logging/setLevel` log filtering.** `logging/setLevel` now actually
  filters server log output via a custom `slog.Handler` wrapper. MCP
  levels (debug, info, notice, warning, error, critical, alert,
  emergency) map to slog levels. Thread-safe via RWMutex
- **`notifications/progress` support.** Tool calls with
  `_meta.progressToken` now receive periodic `notifications/progress`
  notifications during long-running execution. Progress delivered via
  thread-local `currentNotifyFn` (TCP/stdio) or `NotifyCallback` (HTTP)
- **JSON-RPC 2.0 batch support.** All three transports (TCP, stdio,
  HTTP) now handle JSON-RPC batch requests (arrays of requests).
  Responses are collected and returned as an array. All-notification
  batches produce no response
- **`roots/list` handler.** Returns empty roots list for compatibility
  with clients that send it unconditionally, even though we don't
  advertise the `roots` capability
- **`currentSessionID` for TCP/stdio.** TCP and stdio transports now
  set `currentSessionID` before dispatching requests, enabling correct
  subscription tracking on all transports, not just HTTP

### Changed

- Version bumped from 1.4.2 to 1.5.0
- `ServerConfigV2`: new `EvasionDetection` (default: `true`),
  `MaxCallsPerToolPerSession`, `ToolRateOverrides` fields
- Initialize response now advertises `elicitation` capability
- `sseConns` type changed from `map[string]*sseConn` to
  `map[string][]*sseConn` for multiplexing
- `broadcastNotification()` and `writeSSEResponse()` now assign event IDs
  and buffer events for replay
- `server.json`: version 1.5.0, description updated to "23 security layers"

### Performance (CGO_ENABLED=0, 40-core, Go 1.26.9)

- Middleware chain overhead: **13.3μs** per request (negligible vs LLM
  latency)
- Auth middleware: **510ns** (sub-microsecond)
- Content scanning: **1.9μs** (100 chars), **590μs** (500 bytes), linear
  scaling
- HTTP transport: **310μs** per request (full HTTP roundtrip)
- Near-zero allocation hot paths: `ToolsList` (3 allocs),
  `AuthMiddleware` (2 allocs)

### Fixed

- **HTTP session ID mismatch with RBAC.** When `OnAuthSuccess` was
  configured (the default in `NewSecuredMCPServer`), the auth middleware
  replaced `conn.Session.ID` with an RBAC session ID. The HTTP transport
  then returned this RBAC ID in the `Mcp-Session-Id` header, but stored
  the session in its map under the original HTTP session ID. Subsequent
  requests with the RBAC ID always got "session not found or expired".
  Fixed by tracking the HTTP session ID separately from `conn.Session.ID`
  in both the single-request and batch-request paths
- **Test race condition in `mockResponseWriter`.** `elicitation_test.go`
  had a data race: test goroutine called `buf.String()` while
  `sendElicitation` goroutine wrote via `fmt.Fprintf`. Production code
  was already safe (`sseConn.mu`). Fixed by adding `sync.Mutex` to
  `mockResponseWriter` with thread-safe `Write`/`WriteHeader`/`String`
  methods
- **Dockerfile VERSION stale.** `ARG VERSION=1.1.0` despite being on
  v1.5.0. Fixed to `1.5.0`. CI build steps also updated to read from
  `VERSION` file instead of hardcoding
- **Makefile VERSION stale.** `VERSION ?= 1.1.0` despite being on v1.5.0.
  Fixed to `1.5.0`

### CI / DevOps

- **Race detector in CI.** New `race` job runs `go test -race` on all
  tests with CGO enabled, fails on any `DATA RACE` detection
- **Load tests in CI.** New `load-test` job runs the full k6-style
  suite (`-tags=load`) on every push/PR, verifying stress, burst,
  crush, and chaos resilience
- **Benchmark regression tracking.** New `benchmark` job runs all
  benchmarks with `benchstat` and uploads results as artifacts
- **`go mod tidy` check.** Lint job now verifies `go.mod`/`go.sum` are
  tidy, failing if drift is detected
- **Version from VERSION file.** Build job reads version from `VERSION`
  file instead of hardcoding, preventing stale version strings

### Load Testing

- **Comprehensive k6-style load testing suite** (22 tests, `//go:build load`):
  - **Stress**: Ramp-up (10→500 connections, 100% success at 738 rps),
    resource monitor (10 waves × 50 conns × 20 reqs, goroutine leak check)
  - **Burst**: Connection spike (200 simultaneous), request spike (1000
    reqs in 79ms = 12,710 rps), recovery (baseline p50 restored in <1s)
  - **Crush**: Beyond MaxConnections (500 into limit 30), memory pressure
    (300KB payloads), goroutine explosion (500 connection churn, 0 leak),
    malformed flood (500 mixed messages, server survives)
  - **Chaos**: Random drops (100 conns, 30% drop rate), half-sent messages
    (partial JSON + garbage + abrupt close), shutdown under load (50
    active generators, graceful in 1.6ms)
  - **HTTP transport**: Concurrent (50 clients, 2290 rps), sustained (20
    clients × 30 reqs), burst (200 concurrent), oversized body, auth flood,
    soak (5s, 0 errors), batch load (20 clients × 10 batch), connection
    exhaustion (300 concurrent)
  - **Cross-transport**: TCP vs HTTP latency head-to-head comparison
  - **FD leak**: 500 connection churn across 5 rounds, ≤1 FD delta
  - Metrics framework: p50/p90/p99 latencies, goroutine count, heap
    growth, GC cycles, throughput, error rate — formatted report per test

## [1.4.2] — 2026-10-09

### Fixed
- **SSE connections killed after 60 seconds.** The HTTP server's
  `WriteTimeout` was 60s, which silently terminated long-lived SSE
  connections after one minute — breaking server-initiated notification
  delivery for any client connected longer than 60s. Fixed by setting
  `WriteTimeout: 0` (disabled). Connection-level protection is still
  provided by `ReadHeaderTimeout` (slowloris), `ReadTimeout` (body),
  `IdleTimeout` (keepalive), and handler context cancellation
- **Signature verification missing from HTTP and stdio transports.**
  The handler chain in `ServeWithOptions()` for the `http` and `stdio`
  cases was missing `wrapWithSignatureVerification`, meaning the ECDSA
  P-256 signature verification layer only worked on TCP transport. Now
  all three transports (TCP, HTTP, stdio) include the full security
  chain: auth → signature verification → guardrails → response scan →
  handler
- **Concurrent SSE writes race condition.** `broadcastNotification()`
  wrote to `http.ResponseWriter` instances without per-connection
  synchronization. Concurrent notifications (e.g., tools/list_changed
  and resources/updated fired simultaneously) could race on the same
  ResponseWriter. Fixed by adding a `sync.Mutex` to the `sseConn` struct
  to serialize writes

### Changed

- **Removed dead `evasionDetector` field.** `EvasionDetector` was
  instantiated and stored on `SecuredMCPServer` but never wired into
  the detection pipeline. Removed to avoid implying a capability that
  doesn't exist. The `ml.EvasionDetector` type remains available for
  future integration (v1.5.0+)

### Documentation

- `SECURITY.md`: corrected "21 security layers" → "22 security layers"
  (was missed during v1.4.1), corrected "HMAC-SHA256" → "ECDSA P-256"
  (matching actual code), removed "Heuristic evasion detection" row
  (code was never wired)
- `README.md`: corrected test count (480 → 429) and coverage numbers
  (90.1% → 90.8% non-CGO, 90.9% → 91.4% CGO)
- `docs/v1.3.0-roadmap.md`: corrected test count (423 → 429) and
  coverage (90.9% → 91.4%)

### Tests

- Added `TestBroadcastNotificationConcurrent` — 10 concurrent
  notification goroutines writing to a single SSE connection (run with
  `-race` to verify mutex correctness)
- Added `TestSSEServerWriteTimeoutZero` — regression test ensuring
  `WriteTimeout` stays at 0 for long-lived SSE support

## [1.4.1] — 2026-10-09

### Fixed

- **Notification JSON-RPC format.** Server-initiated notifications now use
  a proper `JSONRPCNotification` type with top-level `method` field per
  JSON-RPC 2.0 spec. Previously, notifications were incorrectly wrapped
  in a `JSONRPCResponse.Result` object with `id: null`, which no MCP client
  could parse
- **Notification callback wired in production.** `SetNotifyCallback()` is
  now called in `ServeWithOptions()` for the HTTP transport, connecting
  the handler's notification dispatch to the transport's SSE broadcast
  mechanism. Previously, `NotifyCallback` was nil in production, making
  all `Notify*ListChanged()` and `NotifyResourceUpdated()` calls silent
  no-ops
- **Long-lived SSE connections.** SSE connections are now held open after
  the initial response, allowing server-initiated notifications to be
  pushed to connected clients. The transport maintains a per-session
  connection registry and broadcasts notifications to all active SSE
  connections
- **GET endpoint for SSE streams.** Added `GET /mcp` support per MCP
  2025-06-18 spec. Clients can open a long-lived SSE connection for
  server-initiated messages without sending a request. Requires a valid
  `Mcp-Session-Id` header
- `docs/comparison.md` TL;DR corrected from "21-layer" to "22-layer"
- `TestStreamableHTTPMethodNotAllowed` updated to use PUT (GET is now
  a supported method for SSE streams)

### Added

- `JSONRPCNotification` type in `types.go` — proper JSON-RPC 2.0
  notification with top-level `method` and `params` fields
- `sseConn` type and SSE connection registry in `streamable_http.go`
- `registerSSEConn()`, `unregisterSSEConn()`, `broadcastNotification()`
  methods on Streamable HTTP transport
- `handleSSEStream()` handler for GET-based SSE streams
- `readSSEBody()` test helper with timeout (replaces `io.ReadAll` which
  blocks on now long-lived connections)
- `TestSSENotificationDelivery` rewritten as true end-to-end test:
  handler → broadcast → SSE connection → client reads notification,
  verifies proper JSON-RPC notification format (top-level `method`,
  no `result` field)

### Changed

- `writeSSEResponse()` now holds the connection open after writing the
  response, registering it for notification delivery until the client
  disconnects
- Removed `makeNotificationCallback()` (per-request callback) — replaced
  by `broadcastNotification()` (connection registry broadcast)
- `handleMCP()` now handles GET requests for SSE streams
- Allow header updated to `GET, POST, DELETE`

## [1.4.0] — 2026-10-09

### Added

- **Server-initiated notifications (P2).** The server now advertises
  `listChanged: true` for tools, resources, and prompts capabilities.
  `NotifyToolsListChanged()`, `NotifyResourcesListChanged()`, and
  `NotifyPromptsListChanged()` methods on `SecuredMCPServer` dispatch
  `notifications/*/list_changed` to connected clients via a
  `NotificationCallback`
- **Resource subscriptions (P3).** Real `resources/subscribe` and
  `resources/unsubscribe` handlers with per-session subscription tracking.
  `NotifyResourceUpdated(uri)` sends `notifications/resources/updated` to
  all subscribed sessions. Resources capability now advertises `subscribe: true`
- **Resource templates (P4).** `resources/templates/list` endpoint returns
  registered URI templates. `RegisterResourceTemplate()` on both
  `ResourceRegistry` and `SecuredMCPServer` for parameterized resource URIs
- `SetNotifyCallback()` method on `SecuredMCPServer` for wiring notification
  delivery to the transport layer
- `makeNotificationCallback()` on Streamable HTTP transport for SSE delivery
- 11 new tests: notification dispatch, subscription lifecycle, subscribe
  validation, resource templates, SecuredMCPServer wrapper methods, SSE
  notification delivery, idempotent unsubscribe

### Changed

- `handleInitialize` now advertises `listChanged: true` for tools/resources/prompts
  and `subscribe: true` for resources (was empty capability objects)
- Go runtime updated from 1.26.6 to 1.26.9 (resolves 14 CVE alerts)
- README Go badge updated to 1.26.9

### Fixed

- 14 code scanning CVE alerts resolved by Go 1.26.9 update
- G118 gosec false positive dismissed (standard shutdown pattern)

## [1.3.0] — 2026-10-08

### Added

- **SSE streaming responses for Streamable HTTP transport.** When a client
  sends a POST request with `Accept: text/event-stream`, the server responds
  with `Content-Type: text/event-stream` and streams JSON-RPC responses as
  Server-Sent Events (`data: {json}\n\n`). Notifications receive a comment
  ack (`: ack\n\n`). This enables compatibility with MCP clients that prefer
  or require SSE streaming
- SSE-specific headers: `Cache-Control: no-cache`, `Connection: keep-alive`
- 7 new SSE tests: SSE initialize, SSE ping, SSE notification (comment ack),
  SSE tools/list, SSE session required, Accept JSON still works (non-SSE
  fallback), SSE response format verification

### Changed

- Streamable HTTP transport now checks `Accept` header for content negotiation
  between `application/json` (default) and `text/event-stream` (SSE mode)
- Updated transport documentation comments to reflect SSE support

### Compatibility

- Clients without `Accept: text/event-stream` continue to receive plain JSON
  responses — fully backward compatible with v1.2.2
- SSE mode is opt-in only; no changes required for existing clients

## [1.2.2] — 2026-10-08

### Changed

- **Streamable HTTP transport: implemented `Mcp-Session-Id` support.**
  The server now generates a cryptographically random session ID on
  `initialize`, returns it in the `Mcp-Session-Id` response header, and
  validates it on all subsequent requests. Sessions expire after 30 minutes
  of inactivity. Clients can terminate a session by sending `DELETE` to the
  `/mcp` endpoint with the session ID header — per MCP 2025-06-18 spec
- **Removed fake `resources/subscribe` and `resources/unsubscribe` stubs.**
  These methods previously returned `{}` (fake success) without implementing
  any subscription logic. They now return `method not found` (JSON-RPC error
  code -32601). This aligns with the honest capability advertisements from
  v1.2.1 — the server only claims what it implements
- **Rewrote Streamable HTTP transport documentation comments.** Previous
  comments claimed SSE streaming (`text/event-stream`) support that did not
  exist. Comments now accurately describe request/response mode only, with
  SSE streaming noted as a planned v1.3.0 feature

### Added

- `DELETE` method support on `/mcp` endpoint for session termination
- Session lifecycle management: creation, validation, touch on activity,
  expiry (30 min idle), and client-initiated termination
- 8 new tests: session required, invalid session, DELETE session, DELETE
  without session, session persistence across requests, subscribe returns
  method not found (HTTP), subscribe/unsubscribe return method not found
  (JSON-RPC)

### Security

- Session IDs use 256 bits of cryptographic randomness (32 bytes, hex-encoded)
- Invalid or expired sessions receive `404 Not Found` — no information leak
- `DELETE` without session header receives `400 Bad Request`

## [1.2.1] — 2026-10-08

### Changed

- Removed unimplemented capability advertisements from `initialize` response:
  `listChanged` (tools, resources, prompts) and `subscribe` (resources) are
  no longer advertised. These features are not yet implemented — advertising
  them would cause clients to attempt to use them and fail silently
- Version bumped from 1.2.0 to 1.2.1

### Added

- **Cursor-based pagination** for `tools/list`, `resources/list`, and
  `prompts/list` per MCP 2025-06-18 spec. Clients pass a `cursor` parameter;
  the server returns `nextCursor` if more items are available. Default page
  size is 100 items
- **`notifications/cancelled`** — client-initiated cancellation notification
  (MCP 2025-06-18). Logged and acknowledged; tool execution cancellation
  is handled via existing context timeouts

### Security

- Honesty in capability advertisements: the server no longer claims to
  support features it doesn't implement. This prevents clients from relying
  on non-existent subscription or change-notification behavior


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