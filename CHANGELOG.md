# Changelog

All notable changes to AegisGate MCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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