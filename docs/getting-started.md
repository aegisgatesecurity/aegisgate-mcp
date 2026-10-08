# Getting Started with AegisGate MCP

> **AegisGate MCP** is a product of AegisGate Security, LLC.
>
> **License:** Apache-2.0 &nbsp;|&nbsp; **Version:** 1.1.0 &nbsp;|&nbsp; **Go:** 1.26+ &nbsp;|&nbsp; **Dependencies:** Zero external runtime dependencies

AegisGate MCP is a security-first Model Context Protocol (MCP) server designed for secure AI agent tool use across any environment. It provides tool execution, role-based access control (RBAC), policy enforcement, audit logging, and neural threat detection out of the box — all in a single Go binary with zero external module dependencies.

This guide walks you through installing, running, and testing the server from scratch.

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| **Go** | 1.26 | Required for building from source or using as a module dependency |
| **Git** | any recent version | Required for cloning the repository |
| **Docker** *(optional)* | any recent version | Only needed for containerized deployment |

Verify your environment:

```bash
go version    # should print go1.26 or later
git --version
docker --version   # optional
```

---

## Installation

### From Source

Clone the repository and build the server binary:

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-mcp.git
cd aegisgate-mcp
go build -o mcp-server ./cmd/mcp-server
```

After the build completes you will have an `mcp-server` executable in the current directory.

> **Note:** The project has zero external module dependencies — all third-party code (ONNX Runtime, Unicode normalization) is vendored into `internal/`, `lib/`, and `models/`. No `go mod download` step is needed.

### Docker

A `Dockerfile` is included for containerized deployments. The default build
includes the vendored ONNX Runtime and CharCNN-BiLSTM v13 model for full
neural threat detection:

```bash
# Full ML-enabled build (~135 MB)
docker build -t aegisgate-mcp .
docker run -p 8081:8081 aegisgate-mcp --demo

# Heuristic-only build (~8 MB, no ONNX)
docker build --build-arg CGO_ENABLED=0 -t aegisgate-mcp:lite .
```

### As a Go Module Dependency

To embed AegisGate MCP directly in your own Go application:

```bash
go get github.com/aegisgatesecurity/aegisgate-mcp
```

Then import the packages you need in your code:

```go
import (
    "github.com/aegisgatesecurity/aegisgate-mcp/pkg/server"
    "github.com/aegisgatesecurity/aegisgate-mcp/pkg/tools"
)
```

> See the **How-To Guides** for a complete walkthrough on embedding and registering custom tools.

---

## First Run

The sections below use the built-in `--demo` flag, which starts the server with three pre-registered tools and no authentication required. This is the fastest way to verify your installation.

### 1. Start the Server (TCP Mode)

```bash
./mcp-server --demo
```

This starts the server listening on **`127.0.0.1:8081`** in TCP mode with three demo tools:

| Tool | Description | Required Parameters |
|---|---|---|
| `ping` | Returns `"pong"` | none |
| `system_info` | Returns basic system information | none |
| `echo` | Echoes back a provided message | `message` (string) |

You should see a startup log similar to:

```
AegisGate MCP server starting...
  Transport: tcp
  Address:   :8081
  Mode:      demo
  Auth:      disabled
```

### 2. Verify It Works

Send an MCP `initialize` request using `netcat` (or any JSON-RPC 2.0 client):

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}},"id":1}' | nc 127.0.0.1 8081
```

**Expected response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "aegisgate-mcp",
      "version": "1.1.0"
    },
    "capabilities": {
      "tools": {}
    }
  },
  "id": 1
}
```

The key fields to confirm:

- `serverInfo.name` is `"aegisgate-mcp"`
- `serverInfo.version` is `"1.1.0"`
- `protocolVersion` matches the value you sent

### 3. List Available Tools

Request the full tool catalog:

```bash
echo '{"jsonrpc":"2.0","method":"tools/list","id":2}' | nc 127.0.0.1 8081
```

**Expected response** (abbreviated):

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "ping",
        "description": "Health check tool — returns pong",
        "inputSchema": {
          "type": "object",
          "properties": {},
          "required": []
        }
      },
      {
        "name": "system_info",
        "description": "Returns basic system information",
        "inputSchema": {
          "type": "object",
          "properties": {},
          "required": []
        }
      },
      {
        "name": "echo",
        "description": "Echoes back the provided message",
        "inputSchema": {
          "type": "object",
          "properties": {
            "message": {
              "type": "string",
              "description": "The message to echo back"
            }
          },
          "required": ["message"]
        }
      }
    ]
  },
  "id": 2
}
```

You should see all **3 tools**: `ping`, `system_info`, and `echo`.

### 4. Call a Tool — `ping`

Call the simplest tool, which takes no arguments:

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ping","arguments":{}},"id":3}' | nc 127.0.0.1 8081
```

**Expected response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "pong"
      }
    ]
  },
  "id": 3
}
```

The `text` field should contain `"pong"`.

### 5. Call a Tool — `echo` (with required parameter)

The `echo` tool requires a `message` argument:

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}},"id":4}' | nc 127.0.0.1 8081
```

**Expected response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "hello"
      }
    ]
  },
  "id": 4
}
```

The server echoes back the exact message you sent: `"hello"`.

### 6. Test Input Validation — Missing Required Parameter

Call `echo` without supplying the required `message` argument:

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{}},"id":5}' | nc 127.0.0.1 8081
```

**Expected response (error):**

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Missing required parameters: [message]"
  },
  "id": 5
}
```

The server rejects the call and tells you exactly which parameter is missing. This is the built-in schema validation that AegisGate MCP applies to every tool before execution.

---

## stdio Mode (for Claude Desktop, Cursor, etc.)

For integration with AI clients that communicate over standard input/output (such as Claude Desktop or Cursor), use the `stdio` transport:

```bash
./mcp-server --transport stdio --demo
```

In this mode the server:

- **Reads** JSON-RPC 2.0 messages from `stdin`
- **Writes** responses to `stdout`
- Sends diagnostics and logs to `stderr` (so they don't interfere with the protocol stream)

### Claude Desktop Configuration

Add the following to your Claude Desktop config file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aegisgate-mcp": {
      "command": "/path/to/mcp-server",
      "args": ["--transport", "stdio", "--demo"]
    }
  }
}
```

Restart Claude Desktop, and the three demo tools will appear as available actions.

---

## With Authentication

Enable bearer-token authentication by passing the `--token` flag:

```bash
./mcp-server --demo --token my-secret-bearer
```

Now the server rejects any connection that does not provide valid auth credentials. Clients must include the token in the `initialize` request's `params.auth` field:

```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": {
      "name": "test",
      "version": "1.0"
    },
    "auth": {
      "token": "my-secret-bearer"
    }
  },
  "id": 1
}
```

> **Security note:** In production, always use authentication. The `--token` flag is a simple bearer-token mechanism suitable for development and testing. For production RBAC with multiple roles and scoped permissions, see the **Admin Guide**.

---

## Health Check

For production deployments and container orchestration (e.g., Kubernetes liveness/readiness probes), start the server with a dedicated health-check HTTP endpoint:

```bash
./mcp-server --demo --health-addr :8082
```

This opens a separate HTTP listener on port `8082` alongside the main MCP listener on `8081`. The health server exposes three endpoints:

### `GET /healthz` — Liveness

Returns `200 OK` if the server process is running and able to accept connections.

```bash
curl http://127.0.0.1:8082/healthz
```

```
{"status":"ok"}
```

### `GET /readyz` — Readiness

Returns `200 OK` if the server is fully initialized and ready to handle MCP requests.

```bash
curl http://127.0.0.1:8082/readyz
```

```
{"status":"ready"}
```

### `GET /stats` — Runtime Statistics

Returns JSON with runtime metrics including registered tools, active sessions/connections, guardrail settings, and audit entries.

```bash
curl http://127.0.0.1:8082/stats
```

```json
{
  "tools_registered": 3,
  "active_sessions": 2,
  "active_connections": 5,
  "max_connections": 1000,
  "guardrails": {
    "rate_limit_rpm": 60,
    "max_sessions": 50
  },
  "audit_entries": 12,
  "trusted_keys": 0,
  "policy_rules": 4
}
```

> **Tip:** In Docker or Kubernetes, point your liveness probe at `/healthz` and your readiness probe at `/readyz`.

---

## Quick Reference — Command-Line Flags

| Flag | Description | Default |
|---|---|---|
| `--demo` | Start with 3 built-in demo tools and no auth | `false` |
| `--transport` | Transport mode: `tcp` or `stdio` | `tcp` |
| `--addr` | TCP listen address | `:8081` |
| `--max-connections` | Max concurrent TCP connections (-1 = unlimited) | `1000` |
| `--token` | Bearer token for authentication *(optional)* | none |
| `--health-addr` | HTTP health-check listener address *(optional)* | none |

---

## Troubleshooting

### "connection refused" when using `nc`

Make sure the server is still running. Each `nc` invocation opens a new connection and closes it after receiving the response. The server handles multiple sequential connections but you may need to keep the server process alive in a separate terminal.

### Port already in use

If port `8081` is already in use, specify a different address:

```bash
./mcp-server --demo --addr :9091
```

Then update your `nc` commands to target the new port.

### `nc` not installed

Install it via your package manager:

```bash
# Debian / Ubuntu
sudo apt install netcat-openbsd

# macOS (Homebrew)
brew install netcat

# Or use a JSON-RPC client of your choice — any MCP-compatible client works
```

---

## Next Steps

Now that you have the server running and responding, explore the full feature set:

| Guide | What You'll Learn |
|---|---|
| **Deployment Guide** | Docker configuration, TLS termination, reverse proxy setup, and production hardening |
| **Admin Guide** | RBAC roles and permissions, the policy engine, audit logging, and multi-tenant configuration |
| **How-To Guides** | Embedding AegisGate MCP as a library, writing custom tools, and integrating with security-sensitive environments |

---

*Copyright © AegisGate Security, LLC. Licensed under the Apache License, Version 2.0.*