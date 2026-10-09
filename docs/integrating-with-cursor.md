# Integrating with Cursor via Streamable HTTP

> **AegisGate MCP** is a product of AegisGate Security, LLC.
>
> **License:** Apache-2.0 &nbsp;|&nbsp; **Version:** 1.4.2 &nbsp;|&nbsp; **Go:** 1.26+ &nbsp;|&nbsp; **Dependencies:** Zero external runtime dependencies

Cursor supports MCP servers via Streamable HTTP transport. AegisGate MCP provides a full Streamable HTTP implementation with SSE streaming support and Mcp-Session-Id session management (MCP protocol 2025-06-18).

This guide walks you through connecting Cursor to AegisGate MCP.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **AegisGate MCP binary** | Built from source or downloaded from [releases](https://github.com/aegisgatesecurity/aegisgate-mcp/releases) |
| **Cursor** | Version 0.42+ (MCP support) |
| **Port 8081** | Available on localhost (or change with `--addr`) |

## Step 1: Start AegisGate MCP in HTTP Mode

```bash
./mcp-server --transport http --demo --addr :8081
```

You should see:

```
AegisGate MCP server starting...
  Transport: streamable-http
  Address:   :8081
  Mode:      demo
  Auth:      disabled
```

The server now accepts MCP requests at `http://localhost:8081/mcp`.

### With Authentication

```bash
./mcp-server --transport http --demo --addr :8081 --token my-secret-bearer
```

### With TLS

```bash
./mcp-server --transport http --demo --addr :8081 \
  --tls --tls-cert server.pem --tls-key server.key
```

## Step 2: Configure Cursor

Open Cursor Settings → MCP Servers → Add New MCP Server:

| Field | Value |
|-------|-------|
| **Name** | `aegisgate-mcp` |
| **Type** | `url` |
| **URL** | `http://localhost:8081/mcp` |

Or edit Cursor's MCP configuration file directly:

```json
{
  "mcpServers": {
    "aegisgate-mcp": {
      "url": "http://localhost:8081/mcp"
    }
  }
}
```

### With Authentication

If you started the server with `--token`, add the Authorization header:

```json
{
  "mcpServers": {
    "aegisgate-mcp": {
      "url": "http://localhost:8081/mcp",
      "headers": {
        "Authorization": "Bearer my-secret-bearer"
      }
    }
  }
}
```

## Step 3: Verify the Connection

1. Restart Cursor
2. Open a new chat
3. The three demo tools (`ping`, `system_info`, `echo`) should appear as available MCP tools
4. Try: "Use the ping tool from aegisgate-mcp"

## How Session Management Works

AegisGate MCP implements the Mcp-Session-Id header (MCP 2025-06-18 spec):

1. **Initialize**: Cursor sends `initialize` → server responds with `Mcp-Session-Id: <256-bit ID>` header
2. **Subsequent requests**: Cursor includes `Mcp-Session-Id: <ID>` in all following requests
3. **Session expiry**: Sessions expire after 30 minutes of inactivity
4. **Session termination**: Cursor sends `DELETE /mcp` with the session ID to terminate

This happens automatically — Cursor handles session IDs without manual configuration.

## SSE Streaming

AegisGate MCP supports SSE responses. If Cursor sends `Accept: text/event-stream`, the server responds with:

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

data: {"jsonrpc":"2.0","result":{...},"id":1}
```

If Cursor doesn't request SSE, the server falls back to standard `application/json` responses. Both modes are fully supported.

## Docker Deployment

If you prefer to run AegisGate MCP in a container:

```bash
docker pull ghcr.io/aegisgatesecurity/aegisgate-mcp:1.4.2
docker run -d --name aegisgate-mcp -p 8081:8081 \
  ghcr.io/aegisgatesecurity/aegisgate-mcp:1.4.2 \
  --transport http --demo --addr :8081
```

Then point Cursor at `http://localhost:8081/mcp`.

## Troubleshooting

### Connection refused

- Verify the server is running: `curl http://localhost:8081/mcp -X POST -d '{}' -H "Content-Type: application/json"`
- Check the port: `lsof -i :8081`
- Try a different port: `--addr :9091`

### 404 Not Found

- Ensure you're hitting `/mcp` not the root: `http://localhost:8081/mcp`
- Verify the server is in HTTP mode (not TCP or stdio)

### Authentication failed (-32001)

- The `--token` value must match the `Authorization: Bearer` header exactly
- Check for trailing whitespace in the token

### Session expired (404)

- Sessions expire after 30 minutes of inactivity
- Cursor will automatically re-initialize a new session