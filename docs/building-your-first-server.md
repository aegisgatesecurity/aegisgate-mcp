# Building Your First Secure MCP Server

> **AegisGate MCP** is a product of AegisGate Security, LLC.
>
> **License:** Apache-2.0 &nbsp;|&nbsp; **Version:** 1.4.1 &nbsp;|&nbsp; **Go:** 1.26+ &nbsp;|&nbsp; **Dependencies:** Zero external runtime dependencies

This tutorial walks you through building a complete, production-ready MCP server with AegisGate MCP — from registering custom tools to enrolling agents with RBAC, configuring security policies, and connecting a real MCP client.

**Time to complete:** 15 minutes  
**What you'll build:** A secure MCP server with a custom "weather lookup" tool, RBAC-enrolled agents, policy rules, and all 22 security layers active

---

## Prerequisites

```bash
go version    # 1.26+ required
git --version # any recent version
```

## Step 1: Create Your Project

```bash
mkdir my-secure-mcp && cd my-secure-mcp
go mod init my-secure-mcp
```

Add AegisGate MCP as a dependency:

```bash
go get github.com/aegisgatesecurity/aegisgate-mcp
```

> **Note:** AegisGate MCP has zero external dependencies. The only `require` directive in your go.mod will be AegisGate MCP itself.

## Step 2: Write the Server

Create `main.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	mcp "github.com/aegisgatesecurity/aegisgate-mcp"
)

func main() {
	addr := flag.String("addr", ":8081", "Listen address")
	flag.Parse()

	// 1. Configure the server with secure defaults
	cfg := mcp.DefaultServerConfig()
	cfg.Address = *addr
	cfg.AuthToken = "my-secret-bearer"

	// 2. Create the server
	srv, err := mcp.NewSecuredMCPServer(cfg)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	// 3. Register a custom tool: weather lookup
	srv.RegisterTool(mcp.Tool{
		Name:        "get_weather",
		Description: "Get current weather for a city",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"city": {
					"type": "string",
					"description": "City name, e.g. 'San Francisco'"
				}
			},
			"required": ["city"]
		}`),
	})

	// 4. Register the tool handler
	srv.RegisterToolHandler("get_weather", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		var args struct {
			City string `json:"city"`
		}
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}

		// Simulated weather data (replace with real API call)
		return map[string]interface{}{
			"city":        args.City,
			"temperature": "72°F",
			"condition":   "Sunny",
			"humidity":    "45%",
		}, nil
	})

	// 5. Enroll an agent with RBAC permissions
	srv.RegisterAgent(mcp.Agent{
		ID:       "my-assistant",
		MaxTier:  mcp.TierStandard,
		Tools:    []string{"get_weather", "ping", "echo"},
		Policies: []string{"default"},
	})

	// 6. Load default security policies (22 layers)
	srv.LoadDefaultPolicies()

	// 7. Add a custom policy rule: block requests from non-work hours
	srv.AddPolicyRule(mcp.PolicyRule{
		Name:     "work-hours-only",
		Priority: 10,
		Action:   mcp.ActionAllow,
		Condition: func(req *mcp.PolicyRequest) bool {
			// In production, check time-of-day here
			return true // allow for demo
		},
	})

	// 8. Start the server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := srv.Start(ctx); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	fmt.Printf("Secure MCP server running on %s\n", *addr)
	fmt.Println("Tools: get_weather, ping, echo")
	fmt.Println("Security: 22 layers active (regex, ML, RBAC, policy, audit)")
	fmt.Println("Press Ctrl+C to stop")

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	cancel()
	fmt.Println("\nShutting down...")
}
```

## Step 3: Build and Run

```bash
go build -o my-mcp-server .
./my-mcp-server --addr :8081
```

Output:

```
Secure MCP server running on :8081
Tools: get_weather, ping, echo
Security: 22 layers active (regex, ML, RBAC, policy, audit)
Press Ctrl+C to stop
```

## Step 4: Test with curl (Streamable HTTP)

Send an `initialize` request:

```bash
curl -s http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

Response (with `Mcp-Session-Id` header):

```
HTTP/1.1 200 OK
Content-Type: application/json
Mcp-Session-Id: a1b2c3d4e5f6...

{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"aegisgate-mcp","version":"1.4.1"},...},"id":1}
```

Now call your tool (include the session ID):

```bash
curl -s http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: a1b2c3d4e5f6..." \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_weather","arguments":{"city":"San Francisco"}},"id":2}'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"city\":\"San Francisco\",\"temperature\":\"72°F\",\"condition\":\"Sunny\",\"humidity\":\"45%\"}"
      }
    ]
  },
  "id": 2
}
```

## Step 5: Connect Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-secure-mcp": {
      "command": "/path/to/my-mcp-server",
      "args": ["--addr", ":8081", "--transport", "stdio"]
    }
  }
}
```

Restart Claude Desktop. Your `get_weather` tool will appear alongside the built-in tools.

## Step 6: Connect Cursor

Start the server in HTTP mode:

```bash
./my-mcp-server --addr :8081 --transport http
```

In Cursor Settings → MCP Servers → Add:

| Field | Value |
|-------|-------|
| **Name** | `my-secure-mcp` |
| **Type** | `url` |
| **URL** | `http://localhost:8081/mcp` |

## What's Happening Under the Hood

Every request passes through 22 security layers before reaching your tool handler:

```
Client Request
    ↓
[1] Authentication (Bearer token)
    ↓
[2] Input Scanning — Layer 1: Regex (30 patterns)
    ↓
[3] Input Scanning — Layer 2: ATLAS technique mapping
    ↓
[4] Input Scanning — Layer 3: CharCNN-BiLSTM ML detection
    ↓
[5] Tool Poisoning Detection
    ↓
[6] RBAC — Is this agent allowed to call this tool?
    ↓
[7] Policy Engine — Custom rules (work-hours, rate limits, etc.)
    ↓
[8] Tool Handler executes
    ↓
[9] Response Scanning — PII/secret redaction
    ↓
[10] Audit Logging — Full request/response recorded
    ↓
Client Response
```

If any layer blocks the request, the tool handler never executes. The client receives a security denial with the reason.

## Next Steps

- **Add more tools**: Call `srv.RegisterTool()` and `srv.RegisterToolHandler()` for each new tool
- **Add RBAC tiers**: Use `mcp.TierRestricted`, `mcp.TierStandard`, `mcp.TierElevated` to control tool access
- **Enable TLS**: See the [TLS/mTLS guide](how-to-guides.md#4-how-to-configure-tlsmtls)
- **Enable ML detection**: Build with `CGO_ENABLED=1` for full neural threat detection (see [Deployment Guide](deployment-guide.md))
- **Deploy with Docker**: See the [Deployment Guide](deployment-guide.md) for container orchestration

## Further Reading

| Resource | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Full installation and quick start |
| [How-To Guides](how-to-guides.md) | 10 guides covering embedding, tools, TLS, policies, and more |
| [Deployment Guide](deployment-guide.md) | Docker, Kubernetes, and production deployment |
| [Admin Guide](admin-guide.md) | Runtime administration and monitoring |
| [Cursor Integration](integrating-with-cursor.md) | Streamable HTTP transport guide |
| [OWASP MCP Top 10](owasp-mcp-top-10.md) | How AegisGate MCP maps to OWASP MCP security risks |