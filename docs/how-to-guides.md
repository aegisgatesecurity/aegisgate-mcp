# AegisGate MCP How-To Guides

**Product:** AegisGate MCP — A security-first MCP server for AI agents  
**Trademark:** AegisGate MCP is a product of AegisGate Security, LLC  
**License:** Apache-2.0  
**Version:** 1.4.2  
**Go Module:** `github.com/aegisgatesecurity/aegisgate-mcp`  
**Go Version:** 1.26+  
**Dependencies:** Zero external runtime dependencies  

---

## Table of Contents

1. [How to Embed AegisGate MCP as a Library](#1-how-to-embed-aegisgate-mcp-as-a-library)
2. [How to Register Custom Tools](#2-how-to-register-custom-tools)
3. [How to Use stdio Transport with Claude Desktop](#3-how-to-use-stdio-transport-with-claude-desktop)
4. [How to Configure TLS/mTLS](#4-how-to-configure-tlsmtls)
5. [How to Sign Requests (Anti-Forgery)](#5-how-to-sign-requests-anti-forgery)
6. [How to Use the Policy Engine](#6-how-to-use-the-policy-engine)
7. [How to Use the Demo Tools](#7-how-to-use-the-demo-tools)
8. [How to Write a JSON Config File](#8-how-to-write-a-json-config-file)
9. [How to Run the Pentest Suite](#9-how-to-run-the-pentest-suite)
10. [How to Run Tests](#10-how-to-run-tests)

---

## 1. How to Embed AegisGate MCP as a Library

AegisGate MCP can be embedded directly into any Go application as a library. The entire lifecycle — configuration, tool registration, agent enrollment, policy enforcement, and graceful shutdown — is driven through a single `SecuredMCPServer` instance.

### Overview

| Step | Method | Purpose |
|------|--------|---------|
| 1 | `mcp.DefaultServerConfig()` | Obtain a config with safe defaults |
| 2 | `mcp.NewSecuredMCPServer(cfg)` | Construct the server |
| 3 | `srv.RegisterTool(...)` | Register tool metadata + JSON Schema |
| 4 | `srv.RegisterToolHandler(...)` | Register the Go handler function |
| 5 | `srv.RegisterAgent(...)` | Enroll an agent with RBAC permissions |
| 6 | `srv.LoadDefaultPolicies()` | Load built-in policy rules |
| 7 | `srv.AddPolicyRule(...)` | Add custom policy rules |
| 8 | `srv.AddTrustedKey(...)` | Add a trusted ECDSA public key |
| 9 | `srv.Start(ctx)` | Begin serving |
| 10 | `srv.Stop()` | Graceful shutdown |

### Full Example

```go
package main

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "fmt"
    "log/slog"
    "os"
    "os/signal"
    "syscall"

    mcp "github.com/aegisgatesecurity/aegisgate-mcp"
)

func main() {
    // --- 1. Configure the server ---
    cfg := mcp.DefaultServerConfig()
    cfg.Address = ":8081"
    cfg.AuthToken = "my-bearer-token"
    cfg.AuditLogPath = "/var/log/mcp-audit.json"
    cfg.ScanResponses = true
    cfg.BlockOnPII = true
    cfg.BlockOnSecrets = true

    // --- 2. Create the secured server ---
    srv, err := mcp.NewSecuredMCPServer(cfg)
    if err != nil {
        panic(err)
    }

    // --- 3. Register a custom tool (metadata + input schema) ---
    srv.RegisterTool("get_temperature", "Read temperature sensor", 20, map[string]interface{}{
        "type": "object",
        "properties": map[string]interface{}{
            "sensor_id": map[string]interface{}{
                "type": "string",
                "description": "Sensor identifier",
            },
        },
        "required": []interface{}{"sensor_id"},
    })

    // --- 4. Register the tool handler (execution function) ---
    srv.RegisterToolHandler("get_temperature", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
        sensorID := params["sensor_id"].(string)
        return fmt.Sprintf("Sensor %s: 72.5°F", sensorID), nil
    })

    // --- 5. Register an agent with restricted role ---
    srv.RegisterAgent("agent-001", "Plant Floor Agent", mcp.RoleRestricted, []mcp.ToolPermission{
        {ToolName: "get_temperature", Allowed: true},
        {ToolName: "ping", Allowed: true},
    })

    // --- 6. Load built-in policy rules ---
    srv.LoadDefaultPolicies()

    // --- 7. Add a custom policy rule ---
    srv.AddPolicyRule(mcp.PolicyRule{
        Name:     "block-write-tools-weekend",
        Priority: 15,
        Action:   mcp.PolicyDeny,
        Condition: mcp.Condition{
            Roles:      []mcp.AgentRole{mcp.RoleRestricted, mcp.RoleStandard},
            RiskScore:  50,
            TimeWindow: &mcp.TimeWindow{Days: []string{"Sat", "Sun"}},
        },
    })

    // --- 8. Add a trusted key for request signature verification ---
    privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    pubKeySEC1 := elliptic.Marshal(elliptic.P256(), privKey.X, privKey.Y)
    srv.AddTrustedKey("plant-agent-key", pubKeySEC1)

    // --- 9. Start the server with context-based lifecycle ---
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigCh
        cancel()
    }()

    if err := srv.Start(ctx); err != nil {
        slog.Error("server error", "error", err)
    }

    // --- 10. Graceful shutdown ---
    srv.Stop()
}
```

### Configuration Fields Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Address` | `string` | `":8080"` | Listen address for HTTP transport |
| `AuthToken` | `string` | `""` | Bearer token for client authentication |
| `AuditLogPath` | `string` | `""` | Path to append-only audit log (JSON Lines) |
| `ScanResponses` | `bool` | `false` | Enable PII / secret scanning of tool responses |
| `BlockOnPII` | `bool` | `false` | Block responses containing detected PII |
| `BlockOnSecrets` | `bool` | `false` | Block responses containing detected secrets |

---

## 2. How to Register Custom Tools

Tool registration in AegisGate MCP is a two-step process. This separation allows the server to expose tool metadata (for `tools/list` responses) before or independently of the handler implementation.

### Two-Step Process

#### Step 1 — Register Tool Metadata

```go
srv.RegisterTool("read_sensor", "Read a sensor value", 20, map[string]interface{}{
    "type": "object",
    "properties": map[string]interface{}{
        "sensor_id": map[string]interface{}{
            "type": "string",
            "description": "The sensor identifier",
        },
        "unit": map[string]interface{}{
            "type": "string",
            "enum": []interface{}{"celsius", "fahrenheit"},
            "default": "celsius",
        },
    },
    "required": []interface{}{"sensor_id"},
})
```

**Signature:**

```go
func (s *SecuredMCPServer) RegisterTool(name, description string, riskLevel int, inputSchema map[string]interface{})
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `string` | Unique tool name (e.g., `"read_sensor"`) |
| `description` | `string` | Human-readable description shown to LLMs |
| `riskLevel` | `int` | Integer 1–100 indicating operational risk |
| `inputSchema` | `map[string]interface{}` | JSON Schema describing accepted parameters |

#### Step 2 — Register Tool Handler

```go
srv.RegisterToolHandler("read_sensor", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
    sensorID, ok := params["sensor_id"].(string)
    if !ok {
        return nil, fmt.Errorf("sensor_id must be a string")
    }
    // Read sensor...
    return map[string]interface{}{
        "sensor_id": sensorID,
        "value":     23.5,
        "unit":      "celsius",
    }, nil
})
```

**Signature:**

```go
func (s *SecuredMCPServer) RegisterToolHandler(name string, handler func(ctx context.Context, params map[string]interface{}) (interface{}, error))
```

The handler receives a `context.Context` (which carries agent identity, request metadata, and cancellation) and a `map[string]interface{}` of validated parameters. It returns an arbitrary JSON-serializable value or an error.

### Risk Levels

Risk levels are integers from 1 to 100 and drive both RBAC permission grants and policy engine decisions.

| Range | Category | Examples |
|-------|----------|----------|
| 1–30 | Low (read-only) | `ping`, `get_temperature`, `system_info` |
| 31–60 | Medium (write operations) | `set_valve`, `update_setpoint` |
| 61–100 | High (dangerous operations) | `execute_shell`, `reboot_controller` |

### Parameter Validation

The server automatically validates incoming `tools/call` requests against the registered `inputSchema` **before** the handler is invoked:

- **Required fields:** Every field listed in `"required"` must be present in the `params` object. If any required field is missing, the server returns a JSON-RPC error and the handler is never called.
- **Type checking:** Field types declared in the schema (e.g., `"type": "string"`) are validated against the provided values.

This means handlers can safely assume that required parameters are present and correctly typed — additional defensive checks (as shown in the example above) are recommended for robustness but not strictly required for required fields.

---

## 3. How to Use stdio Transport with Claude Desktop

AegisGate MCP supports stdio transport for integration with Claude Desktop and other MCP-compatible clients that launch the server as a subprocess.

### Configuration File Location

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

### Configuration File

```json
{
  "mcpServers": {
    "aegisgate": {
      "command": "/usr/local/bin/mcp-server",
      "args": ["--transport", "stdio", "--demo", "--token", "my-secret"]
    }
  }
}
```

### Field Reference

| Field | Description |
|-------|-------------|
| `command` | Absolute path to the `mcp-server` binary |
| `args` | Command-line arguments passed to the binary |
| `--transport stdio` | Select stdio transport (reads JSON-RPC from stdin, writes to stdout) |
| `--demo` | Register the three built-in demo tools (`ping`, `system_info`, `echo`) |
| `--token` | Set the bearer authentication token |

### Authentication Requirement

When `--token` is set, the client **must** include the token in the `initialize` request. Claude Desktop handles this automatically when the token is provided in the server configuration. If authentication fails, the server rejects all subsequent requests with a `-32001` authentication error.

After updating the configuration file, restart Claude Desktop for the changes to take effect.

---

## 4. How to Configure TLS/mTLS

AegisGate MCP supports TLS for encrypted transport and mutual TLS (mTLS) for client certificate authentication — essential for secure network segments where plaintext traffic is prohibited.

### Generate a Certificate Authority

```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.pem -days 3650 -subj "/CN=AegisGate CA"
```

### Generate a Server Certificate

```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=mcp-server"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365
```

### Generate a Client Certificate (for mTLS)

```bash
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=mcp-client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 365
```

### Start the Server with TLS

```bash
./mcp-server --tls --tls-cert server.pem --tls-key server.key
```

### Start the Server with mTLS

```bash
./mcp-server \
    --tls \
    --tls-cert server.pem \
    --tls-key server.key \
    --tls-client-ca ca.pem \
    --tls-min-version 1.3
```

### TLS Command-Line Flags

| Flag | Description |
|------|-------------|
| `--tls` | Enable TLS mode |
| `--tls-cert` | Path to server certificate (PEM) |
| `--tls-key` | Path to server private key (PEM) |
| `--tls-client-ca` | Path to CA certificate for client verification (enables mTLS) |
| `--tls-min-version` | Minimum TLS version: `1.2` or `1.3` (default: `1.2`) |

### Client-Side TLS (Go Example)

The following Go client connects to the server with TLS and presents a client certificate for mTLS:

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    "os"
)

func main() {
    // Load client certificate
    cert, err := tls.LoadX509KeyPair("client.pem", "client.key")
    if err != nil {
        panic(err)
    }

    // Load CA certificate for server verification
    caCert, err := os.ReadFile("ca.pem")
    if err != nil {
        panic(err)
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)

    // Configure TLS client
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caPool,
        MinVersion:   tls.VersionTLS13,
    }

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    // Make an authenticated request
    req, _ := http.NewRequest("POST", "https://mcp-server:8080/mcp", nil)
    req.Header.Set("Authorization", "Bearer my-bearer-token")
    req.Header.Set("Content-Type", "application/json")

    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("Response: %s\n", body)
}
```

> **Security Best Practice:** Always use TLS 1.3 in production environments. Store private keys (`*.key`) with restrictive permissions (`chmod 600`) and never commit them to version control.

---

## 5. How to Sign Requests (Anti-Forgery)

AegisGate MCP supports ECDSA P-256 request signing to prevent request forgery and replay attacks. When trusted keys are registered on the server, signed requests are verified against the trusted key store before the request is processed.

### Generate a Key Pair

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
)

func generateKey() *ecdsa.PrivateKey {
    privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    return privKey
}
```

### Sign a Request

```go
req := &mcp.JSONRPCRequest{
    JSONRPC: "2.0",
    Method:  "tools/call",
    Params:  params,
    ID:      1,
}
err := mcp.SignRequest(req, "my-key-id", privKey)
if err != nil {
    panic(err)
}
// req.Signature and req.KeyID are now set
```

**Signature:**

```go
func SignRequest(req *JSONRPCRequest, keyID string, privKey *ecdsa.PrivateKey) error
```

### Add Trusted Key on the Server

```go
pubKeySEC1 := elliptic.Marshal(elliptic.P256(), privKey.X, privKey.Y)
srv.AddTrustedKey("my-key-id", pubKeySEC1)
```

The server stores the SEC1-encoded public key indexed by the provided key ID. When a request arrives with a `KeyID` and `Signature`, the server looks up the trusted key and verifies the signature.

### How the Signing Process Works

The `SignRequest` function performs the following steps internally:

1. **Zero signature fields** — The `KeyID` and `Signature` fields on the request are temporarily set to empty/zero values so they do not influence the hash.
2. **Canonicalize the request** — The request is serialized to JSON with sorted keys (canonical JSON) to ensure deterministic output across platforms and encoders.
3. **Hash** — A SHA-256 hash is computed over the canonical JSON byte sequence.
4. **Sign** — The hash is signed using ECDSA on the P-256 curve. The resulting signature is encoded in ASN.1 DER format.
5. **Encode** — The DER signature is hex-encoded and assigned to `req.Signature`. The `req.KeyID` field is set to the provided key identifier.

### Verification on the Server Side

When a request arrives:

1. The server checks whether `req.KeyID` matches any registered trusted key.
2. If a match is found, the server reconstructs the canonical JSON (with signature fields zeroed), recomputes the SHA-256 hash, and verifies the ECDSA signature.
3. If verification fails, the request is rejected with an authentication error and logged to the audit trail.

> **Note:** Request signing is complementary to bearer token authentication. For maximum security in OT environments, use both: the bearer token authenticates the agent identity, and the signature proves the request originated from a holder of the private key.

---

## 6. How to Use the Policy Engine

The policy engine evaluates rules before every `tools/call` request. Rules can allow, deny, or allow-with-alert based on agent role, risk score, time windows, parameter patterns, and more.

### Load Built-in Rules

```go
srv.LoadDefaultPolicies()
```

This registers the default policy rule set, which includes baseline protections such as blocking high-risk tools for restricted agents and alerting on suspicious parameter patterns.

### Custom Rules

#### Example 1 — Time-Based Rule: Block Write Tools on Weekends

```go
srv.AddPolicyRule(mcp.PolicyRule{
    Name:     "block-write-tools-weekend",
    Priority: 15,
    Action:   mcp.PolicyDeny,
    Condition: mcp.Condition{
        Roles:      []mcp.AgentRole{mcp.RoleRestricted, mcp.RoleStandard},
        RiskScore:  50,
        TimeWindow: &mcp.TimeWindow{Days: []string{"Sat", "Sun"}},
    },
})
```

This rule denies any tool call from restricted or standard agents where the tool's risk score is 50 or higher, but only on Saturdays and Sundays.

#### Example 2 — Parameter Pattern Rule: Block Internal IP Addresses

```go
srv.AddPolicyRule(mcp.PolicyRule{
    Name:     "block-internal-ip-access",
    Priority: 10,
    Action:   mcp.PolicyDeny,
    Condition: mcp.Condition{
        ParamPattern: map[string]string{
            "target_ip": `^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.`,
        },
    },
})
```

This rule denies any tool call where the `target_ip` parameter matches a private/internal IP address range (RFC 1918). The pattern uses standard Go regexp syntax.

#### Example 3 — Risk Threshold Rule: Alert on High-Risk Tools

```go
srv.AddPolicyRule(mcp.PolicyRule{
    Name:     "alert-high-risk-tools",
    Priority: 20,
    Action:   mcp.PolicyAllowWithAlert,
    Condition: mcp.Condition{
        RiskScore: 70,
    },
})
```

This rule allows tool calls with a risk score of 70 or above but generates an alert in the audit log. Use this for monitoring dangerous operations without blocking them outright.

### Policy Priorities

Rules are evaluated in ascending priority order — **lower number = higher priority**. The first rule whose condition matches the incoming request determines the outcome. If no rule matches, the default action is `PolicyAllow` (subject to RBAC checks).

| Priority | Meaning |
|----------|---------|
| 1–9 | Critical rules (evaluated first) |
| 10–19 | High-priority custom rules |
| 20–49 | Standard rules |
| 50–100 | Low-priority / fallback rules |

> **Tip:** Always assign explicit priorities to custom rules. Rules with the same priority are evaluated in registration order, which can lead to unpredictable behavior.

### Policy Actions

| Action | Constant | Behavior |
|--------|----------|----------|
| Allow | `mcp.PolicyAllow` | Permit the tool call. No alert is generated. |
| Deny | `mcp.PolicyDeny` | Reject the tool call. A denial record is written to the audit log. |
| Allow with Alert | `mcp.PolicyAllowWithAlert` | Permit the tool call but log an alert to the audit log for review. |

### PolicyRule Structure

```go
type PolicyRule struct {
    Name      string    // Unique rule name
    Priority  int       // Evaluation order (lower = earlier)
    Action    PolicyAction // Allow, Deny, or AllowWithAlert
    Condition Condition  // Match criteria
}

type Condition struct {
    Roles        []AgentRole            // Match agent roles
    RiskScore    int                    // Match tools with risk >= this value
    TimeWindow   *TimeWindow            // Match specific days/hours
    ParamPattern map[string]string      // Match parameter values by regex
}

type TimeWindow struct {
    Days  []string // e.g., ["Sat", "Sun"]
    Hours []int    // e.g., [0, 1, 2, 3, 4, 5] for midnight–6am
}
```

---

## 7. How to Use the Demo Tools

AegisGate MCP includes three built-in demo tools that are registered when the `--demo` flag is passed. These tools are useful for testing, integration validation, and onboarding.

### Start the Server with Demo Tools

```bash
./mcp-server --demo
```

### Available Demo Tools

| Tool | Risk Level | Parameters | Description |
|------|------------|------------|-------------|
| `ping` | 10 | None | Returns `"pong"` |
| `system_info` | 30 | None | Returns Go version, OS, architecture, CPU count, goroutine count, and timestamp |
| `echo` | 20 | `message` (string, required) | Echoes the provided message back |

### Calling Demo Tools via JSON-RPC

#### Ping

```json
{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "ping",
        "arguments": {}
    },
    "id": 1
}
```

**Response:**

```json
{
    "jsonrpc": "2.0",
    "result": "pong",
    "id": 1
}
```

#### System Info

```json
{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "system_info",
        "arguments": {}
    },
    "id": 2
}
```

**Response:**

```json
{
    "jsonrpc": "2.0",
    "result": {
        "go_version": "go1.26.0",
        "os": "linux",
        "arch": "amd64",
        "cpus": 8,
        "goroutines": 4,
        "timestamp": "2026-10-07T14:45:00Z"
    },
    "id": 2
}
```

#### Echo

```json
{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "echo",
        "arguments": {
            "message": "Hello, AegisGate!"
        }
    },
    "id": 3
}
```

**Response:**

```json
{
    "jsonrpc": "2.0",
    "result": "Hello, AegisGate!",
    "id": 3
}
```

> **Note:** The `echo` tool requires the `message` parameter. If it is omitted, the server returns a parameter validation error before the handler is invoked.

---

## 8. How to Write a JSON Config File

AegisGate MCP can be configured via a JSON file passed with the `--config` flag. This is the preferred approach for production deployments where command-line arguments become unwieldy.

### Usage

```bash
./mcp-server --config /etc/aegisgate/config.json
```

### Complete Example

```json
{
    "address": ":8080",
    "auth_token": "prod-bearer-token-change-me",
    "audit_log_path": "/var/log/aegisgate/audit.json",
    "scan_responses": true,
    "block_on_pii": true,
    "block_on_secrets": true,
    "max_request_size": 1048576,
    "rate_limit_per_second": 100,
    "tls": {
        "enabled": true,
        "cert_file": "/etc/aegisgate/certs/server.pem",
        "key_file": "/etc/aegisgate/certs/server.key",
        "client_ca_file": "/etc/aegisgate/certs/ca.pem",
        "min_version": "1.3"
    },
    "agents": [
        {
            "id": "agent-001",
            "name": "Plant Floor Agent",
            "role": "restricted",
            "permissions": [
                { "tool_name": "get_temperature", "allowed": true },
                { "tool_name": "ping", "allowed": true }
            ]
        },
        {
            "id": "agent-002",
            "name": "Supervisor Agent",
            "role": "standard",
            "permissions": [
                { "tool_name": "get_temperature", "allowed": true },
                { "tool_name": "set_valve", "allowed": true },
                { "tool_name": "system_info", "allowed": true }
            ]
        }
    ],
    "policies": [
        {
            "name": "block-high-risk-restricted",
            "priority": 10,
            "action": "deny",
            "condition": {
                "roles": ["restricted"],
                "risk_score": 60
            }
        },
        {
            "name": "alert-write-ops-off-hours",
            "priority": 25,
            "action": "allow_with_alert",
            "condition": {
                "risk_score": 40,
                "time_window": {
                    "days": ["Sat", "Sun"],
                    "hours": [0, 1, 2, 3, 4, 5, 6, 7, 18, 19, 20, 21, 22, 23]
                }
            }
        }
    ],
    "trusted_keys": [
        {
            "key_id": "plant-agent-key",
            "public_key_sec1": "MFkwEwYHKoZIzj0CAQYIKoZIzj0D..."
        }
    ]
}
```

### Field Reference

#### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `address` | `string` | Listen address (e.g., `":8080"`) |
| `auth_token` | `string` | Bearer token for client authentication |
| `audit_log_path` | `string` | Path to the append-only audit log file |
| `scan_responses` | `bool` | Enable PII / secret scanning of tool responses |
| `block_on_pii` | `bool` | Block responses containing detected PII |
| `block_on_secrets` | `bool` | Block responses containing detected secrets |
| `max_request_size` | `int` | Maximum request body size in bytes |
| `rate_limit_per_second` | `int` | Maximum requests per second per client |
| `tls` | `object` | TLS configuration (see below) |
| `agents` | `array` | Agent registrations with RBAC (see below) |
| `policies` | `array` | Policy rules (see below) |
| `trusted_keys` | `array` | Trusted public keys for signature verification |

#### TLS Section

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Enable TLS |
| `cert_file` | `string` | Path to server certificate (PEM) |
| `key_file` | `string` | Path to server private key (PEM) |
| `client_ca_file` | `string` | Path to CA cert for client verification (enables mTLS) |
| `min_version` | `string` | Minimum TLS version: `"1.2"` or `"1.3"` |

#### Agent Section

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique agent identifier |
| `name` | `string` | Human-readable agent name |
| `role` | `string` | Agent role: `"restricted"`, `"standard"`, or `"admin"` |
| `permissions` | `array` | List of tool permissions |
| `permissions[].tool_name` | `string` | Tool name |
| `permissions[].allowed` | `bool` | Whether the agent may call this tool |

#### Policy Section

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Unique rule name |
| `priority` | `int` | Evaluation order (lower = earlier) |
| `action` | `string` | `"allow"`, `"deny"`, or `"allow_with_alert"` |
| `condition.roles` | `array` | Agent roles to match |
| `condition.risk_score` | `int` | Match tools with risk ≥ this value |
| `condition.time_window.days` | `array` | Day names to match (e.g., `["Sat", "Sun"]`) |
| `condition.time_window.hours` | `array` | Hour values (0–23) to match |
| `condition.param_pattern` | `object` | Map of parameter name → regex pattern |

#### Trusted Keys Section

| Field | Type | Description |
|-------|------|-------------|
| `key_id` | `string` | Unique key identifier |
| `public_key_sec1` | `string` | Base64-encoded SEC1 (uncompressed) ECDSA P-256 public key |

### Time Duration Format

Any configuration field that accepts a time duration (e.g., timeouts, rate limit windows) is specified as an integer representing **nanoseconds**. For example:

| Desired Duration | Config Value |
|-------------------|-------------|
| 1 second | `1000000000` |
| 5 seconds | `5000000000` |
| 30 seconds | `30000000000` |
| 1 minute | `60000000000` |
| 5 minutes | `300000000000` |

> **Note:** The integer values are Go `time.Duration` values expressed in nanoseconds. Use the table above as a reference or compute the value as `seconds × 1,000,000,000`.

---

## 9. How to Run the Pentest Suite

AegisGate MCP ships with an automated penetration testing suite designed to validate the server's security posture. The suite is containerized using Docker Compose and produces reports in the `pentest/reports/` directory.

### Prerequisites

- Docker Engine 24+
- Docker Compose v2+
- The `docker-compose.yml` and `pentest/` directory from the repository

### Step 1 — Start the Server

```bash
docker compose up -d
```

This launches the AegisGate MCP server in a container, listening on the configured port.

### Step 2 — Run the Pentest Suite

```bash
docker compose --profile pentest run mcp-pentest /audit/scripts/run_pentest.sh
```

The `--profile pentest` flag activates the pentest service profile, which is separate from the normal server profile.

### Step 3 — View Reports

```bash
ls pentest/reports/
```

Reports are generated as individual files for each test, containing pass/fail status, evidence, and recommendations.

### Test Inventory

The pentest suite includes seven automated tests:

| # | Test Name | Description |
|---|-----------|-------------|
| 1 | Port Scan | Verifies that only the MCP port is exposed — no debugging, metrics, or admin endpoints are listening |
| 2 | Auth Bypass | Sends `tools/list` without first calling `initialize` with an auth token — expects rejection |
| 3 | Brute Force | Submits rapid failed authentication attempts to verify rate limiting and lockout behavior |
| 4 | Shell Injection via STDIO | Sends malformed STDIO payloads containing shell escape sequences and command injection strings |
| 5 | Prompt Injection via Tool Responses | Submits tool responses containing prompt injection payloads — verifies response scanning blocks them |
| 6 | RBAC Escalation | A restricted agent attempts to call admin-only tools — verifies RBAC enforcement denies the calls |
| 7 | Fuzzing | Sends malformed JSON-RPC inputs (truncated, oversized, invalid UTF-8, nested beyond limits) to verify graceful handling |

### Interpreting Results

Each report file contains:

- **Status:** `PASS` or `FAIL`
- **Evidence:** Request/response captures showing the server's behavior
- **Recommendations:** Actionable guidance if the test failed

> **Best Practice:** Run the pentest suite after every configuration change and before any deployment to a production OT network. Integrate it into your CI/CD pipeline as a security gate.

---

## 10. How to Run Tests

AegisGate MCP maintains a comprehensive test suite (335 non-CGO / 333 CGO tests).
Tests can be run in two modes depending on build configuration.

### Run All Tests

```bash
# Non-CGO (heuristic-only, no ONNX)
CGO_ENABLED=0 go test ./... -count=1

# CGO (full ML, requires libonnxruntime.so)
CGO_ENABLED=1 CGO_LDFLAGS="-L$(pwd)/lib -lonnxruntime" go test ./... -count=1
```

The `-count=1` flag disables test result caching, ensuring every test is re-executed.

### Run Tests with Coverage

```bash
CGO_ENABLED=0 go test ./... -coverprofile=cover.out
go tool cover -func=cover.out
```

To generate an HTML coverage report:

```bash
go tool cover -html=cover.out -o cover.html
```

Open `cover.html` in a browser to view line-by-line coverage.

### Run Tests in Verbose Mode

```bash
go test ./... -v -count=1
```

Verbose mode prints every test name and its pass/fail status, which is useful for debugging test failures.

### Run a Specific Test

```bash
go test -run TestRegisterDemoTools -v
```

The `-run` flag accepts a regular expression. Only tests whose names match are executed.

```bash
# Run all tests in a specific package
go test ./internal/security/... -v -count=1

# Run tests matching a pattern across all packages
go test ./... -run "TestPolicy" -v
```

### Common Test Commands

| Command | Purpose |
|---------|---------|
| `go test ./... -count=1 -timeout 120s` | Run all regular tests (no cache) |
| `go test ./... -v -count=1` | Run all tests with verbose output |
| `go test ./... -coverprofile=cover.out` | Run all tests with coverage |
| `go tool cover -func=cover.out` | Show coverage summary by function |
| `go tool cover -html=cover.out` | Generate HTML coverage report |
| `go test -run TestName -v` | Run a single test by name |
| `go test -race -count=1 -timeout 180s ./...` | Run tests with race detector (recommended for development) |
| `go test -tags=load -count=1 -timeout 120s -v ./...` | Run load/break/soak tests |
| `go test -bench=. -benchmem -benchtime=5s ./...` | Run benchmarks for regression tracking |
| `go test -fuzz=FuzzHandleRequest -fuzztime=60s ./...` | Run fuzz testing (60s per target) |

### Test Suite Breakdown

| Category | Count | Description |
|----------|-------|-------------|
| Unit + integration | 327 | Core functionality, RBAC, policy, scanner, audit, transport |
| Load / break / soak | 10 | Concurrent connections, throughput, flood, slowloris, churn, memory |
| Benchmarks | 10 | Ping, initialize, tools/list, auth, scanner, audit, JSON encode/decode |
| Fuzz targets | 3 | Handler, auth middleware, response scanner |
| **Total** | **350** | **96.0% coverage** |

> **Note:** The race detector (`-race`) is recommended during development to catch concurrent access issues. It adds runtime overhead, so it is typically not used in CI unless race detection is explicitly required.

### Recommended CI Pipeline

```yaml
# GitHub Actions example
- name: Run tests
  run: go test ./... -count=1 -timeout 120s

- name: Run race detector
  run: go test -race -count=1 -timeout 180s ./...

- name: Run benchmarks (regression check)
  run: go test -bench=. -benchmem -benchtime=1s ./...

- name: Check formatting
  run: test -z "$(gofmt -l .)"
```

### Performance Benchmarks

Benchmarks are used for regression tracking. Run with `go test -bench=. -benchmem -benchtime=5s ./...`:

| Benchmark | ns/op | allocs/op | Description |
|-----------|-------|-----------|-------------|
| BenchmarkPing | ~12,000 | 31 | Single ping tool call |
| BenchmarkToolsList | ~750 | 3 | Tools list response |
| BenchmarkAuthMiddleware | — | — | Auth on pre-authenticated connection |
| BenchmarkResponseScanShort | ~1,900 | — | Scanner on "pong" (4 bytes) |
| BenchmarkResponseScanMedium | ~433,000 | — | Scanner on ~500 bytes |
| BenchmarkResponseScanLarge | ~3,857,000 | — | Scanner on ~4KB (shows 64KB cap rationale) |
| BenchmarkAuditLog | ~3,100 | 7 | Audit log with hash chain |
| BenchmarkJSONEncodeResponse | ~1,670 | — | JSON encoding |
| BenchmarkJSONDecodeRequest | ~5,170 | 11 | JSON decoding |

---

## Appendix — Quick Reference

### Agent Roles

| Role | Constant | Description |
|------|----------|-------------|
| Restricted | `mcp.RoleRestricted` | Minimal access — only explicitly permitted tools |
| Standard | `mcp.RoleStandard` | Standard operational access |
| Admin | `mcp.RoleAdmin` | Full access to all tools and configuration |

### Policy Actions

| Action | Constant | Description |
|--------|----------|-------------|
| Allow | `mcp.PolicyAllow` | Permit the call |
| Deny | `mcp.PolicyDeny` | Reject the call |
| Allow with Alert | `mcp.PolicyAllowWithAlert` | Permit the call, log an alert |

### Key Methods

| Method | Description |
|--------|-------------|
| `mcp.DefaultServerConfig()` | Returns a `ServerConfigV2` with safe defaults |
| `mcp.NewSecuredMCPServer(cfg)` | Creates a new `SecuredMCPServer` |
| `srv.RegisterTool(...)` | Registers tool metadata and JSON Schema |
| `srv.RegisterToolHandler(...)` | Registers the Go handler for a tool |
| `srv.RegisterAgent(...)` | Enrolls an agent with RBAC permissions |
| `srv.LoadDefaultPolicies()` | Loads built-in policy rules |
| `srv.AddPolicyRule(...)` | Adds a custom policy rule |
| `srv.AddTrustedKey(...)` | Registers a trusted ECDSA public key |
| `mcp.SignRequest(...)` | Signs a JSON-RPC request with ECDSA P-256 |
| `srv.Start(ctx)` | Starts the server (blocks until context is cancelled) |
| `srv.Stop()` | Performs graceful shutdown |

---

*Copyright © 2026 AegisGate Security, LLC. AegisGate MCP is a product of AegisGate Security, LLC. Licensed under the Apache License, Version 2.0.*