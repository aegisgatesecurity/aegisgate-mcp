# AegisGate MCP Deployment Guide

**Product:** AegisGate MCP — Security-First MCP Server  
**Vendor:** AegisGate Security, LLC  
**License:** Apache-2.0  
**Version:** 1.4.1  
**Runtime:** Go 1.26+  
**External Dependencies:** Zero  
**Docker Base Image:** `debian:bookworm-slim` (~135 MB ML-enabled, ~8 MB heuristic-only)

---

## Table of Contents

1. [Deployment Modes Overview](#1-deployment-modes-overview)
2. [Binary Deployment](#2-binary-deployment)
3. [Docker Deployment](#3-docker-deployment)
4. [Docker Compose Deployment](#4-docker-compose-deployment)
5. [TLS/mTLS Configuration](#5-tlsmtls-configuration)
6. [JSON Config File Deployment](#6-json-config-file-deployment)
7. [stdio Mode Deployment](#7-stdio-mode-deployment)
8. [Health Checks and Monitoring](#8-health-checks-and-monitoring)
9. [Air-Gapped Deployment](#9-air-gapped-deployment)
10. [Hardening Checklist](#10-hardening-checklist)

---

## 1. Deployment Modes Overview

AegisGate MCP supports three deployment modes, each tailored to a specific operational context.

| Mode | Transport | TLS/mTLS | Use Case |
|------|-----------|----------|----------|
| **TCP** (default) | JSON-RPC 2.0 over TCP | ✅ Full TLS + mTLS | Network-accessible server; production multi-client environments |
| **stdio** | JSON-RPC 2.0 over stdin/stdout | ❌ Not applicable (local IPC) | Local MCP clients (Claude Desktop, Cursor, other MCP-compatible IDEs) |
| **Go library** | In-process function calls | N/A | Embedding AegisGate MCP directly inside another Go application |

### TCP Mode

The default and recommended mode for production. Listens on a configurable address, supports bearer-token authentication, TLS encryption, and mutual TLS (mTLS) for client identity verification. Suitable for production environments where network-level access control and audit logging are required.

### stdio Mode

Designed for local integration with MCP-compatible desktop clients. The server reads JSON-RPC 2.0 messages from stdin and writes responses to stdout. No network listener is opened, making it ideal for developer workstations and local tooling pipelines. TLS is not applicable because communication is over local IPC.

### Go Library

AegisGate MCP can be imported as a Go package and embedded directly in another application. This eliminates the network hop entirely and gives the host application full programmatic control over configuration, session management, and security policies. See the [Go API documentation](./api-reference.md) for details.

---

## 2. Binary Deployment

### Build from Source

```bash
# Clone the repository
git clone https://github.com/aegisgate/mcp-security.git
cd mcp-security

# Build the binary (non-CGO: heuristic-only, no ONNX)
CGO_ENABLED=0 go build -o mcp-server ./cmd/mcp-server

# Or build with full ML support (CGO: requires libonnxruntime.so)
CGO_ENABLED=1 CGO_LDFLAGS="-L$(pwd)/lib -lonnxruntime" go build -o mcp-server ./cmd/mcp-server

# Verify the binary
./mcp-server --version
```

The non-CGO binary is fully static and has zero external runtime dependencies.
The CGO binary requires `libonnxruntime.so` at runtime (vendored in `lib/`).
Both can be copied to any Linux/amd64 machine.

### Install the Binary

```bash
sudo cp mcp-server /usr/local/bin/mcp-server
sudo chmod 755 /usr/local/bin/mcp-server
```

### Create a Dedicated User

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcp
sudo mkdir -p /var/log/mcp /etc/mcp
sudo chown mcp:mcp /var/log/mcp
```

### Environment File

Create `/etc/mcp/mcp.env`:

```ini
# /etc/mcp/mcp.env — AegisGate MCP runtime environment
TOKEN=production-bearer-token-change-me
```

> **Security Note:** Restrict file permissions on the environment file.
> ```bash
> sudo chmod 600 /etc/mcp/mcp.env
> sudo chown mcp:mcp /etc/mcp/mcp.env
> ```

### systemd Unit File

Create `/etc/systemd/system/aegisgate-mcp.service`:

```ini
[Unit]
Description=AegisGate MCP Server
After=network.target

[Service]
Type=simple
User=mcp
ExecStart=/usr/local/bin/mcp-server --addr 0.0.0.0:8081 --token ${TOKEN} --audit /var/log/mcp/audit.json --health-addr 127.0.0.1:8082
EnvironmentFile=/etc/mcp/mcp.env
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/mcp
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
```

### Enable and Start the Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable aegisgate-mcp
sudo systemctl start aegisgate-mcp

# Verify
sudo systemctl status aegisgate-mcp
curl http://127.0.0.1:8082/healthz
```

---

## 3. Docker Deployment

AegisGate MCP uses `debian:bookworm-slim` as the base image with CGO enabled
for full neural threat detection. The final image is approximately 135 MB and
includes the vendored ONNX Runtime and CharCNN-BiLSTM v13 model. A lighter
heuristic-only image (~8 MB) can be built with `--build-arg CGO_ENABLED=0`.

The image runs as a non-root user (`mcpuser`) with shell disabled.

### Build the Image

```bash
# Full ML-enabled build (default, ~135 MB)
docker build -t aegisgate-mcp .

# Heuristic-only build (no CGO, ~8 MB)
docker build --build-arg CGO_ENABLED=0 -t aegisgate-mcp:lite .
```

### Run — Basic

```bash
docker run -d --name aegisgate-mcp -p 8081:8081 aegisgate-mcp
```

### Run — With Authentication, Audit, and Demo Tools

```bash
docker run -d --name aegisgate-mcp \
  -p 8081:8081 \
  -p 8082:8082 \
  -e MCP_AUTH_TOKEN=my-secret \
  -e MCP_DEMO_TOOLS=true \
  -v mcp-audit:/var/log/mcp \
  aegisgate-mcp --health-addr :8082 --demo
```

### Run — With TLS

```bash
docker run -d --name aegisgate-mcp \
  -p 8081:8081 \
  -v /path/to/certs:/certs:ro \
  -e MCP_TLS_ENABLED=true \
  -e MCP_TLS_CERT=/certs/server.pem \
  -e MCP_TLS_KEY=/certs/server.key \
  aegisgate-mcp
```

### Run — With mTLS (Mutual TLS)

Mutual TLS requires the server to verify client certificates against a trusted CA. This is the recommended configuration for production environments.

```bash
docker run -d --name aegisgate-mcp \
  -p 8081:8081 \
  -v /path/to/certs:/certs:ro \
  -e MCP_TLS_ENABLED=true \
  -e MCP_TLS_CERT=/certs/server.pem \
  -e MCP_TLS_KEY=/certs/server.key \
  -e MCP_TLS_CLIENT_CA=/certs/ca.pem \
  -e MCP_TLS_MIN_VERSION=1.3 \
  aegisgate-mcp
```

### Environment Variable Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_AUTH_TOKEN` | Bearer token for client authentication | (none — auth disabled) |
| `MCP_DEMO_TOOLS` | Enable demonstration tools | `false` |
| `MCP_AUDIT_LOG` | Path to audit log file | (none) |
| `MCP_TLS_ENABLED` | Enable TLS | `false` |
| `MCP_TLS_CERT` | Path to TLS certificate | (none) |
| `MCP_TLS_KEY` | Path to TLS private key | (none) |
| `MCP_TLS_CLIENT_CA` | Path to client CA certificate (mTLS) | (none) |
| `MCP_TLS_MIN_VERSION` | Minimum TLS version (`1.2` or `1.3`) | `1.2` |
| `MCP_HEALTH_ADDR` | Health endpoint listen address | (none) |
| `MCP_MAX_CONNECTIONS` | Max concurrent TCP connections (-1 = unlimited) | `1000` |

---

## 4. Docker Compose Deployment

For production deployments using Docker Compose, reference the `docker-compose.yml` file in the project root. A complete production example is provided below.

### docker-compose.yml

```yaml
version: '3.8'
services:
  aegisgate-mcp:
    build: .
    container_name: aegisgate-mcp
    ports:
      - "8081:8081"
      - "8082:8082"
    environment:
      - MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN}
      - MCP_DEMO_TOOLS=true
      - MCP_AUDIT_LOG=/var/log/mcp/audit.json
      - MCP_TLS_ENABLED=true
      - MCP_TLS_CERT=/certs/server.pem
      - MCP_TLS_KEY=/certs/server.key
      - MCP_HEALTH_ADDR=:8082
    volumes:
      - mcp-audit:/var/log/mcp
      - ./certs:/certs:ro
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://127.0.0.1:8082/healthz"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
volumes:
  mcp-audit:
```

### Healthchecks

The AegisGate MCP Docker image is based on `debian:bookworm-slim` and includes
`wget` for health checks. Enable the health endpoint with `--health-addr` and
configure the Docker healthcheck:

```yaml
# docker-compose.yml
services:
  aegisgate-mcp:
    environment:
      - MCP_HEALTH_ADDR=:8082
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8082/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3
```

Alternatively, use Kubernetes liveness/readiness probes or an external
monitoring script that polls the health endpoint.
  sleep 10
done
```

**Option C — Switch to a minimal alpine-based image if in-container healthcheck is required:**

If you must use Docker's native healthcheck, build a custom image based on `alpine` that includes `wget` or `curl`. Note that this increases the image size and attack surface.

```dockerfile
FROM alpine:3.19
RUN apk add --no-cache wget
COPY mcp-server /mcp-server
USER 65532:65532
ENTRYPOINT ["/mcp-server"]
```

### Deploy with Docker Compose

```bash
# Create a .env file for secrets
echo 'MCP_AUTH_TOKEN=production-bearer-token-change-me' > .env

# Launch
docker compose up -d

# Verify
docker compose ps
curl http://localhost:8082/healthz
```

---

## 5. TLS/mTLS Configuration

TLS encryption is strongly recommended for all network-accessible deployments. mTLS adds client identity verification, which is important in security-sensitive environments.

### Generate Self-Signed Certificates (for Testing)

The following OpenSSL commands generate a complete PKI for testing: a CA, a server certificate, and a client certificate.

```bash
# Create a working directory
mkdir -p certs && cd certs

# --- 1. Generate CA key and certificate ---
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
  -out ca.pem \
  -subj "/CN=AegisGate Test CA/O=AegisGate Security, LLC"

# --- 2. Generate server key and certificate (signed by CA) ---
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
  -out server.csr \
  -subj "/CN=aegisgate-mcp/O=AegisGate Security, LLC"

# Create a SANs extension file
cat > server-ext.cnf << 'EOF'
subjectAltName = DNS:localhost, DNS:aegisgate-mcp, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in server.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -sha256 \
  -extfile server-ext.cnf

# --- 3. Generate client key and certificate (signed by CA, for mTLS) ---
openssl genrsa -out client.key 2048
openssl req -new -key client.key \
  -out client.csr \
  -subj "/CN=mcp-client/O=AegisGate Security, LLC"

cat > client-ext.cnf << 'EOF'
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 365 -sha256 \
  -extfile client-ext.cnf

# Clean up intermediate files
rm -f *.csr *.srl server-ext.cnf client-ext.cnf

cd ..
```

The `certs/` directory will contain:

| File | Purpose |
|------|---------|
| `ca.pem` | CA certificate (used as `--tls-client-ca`) |
| `server.pem` | Server certificate (used as `--tls-cert`) |
| `server.key` | Server private key (used as `--tls-key`) |
| `client.pem` | Client certificate (presented by client during mTLS handshake) |
| `client.key` | Client private key (used by client to sign mTLS handshake) |

### TLS 1.3 Enforcement

TLS 1.3 is the recommended minimum version for all deployments. Enforce it with the `--tls-min-version` flag:

```bash
./mcp-server \
  --addr 0.0.0.0:8081 \
  --tls \
  --tls-cert server.pem \
  --tls-key server.key \
  --tls-min-version 1.3
```

### mTLS (Mutual TLS)

For mutual TLS, provide the CA certificate that signed client certificates:

```bash
./mcp-server \
  --addr 0.0.0.0:8081 \
  --tls \
  --tls-cert server.pem \
  --tls-key server.key \
  --tls-client-ca ca.pem \
  --tls-min-version 1.3 \
  --token production-bearer-token
```

When `--tls-client-ca` is set, the server will reject any client that does not present a valid certificate signed by the specified CA.

---

## 6. JSON Config File Deployment

For production deployments, a JSON configuration file is recommended over command-line flags. It provides better manageability, version control, and the ability to specify all parameters in one place.

### Production config.json

```json
{
  "Address": ":8081",
  "AuthToken": "production-bearer-token",
  "MaxSessions": 100,
  "MaxConnections": 1000,
  "SessionTimeout": 3600000000000,
  "MaxToolsPerSession": 200,
  "ExecTimeout": 60000000000,
  "RateLimitRPM": 120,
  "ScanResponses": true,
  "BlockOnPII": true,
  "BlockOnSecrets": true,
  "BlockOnXSS": true,
  "BlockOnPromptInject": true,
  "RedactEnabled": true,
  "RedactPII": true,
  "RedactSecrets": true,
  "RedactPlaceholder": "[SCRUBBED]",
  "AuditLogPath": "/var/log/mcp/audit.json",
  "MaxAuditEntries": 50000,
  "EnableStdioValidation": true,
  "TLSEnabled": true,
  "TLSCertFile": "/certs/server.pem",
  "TLSKeyFile": "/certs/server.key",
  "TLSClientCAFile": "/certs/ca.pem",
  "TLSMinVersion": "1.3",
  "DemoTools": true
}
```

### Time Duration Format

Time durations in the JSON config file are expressed in **nanoseconds**, following Go's `time.Duration` JSON marshaling format.

| Field | Value (ns) | Human-Readable |
|-------|------------|----------------|
| `SessionTimeout` | `3600000000000` | 1 hour |
| `ExecTimeout` | `60000000000` | 60 seconds |
| `3000000000000` | 50 minutes |
| `1800000000000` | 30 minutes |
| `30000000000` | 30 seconds |

### Config Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Address` | string | `":8081"` | Listen address for TCP mode |
| `AuthToken` | string | `""` | Bearer token for authentication (empty = disabled) |
| `MaxSessions` | int | `100` | Maximum concurrent sessions |
| `MaxConnections` | int | `1000` | Maximum concurrent TCP connections (-1 = unlimited) |
| `SessionTimeout` | duration (ns) | `3600000000000` (1h) | Session idle timeout |
| `MaxToolsPerSession` | int | `200` | Maximum tools registered per session |
| `ExecTimeout` | duration (ns) | `60000000000` (60s) | Tool execution timeout |
| `RateLimitRPM` | int | `120` | Rate limit (requests per minute per connection) |
| `ScanResponses` | bool | `true` | Enable response content scanning |
| `BlockOnPII` | bool | `true` | Block responses containing PII |
| `BlockOnSecrets` | bool | `true` | Block responses containing secrets |
| `BlockOnXSS` | bool | `true` | Block responses containing XSS payloads |
| `BlockOnPromptInject` | bool | `true` | Block responses containing prompt injection |
| `RedactEnabled` | bool | `true` | Enable response redaction |
| `RedactPII` | bool | `true` | Redact PII from responses |
| `RedactSecrets` | bool | `true` | Redact secrets from responses |
| `RedactPlaceholder` | string | `"[SCRUBBED]"` | Placeholder text for redacted content |
| `AuditLogPath` | string | `""` | Path to audit log JSON file |
| `MaxAuditEntries` | int | `50000` | Maximum audit log entries before rotation |
| `EnableStdioValidation` | bool | `true` | Validate input in stdio mode |
| `TLSEnabled` | bool | `false` | Enable TLS |
| `TLSCertFile` | string | `""` | Path to TLS certificate file |
| `TLSKeyFile` | string | `""` | Path to TLS private key file |
| `TLSClientCAFile` | string | `""` | Path to client CA certificate (mTLS) |
| `TLSMinVersion` | string | `"1.2"` | Minimum TLS version (`"1.2"` or `"1.3"`) |
| `DemoTools` | bool | `false` | Enable demonstration tools |

### Launch with Config File

```bash
./mcp-server --config /etc/mcp/config.json
```

### Launch with Config File and Override Flags

```bash
./mcp-server --config /etc/mcp/config.json --health-addr 127.0.0.1:8082
```

Command-line flags override values set in the config file.

---

## 7. stdio Mode Deployment

stdio mode is for local integration with MCP-compatible desktop clients. The server communicates over stdin/stdout using JSON-RPC 2.0 — no network listener is opened.

### Claude Desktop Configuration

Add the following to your Claude Desktop configuration file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aegisgate": {
      "command": "/usr/local/bin/mcp-server",
      "args": ["--transport", "stdio", "--demo"]
    }
  }
}
```

### Claude Desktop Config File Locations

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

### Cursor Configuration

For Cursor and other MCP-compatible IDEs, refer to the client's documentation for MCP server configuration. The command and arguments are the same:

```json
{
  "mcpServers": {
    "aegisgate": {
      "command": "/usr/local/bin/mcp-server",
      "args": ["--transport", "stdio", "--demo"]
    }
  }
}
```

### stdio Mode with Config File

```json
{
  "mcpServers": {
    "aegisgate": {
      "command": "/usr/local/bin/mcp-server",
      "args": ["--transport", "stdio", "--config", "/etc/mcp/config.json"]
    }
  }
}
```

### Important Notes for stdio Mode

- **TLS is not supported** in stdio mode. Communication is over local stdin/stdout IPC, which does not traverse the network.
- **Authentication tokens are not required** in stdio mode because the transport is local. However, input validation and response scanning remain active.
- **Audit logging** can still be configured via the config file or `--audit` flag.
- **Demo tools** can be enabled with `--demo` for testing and evaluation.

---

## 8. Health Checks and Monitoring

AegisGate MCP exposes three HTTP endpoints for health checking and monitoring when `--health-addr` is configured.

### Endpoints

| Endpoint | Method | Description | Success Response |
|----------|--------|-------------|------------------|
| `/healthz` | GET | Liveness probe | `200 OK` + JSON status |
| `/readyz` | GET | Readiness probe | `200 OK` if ready, `503` if not |
| `/stats` | GET | Runtime statistics | `200 OK` + JSON stats |

### /healthz — Liveness

```bash
curl -s http://127.0.0.1:8082/healthz | jq .
```

Expected response:

```json
{
  "status": "ok",
  "version": "1.4.1",
  "uptime": "2h30m15s"
}
```

### /readyz — Readiness

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8082/readyz
```

Expected response: `200` (ready) or `503` (not ready).

### /stats — Runtime Statistics

```bash
curl -s http://127.0.0.1:8082/stats | jq .
```

Expected response:

```json
{
  "sessions": 3,
  "maxSessions": 100,
  "totalRequests": 1542,
  "blockedRequests": 7,
  "redactedItems": 23,
  "auditEntries": 1542,
  "uptime": "2h30m15s"
}
```

### Monitoring Script Example

The following bash script checks the `/healthz` endpoint and sends an alert if the server is not responding:

```bash
#!/usr/bin/env bash
# /usr/local/bin/aegisgate-healthcheck.sh
# AegisGate MCP health check and alerting script

set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8082/healthz}"
ALERT_EMAIL="${ALERT_EMAIL:-ops@aegisgate.example}"
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"

check_health() {
  local attempt=0
  while (( attempt < MAX_RETRIES )); do
    (( attempt++ ))
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$HEALTH_URL" 2>/dev/null || echo "000")
    if [[ "$response" == "200" ]]; then
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] OK — AegisGate MCP is healthy (attempt $attempt)"
      exit 0
    fi
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] WARN — Health check failed (HTTP $response, attempt $attempt/$MAX_RETRIES)"
    sleep "$RETRY_DELAY"
  done

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] CRITICAL — AegisGate MCP health check failed after $MAX_RETRIES attempts"
  echo "Alerting $ALERT_EMAIL..."

  # Send alert (adjust for your notification system)
  # mail -s "CRITICAL: AegisGate MCP is down" "$ALERT_EMAIL" < /dev/null
  # Or use curl to push to a webhook:
  # curl -X POST -H 'Content-Type: application/json' \
  #   -d '{"text":"CRITICAL: AegisGate MCP is down"}' \
  #   https://hooks.example.com/alerts

  exit 1
}

check_health
```

Set up a cron job to run it periodically:

```bash
# /etc/cron.d/aegisgate-healthcheck
*/2 * * * * root /usr/local/bin/aegisgate-healthcheck.sh >> /var/log/mcp/healthcheck.log 2>&1
```

### Performance Characteristics

AegisGate MCP has been validated with comprehensive load testing:

| Metric | Value |
|--------|-------|
| Sustained throughput | 14,427 req/sec |
| p50 latency (100 concurrent) | 34 ms |
| p99 latency (100 concurrent) | 46 ms |
| Connection churn rate | 2,662 conn/sec |
| Goroutine leaks (10s soak) | 0 |
| Graceful shutdown under load | 1.6 ms |

These metrics were measured with the built-in load test suite (`//go:build load` tag).
Run them locally with:

```bash
go test -tags=load -count=1 -timeout 120s -v ./...
```

---

## 9. Air-Gapped Deployment

Air-gapped deployment is a common requirement in environments where the server operates on a network with no internet connectivity.

### Step 1 — Build on a Connected Machine

```bash
# On a machine with internet access
git clone https://github.com/aegisgate/mcp-security.git
cd mcp-security

# Option A: Non-CGO static binary (heuristic-only, no ONNX)
CGO_ENABLED=0 go build -ldflags="-s -w" -o mcp-server ./cmd/mcp-server

# Option B: CGO binary with full ML (requires libonnxruntime.so at runtime)
CGO_ENABLED=1 CGO_LDFLAGS="-L$(pwd)/lib -lonnxruntime" \
  go build -ldflags="-s -w" -o mcp-server ./cmd/mcp-server

# Verify the binary
file mcp-server
```

### Step 2 — Prepare the Deployment Bundle

```bash
mkdir -p aegisgate-bundle/{bin,lib,models,certs,config}

# Copy binary
cp mcp-server aegisgate-bundle/bin/

# For CGO builds: copy shared library and model
cp lib/libonnxruntime.so aegisgate-bundle/lib/
cp models/threat_cnn_bilstm.onnx aegisgate-bundle/models/

# Copy certificates
cp certs/ca.pem certs/server.pem certs/server.key aegisgate-bundle/certs/

# Copy config
cp config.json aegisgate-bundle/config/

# Create a checksum file
sha256sum aegisgate-bundle/bin/mcp-server > aegisgate-bundle/checksums.sha256

# Create a tarball
tar czf aegisgate-bundle.tar.gz aegisgate-bundle/
```

### Step 3 — Transfer to the Air-Gapped Machine

Transfer the `aegisgate-bundle.tar.gz` file via approved media (USB drive, secure file transfer, etc.) following your organization's data transfer procedures.

### Step 4 — Install on the Air-Gapped Machine

```bash
# Extract the bundle
tar xzf aegisgate-bundle.tar.gz

# Verify checksums
cd aegisgate-bundle
sha256sum -c checksums.sha256

# Install the binary
sudo cp bin/mcp-server /usr/local/bin/mcp-server
sudo chmod 755 /usr/local/bin/mcp-server

# Install certificates
sudo mkdir -p /etc/mcp/certs
sudo cp certs/* /etc/mcp/certs/
sudo chmod 600 /etc/mcp/certs/*.key
sudo chmod 644 /etc/mcp/certs/*.pem

# Install config
sudo mkdir -p /etc/mcp
sudo cp config/config.json /etc/mcp/config.json
sudo chmod 640 /etc/mcp/config.json

# Create audit log directory
sudo mkdir -p /var/log/mcp
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcp 2>/dev/null || true
sudo chown mcp:mcp /var/log/mcp
```

### Step 5 — Run the Server

```bash
# Run with the config file
/usr/local/bin/mcp-server --config /etc/mcp/config.json --health-addr 127.0.0.1:8082
```

Or set up as a systemd service (see [Section 2](#2-binary-deployment)).

### Air-Gapped Deployment Notes

| Consideration | Details |
|---------------|---------|
| **Network** | No internet access required at runtime. The server is fully self-contained. |
| **Audit logs** | Written to the local filesystem at the configured path. Configure log rotation separately. |
| **Certificates** | Must be generated and signed on a connected machine (or an internal CA) and transferred with the bundle. |
| **Updates** | Repeat the build-and-transfer process for each new version. Verify checksums after transfer. |
| **Monitoring** | Use the local health endpoints (`/healthz`, `/readyz`, `/stats`) from within the air-gapped network. |

---

## 10. Hardening Checklist

Review and complete this checklist before deploying AegisGate MCP to production.

### Authentication

- [ ] Set `--token` (or `AuthToken` in config) to enable bearer-token authentication
- [ ] Use a strong, randomly generated token (minimum 32 characters)
- [ ] Store the token in an environment file or secrets manager — never in version control
- [ ] Rotate tokens periodically

### Transport Security

- [ ] Enable `--tls` with `--tls-cert` and `--tls-key`
- [ ] Set `--tls-min-version 1.3` to enforce TLS 1.3
- [ ] Configure `--tls-client-ca` for mutual TLS (mTLS) client verification
- [ ] Use certificates from a trusted CA or your organization's internal PKI
- [ ] Set appropriate certificate expiration and renewal procedures

### Auditing

- [ ] Set `--audit` log path (or `AuditLogPath` in config)
- [ ] Configure `MaxAuditEntries` for log rotation (recommend 50,000)
- [ ] Ensure the audit log directory has restricted permissions
- [ ] Set up log forwarding to a SIEM or centralized logging system

### Execution Controls

- [ ] Set `--exec-timeout` (recommend 30–60 seconds: `30000000000`–`60000000000` ns)
- [ ] Set `--rate-limit` (recommend 60 RPM per connection)
- [ ] Set `--max-sessions` (recommend 50–100 for production)
- [ ] Set `--max-connections` (recommend 100–1000 for production; use `-1` only with network-level controls)

### Content Security

- [ ] Enable `--scan-responses` (default: `true`)
- [ ] Enable `--block-pii` to block responses containing PII
- [ ] Enable `--block-secrets` to block responses containing secrets
- [ ] Enable `--block-xss` to block responses containing XSS payloads
- [ ] Enable `--block-prompt-inject` to block responses containing prompt injection
- [ ] Consider `--redact` for PII/secrets redaction (replaces blocked content with `[SCRUBBED]`)

### Operational

- [ ] Configure health endpoint (`--health-addr`) for orchestration and monitoring
- [ ] Run as a non-root user (the Docker image uses `mcpuser` by default; for binary deployment, use the systemd `User=mcp` directive)
- [ ] Use a JSON config file for production (easier management, version control, and review)
- [ ] Set up the systemd service with security hardening directives (see [Section 2](#2-binary-deployment))
- [ ] Configure firewall rules to restrict access to port 8081 (MCP) and 8082 (health) to authorized clients only
- [ ] Regularly update to the latest version of AegisGate MCP

---

## Appendix — Quick Start Reference

| Scenario | Command |
|----------|---------|
| **Quick test** | `./mcp-server --demo` |
| **Production (TCP + TLS + mTLS + audit)** | `./mcp-server --config /etc/mcp/config.json --health-addr 127.0.0.1:8082` |
| **Docker (basic)** | `docker run -d -p 8081:8081 aegisgate-mcp` |
| **Docker (full prod)** | `docker compose up -d` |
| **Claude Desktop (stdio)** | Configure `claude_desktop_config.json` with `--transport stdio` |
| **Health check** | `curl http://127.0.0.1:8082/healthz` |

---

*AegisGate MCP is a product of AegisGate Security, LLC. Licensed under Apache-2.0.*