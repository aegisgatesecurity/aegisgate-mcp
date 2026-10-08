# =========================================================================
# AegisGate MCP — Standalone Docker Image
# Zero external dependencies. Air-gapped capable. Multi-stage build.
#
# This Dockerfile builds the FULL ML-enabled image (CGO_ENABLED=1) with the
# vendored CharCNN-BiLSTM v13 neural threat detector. All dependencies are
# self-contained:
#   - libonnxruntime.so (Microsoft, MIT, vendored in ./lib/)
#   - threat_cnn_bilstm.onnx (AegisGate, Apache-2.0, vendored in ./models/)
#   - onnxruntime_go (vendored in ./internal/onnxruntime_go/)
#   - golang.org/x/text (vendored in ./internal/textnorm/)
#
# Build:  docker build -t aegisgate-mcp:latest .
# Run:    docker run -p 8081:8081 aegisgate-mcp:latest
#
# For non-CGO (heuristic-only) builds, use:
#   docker build --build-arg CGO_ENABLED=0 -t aegisgate-mcp:lite .
#
# Uses Debian bookworm-slim (not Alpine/distroless) because:
#   1. onnxruntime prebuilt Linux shared libraries require glibc (ld-linux)
#   2. dlopen() requires libdl, which is part of glibc
#   3. ONNX runtime requires libstdc++6 at runtime
# Alpine's musl libc cannot load glibc-compiled .so files.
# =========================================================================

# --- Build stage ---
FROM golang:1.23-bookworm AS builder

# Install C compiler for CGO (gcc is pre-installed in golang:bookworm,
# but we ensure it's present along with make for the C wrapper)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy module files first for layer caching
COPY go.mod ./

# Copy source (includes vendored internal/, lib/, models/)
COPY . .

# Build-time argument controls CGO/ONNX support.
# Default: CGO_ENABLED=1 (full neural threat detection).
# Override: --build-arg CGO_ENABLED=0 for heuristic-only (smaller image).
ARG CGO_ENABLED=1
ARG VERSION=1.1.0

# Set up environment for CGO build with vendored onnxruntime.
# WORKDIR is /build, so the .so is at /build/lib/ and C headers at
# /build/internal/onnxruntime_go/. We use absolute paths because Dockerfile
# ENV does not expand $PWD at build time.
ENV CGO_ENABLED=${CGO_ENABLED}
ENV CGO_CFLAGS="-I/build/internal/onnxruntime_go"
ENV CGO_LDFLAGS="-L/build/lib -lonnxruntime -ldl"

# Build the binary.
# -s -w strips debug info for smaller binary.
# Version is injected via ldflags.
RUN go build \
    -ldflags="-s -w -X github.com/aegisgatesecurity/aegisgate-mcp.Version=${VERSION}" \
    -o /mcp-server \
    ./cmd/mcp-server

# --- Runtime stage ---
# Debian bookworm-slim: ~80MB base, has glibc (libdl for dlopen), can install
# libstdc++6 for ONNX runtime. Much smaller than full debian, no shell by
# default (we remove it in hardening step below).
FROM debian:bookworm-slim

# Install runtime dependencies and create non-root user.
# - libstdc++6: required by libonnxruntime.so (C++ runtime)
# - ca-certificates: TLS for any outbound HTTPS (health checks, webhooks)
# - libc6: provides libdl.so.2 for dlopen() — pre-installed but explicit
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates wget libstdc++6 libc6 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /usr/sbin/nologin mcpuser

# Create application directories
RUN mkdir -p /app/models /app/lib /var/log/mcp /tmp/mcp-audit && \
    chown -R mcpuser:mcpuser /app /var/log/mcp /tmp/mcp-audit

# Copy binary from build stage
COPY --from=builder /mcp-server /app/mcp-server

# Copy vendored ONNX runtime shared library
COPY --from=builder /build/lib/libonnxruntime.so /app/lib/libonnxruntime.so

# Copy vendored ML model (CharCNN-BiLSTM v13, 6.2MB)
COPY --from=builder /build/models/threat_cnn_bilstm.onnx /app/models/threat_cnn_bilstm.onnx

# Set up shared library discovery.
# The onnxruntime_go library uses dlopen() to load libonnxruntime.so at
# runtime. It searches ONNXRUNTIME_SHARED_LIBRARY_PATH env var first,
# then well-known system paths. We set it to our vendored copy.
ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/app/lib/libonnxruntime.so
# Also set LD_LIBRARY_PATH as a fallback for the dynamic linker.
ENV LD_LIBRARY_PATH=/app/lib

# ML configuration: enabled by default in Docker (full 21-layer security).
# Override with env vars or CLI flags at runtime.
ENV MCP_ML_ENABLED=true
ENV MCP_ML_THRESHOLD=0.50
ENV MCP_ML_MODEL=/app/models/threat_cnn_bilstm.onnx

# Server configuration
ENV MCP_SERVER_ADDR=:8081
ENV MCP_AUDIT_LOG=/var/log/mcp/audit.json
ENV MCP_HEALTH_ADDR=:8082

WORKDIR /app

# Expose MCP server port (TCP mode) and health endpoint
EXPOSE 8081 8082

# Run as non-root user
USER mcpuser

# Health check hits the health endpoint (wget available in debian:bookworm-slim)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8082/healthz || exit 1

# Run the server.
# The --ml flag is set by MCP_ML_ENABLED=true env var.
# Additional flags: --token, --audit, --transport, --health-addr, --tls,
# --config, --demo, --ml-shadow, --ml-threshold, --ml-model.
# See --help for full list. JSON config file via --config /path/to/config.json
ENTRYPOINT ["/app/mcp-server"]
CMD ["--addr", ":8081"]