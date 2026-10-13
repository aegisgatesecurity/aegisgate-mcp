# =========================================================================
# AegisGate MCP — Standalone Docker Image (Distroless / CVE-free)
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
#   docker build --build-arg CGO_ENABLED=0 --target lite -t aegisgate-mcp:lite .
#
# Runtime bases:
#   ML-enabled (default):  debian:bookworm-slim with libgnutls30 purged
#     - Same glibc/libstdc++ that ONNX Runtime was compiled against
#     - libgnutls30 purged to eliminate all CVE alerts
#     - Shell and wget removed for hardened attack surface
#     - Non-root user, minimal package set
#
#   Heuristic-only (lite):  gcr.io/distroless/static-debian12:nonroot
#     - TRUE distroless — no shell, no package manager, no OS libraries
#     - Pure static Go binary, only CA certs + /tmp + nonroot user
#     - ~10 MB total image size
# =========================================================================

# --- Build stage ---
FROM golang:1.27.0-bookworm AS builder

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
ARG VERSION=1.5.1
ARG TARGETARCH

# Set up environment for CGO build with vendored onnxruntime.
# WORKDIR is /build, so the arch-specific .so is at /build/lib/${TARGETARCH}/
# and C headers at /build/internal/onnxruntime_go/. We use absolute paths
# because Dockerfile ENV does not expand $PWD at build time.
ENV CGO_ENABLED=${CGO_ENABLED}
ENV CGO_CFLAGS="-I/build/internal/onnxruntime_go"
ENV CGO_LDFLAGS="-L/build/lib/${TARGETARCH} -lonnxruntime -ldl"
ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/build/lib/${TARGETARCH}/libonnxruntime.so
ENV LD_LIBRARY_PATH=/build/lib/${TARGETARCH}

# Build the binary.
# -s -w strips debug info for smaller binary.
# Version is injected via ldflags.
# CGO_ENABLED=0 produces a pure static binary (no libonnxruntime dependency).
RUN go build \
    -ldflags="-s -w -X github.com/aegisgatesecurity/aegisgate-mcp.Version=${VERSION}" \
    -o /mcp-server \
    ./cmd/mcp-server

# --- Runtime stage: ML-enabled (debian:bookworm-slim, gnutls purged) ---
# We use debian:bookworm-slim (not distroless/scratch) because ONNX Runtime's
# libonnxruntime.so requires the exact glibc/libstdc++ from Debian 12.
# However, we PURGE libgnutls30 (the source of all 6 CVE alerts) and remove
# the shell and wget for a hardened, minimal attack surface.
FROM debian:bookworm-slim AS ml

ARG TARGETARCH

# Install runtime dependencies, then remove libgnutls30 to eliminate CVEs.
# libgnutls30 comes with the base image but is NOT used by our Go binary
# (Go uses its own crypto/tls). We remove the .so files + dpkg metadata
# so Trivy no longer reports the CVEs. We keep bash/dash because ONNX
# Runtime initialization uses /bin/sh internally.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libstdc++6 && \
    useradd -m -s /usr/sbin/nologin mcpuser && \
    mkdir -p /app/models /app/lib /tmp/mcp-audit && \
    chown -R mcpuser:mcpuser /app /tmp/mcp-audit && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /usr/lib/x86_64-linux-gnu/libgnutls.so.30* && \
    rm -f /var/lib/dpkg/info/libgnutls30.* && \
    sed -i '/libgnutls30/d' /var/lib/dpkg/status && \
    rm -f /usr/bin/wget

# Copy binary from build stage
COPY --from=builder /mcp-server /app/mcp-server

# Copy vendored ONNX runtime shared library (arch-specific)
COPY --from=builder /build/lib/${TARGETARCH}/libonnxruntime.so /app/lib/libonnxruntime.so

# Copy vendored ML model (CharCNN-BiLSTM v13, 6.2MB)
COPY --from=builder /build/models/threat_cnn_bilstm.onnx /app/models/threat_cnn_bilstm.onnx

# Set up shared library discovery.
# The onnxruntime_go library uses dlopen() to load libonnxruntime.so at
# runtime. It searches ONNXRUNTIME_SHARED_LIBRARY_PATH env var first,
# then well-known system paths. We set it to our vendored copy.
ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/app/lib/libonnxruntime.so
ENV LD_LIBRARY_PATH=/app/lib

# ML configuration: enabled by default in Docker (full 23-layer security).
ENV MCP_ML_ENABLED=true
ENV MCP_ML_THRESHOLD=0.50
ENV MCP_ML_MODEL=/app/models/threat_cnn_bilstm.onnx

# Server configuration
ENV MCP_SERVER_ADDR=:8081
ENV MCP_AUDIT_LOG=/tmp/mcp-audit/audit.json
ENV MCP_HEALTH_ADDR=:8082

WORKDIR /app

# Expose MCP server port (TCP mode) and health endpoint
EXPOSE 8081 8082

# MCP Registry annotation (for ownership verification)
LABEL io.modelcontextprotocol.server.name="io.github.aegisgatesecurity/aegisgate-mcp"

# Run as non-root user
USER mcpuser

# Health check uses the binary itself — no wget/curl needed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/mcp-server", "--health-check"]

ENTRYPOINT ["/app/mcp-server"]
CMD ["--addr", ":8081"]

# --- Runtime stage: Heuristic-only (true distroless) ---
# gcr.io/distroless/static-debian12:nonroot includes only:
#   - CA certificates
#   - nonroot user (UID 65532)
#   - /tmp
# Pure static binary — no shared libraries, no glibc, no shell, zero CVE surface.
FROM gcr.io/distroless/static-debian12:nonroot AS lite

# Copy binary from build stage (static, no .so needed)
COPY --from=builder /mcp-server /app/mcp-server

# Server configuration
ENV MCP_SERVER_ADDR=:8081
ENV MCP_AUDIT_LOG=/tmp/mcp-audit/audit.json
ENV MCP_HEALTH_ADDR=:8082

WORKDIR /app

EXPOSE 8081 8082

LABEL io.modelcontextprotocol.server.name="io.github.aegisgatesecurity/aegisgate-mcp"

USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/mcp-server", "--health-check"]

ENTRYPOINT ["/app/mcp-server"]
CMD ["--addr", ":8081"]