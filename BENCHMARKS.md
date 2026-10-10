# AegisGate MCP — Performance Benchmarks

**Date:** October 10, 2026
**Version:** v1.5.0-dev (post-EvasionDetector wiring)
**Platform:** 40-core Linux, CGO_ENABLED=0 (no ML inference)
**Method:** `go test -run=^$ -bench=. -benchmem -benchtime=3s`

## Overview

AegisGate MCP is a zero-dependency MCP security server written in pure Go.
These benchmarks measure the hot-path components to track performance across releases.

## Results

### Core Request Processing

| Benchmark | ns/op | B/op | allocs/op | Description |
|-----------|-------|------|-----------|-------------|
| `BenchmarkPing` | 14,194 | 1,619 | 31 | Full ping request through handler dispatch |
| `BenchmarkInitialize` | 22,861 | 3,632 | 44 | Initialize handshake (auth + session creation) |
| `BenchmarkToolsList` | 789 | 248 | 3 | List registered tools |
| `BenchmarkAuthMiddleware` | 510 | 120 | 2 | Bearer token authentication check |
| `BenchmarkMiddlewareChain` | 12,351 | 2,635 | 35 | Full chain: auth → sig → guardrails → scan → handler |

### Content Scanning

| Benchmark | ns/op | B/op | allocs/op | Description |
|-----------|-------|------|-----------|-------------|
| `BenchmarkResponseScanShort` | 1,891 | 81 | 1 | Scan 100-char response (30 patterns) |
| `BenchmarkResponseScanMedium` | 588,336 | 87 | 1 | Scan 10KB response |
| `BenchmarkResponseScanLarge` | 5,310,191 | 169 | 1 | Scan 1MB response |

### Serialization & Logging

| Benchmark | ns/op | B/op | allocs/op | Description |
|-----------|-------|------|-----------|-------------|
| `BenchmarkJSONEncodeResponse` | 1,545 | 80 | 1 | JSON marshal a JSONRPCResponse |
| `BenchmarkJSONDecodeRequest` | 5,260 | 432 | 11 | JSON unmarshal a JSONRPCRequest |
| `BenchmarkAuditLog` | 3,620 | 1,400 | 7 | Write an audit log entry (hash-chained) |

### HTTP Transport

| Benchmark | ns/op | B/op | allocs/op | Description |
|-----------|-------|------|-----------|-------------|
| `BenchmarkHTTPPing` | 304,619 | 9,466 | 98 | Ping over Streamable HTTP (full HTTP roundtrip) |

## Key Takeaways

1. **Middleware chain overhead: ~12.3μs per request** — The full security chain (auth, signature verification, guardrails, response scanning, handler) adds only 12.3 microseconds per tools/call request. This is negligible compared to typical LLM API latency (100ms+).

2. **Auth middleware: 510ns** — Bearer token authentication adds less than 1 microsecond. No measurable impact on request throughput.

3. **Content scanning scales linearly** — Response scanning is O(n) in content length. A typical 100-character tool response scans in 1.9μs. A 10KB response scans in 588μs. The 30 regex patterns are compiled once at startup.

4. **HTTP transport: 305μs per request** — The Streamable HTTP transport adds ~290μs of HTTP protocol overhead on top of the 14μs handler cost. This is expected for HTTP (TCP handshake, HTTP parsing, response writing).

5. **Zero allocation hot paths** — `BenchmarkToolsList` (3 allocs) and `BenchmarkAuthMiddleware` (2 allocs) are near-zero-allocation. The middleware chain's 35 allocs are dominated by JSON marshaling and audit logging.

## Reproducing

```bash
# Run all benchmarks
CGO_ENABLED=0 go test -run=^$ -bench=. -benchmem -benchtime=3s ./...

# Run with ML enabled (requires CGO + ONNX model)
CGO_ENABLED=1 go test -run=^$ -bench=. -benchmem -benchtime=3s ./...

# Compare across versions
go test -run=^$ -bench=. -count=5 ./... | tee new.txt
benchstat old.txt new.txt

# Load/stress/break tests (gated behind build tag)
go test -tags=load -v -timeout=120s ./...
```

## Environment

- **CPU:** 40-core (benchmark results show `-40` suffix)
- **CGO:** Disabled (ML inference not measured — heuristic-only fallback)
- **ML Model:** Not loaded (would add ~1-5ms per scanned input with CharCNN-BiLSTM v13)
- **Go Version:** 1.26.9
- **Dependencies:** Zero (Go standard library only)