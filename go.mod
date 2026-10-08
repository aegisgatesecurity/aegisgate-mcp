module github.com/aegisgatesecurity/aegisgate-mcp

go 1.22

// Zero external module dependencies (no `require` directives).
// All third-party code is vendored into internal/ — see NOTICE for details.
// Runs air-gapped without network connectivity.
// CGO_ENABLED=1: full neural detection (ONNX Runtime vendored in lib/).
// CGO_ENABLED=0: heuristic-only fallback (no ONNX, pure Go).