# Contributing to AegisGate MCP

Thank you for your interest in contributing to AegisGate MCP!

## DCO (Developer Certificate of Origin)

All commits must be signed off with `git commit -s` to indicate your
agreement with the [Developer Certificate of Origin](https://developercertificate.org/).

## Build

```bash
# Non-CGO (heuristic-only, static binary)
make build

# CGO (full ML, requires libonnxruntime.so)
make build-cgo
```

## Test

```bash
# Non-CGO tests
make test

# CGO tests (full ML)
make test-cgo

# Race detector
make race

# Both test suites
make test-all
```

## Code Style

- Run `gofmt -w .` before committing
- Run `go vet ./...` and fix any issues
- Follow Go conventions: effective Go, Go Code Review Comments

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass: `make test-all`
5. Ensure `make vet` and `make fmt` are clean
6. Commit with DCO sign-off (`git commit -s`)
7. Open a pull request with a clear description

## Security Issues

**Do not open public issues for security vulnerabilities.**
Email security@aegisgatesecurity.io instead.

---

*Copyright 2024-2026 AegisGate Security, LLC. Licensed under Apache-2.0.*