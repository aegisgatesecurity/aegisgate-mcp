# =========================================================================
# AegisGate MCP — Makefile
# Common build, test, and deployment tasks.
# =========================================================================

# Default: non-CGO build (heuristic-only, no ONNX, static binary)
CGO ?= 0

# CGO build flags (only used when CGO=1)
CGO_LDFLAGS := -L$(CURDIR)/lib/$(shell go env GOARCH) -lonnxruntime
CGO_CFLAGS := -I$(CURDIR)/internal/onnxruntime_go

VERSION ?= 1.1.0
LDFLAGS := -s -w -X github.com/aegisgatesecurity/aegisgate-mcp.Version=$(VERSION)

.PHONY: build build-cgo build-lite test test-cgo test-all vet fmt race docker docker-lite pentest clean help

## build: Build the MCP server binary (default: non-CGO)
build:
	CGO_ENABLED=$(CGO) go build -ldflags="$(LDFLAGS)" -o mcp-server ./cmd/mcp-server

## build-cgo: Build with full ML support (requires libonnxruntime.so)
build-cgo:
	CGO_ENABLED=1 CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		go build -ldflags="$(LDFLAGS)" -o mcp-server ./cmd/mcp-server

## build-lite: Build heuristic-only (static binary, no CGO)
build-lite:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o mcp-server ./cmd/mcp-server

## test: Run non-CGO test suite (heuristic-only)
test:
	CGO_ENABLED=0 go test -count=1 -timeout 120s ./...

## test-cgo: Run CGO test suite (full ML, requires libonnxruntime.so)
test-cgo:
	CGO_ENABLED=1 CGO_LDFLAGS="$(CGO_LDFLAGS)" go test -count=1 -timeout 120s ./...

## test-all: Run both test suites
test-all: test test-cgo

## vet: Run go vet (both modes)
vet:
	CGO_ENABLED=0 go vet ./...
	CGO_ENABLED=1 CGO_LDFLAGS="$(CGO_LDFLAGS)" go vet ./...

## fmt: Format all Go files
fmt:
	gofmt -w .
	gofmt -l .  # Verify clean

## race: Run race detector (requires CGO)
race:
	CGO_ENABLED=1 CGO_LDFLAGS="$(CGO_LDFLAGS)" go test -race -count=1 -timeout 180s ./...

## docker: Build Docker image (ML-enabled, ~135 MB)
docker:
	docker build -t aegisgate-mcp:latest .

## docker-lite: Build lightweight Docker image (heuristic-only, ~8 MB)
docker-lite:
	docker build --build-arg CGO_ENABLED=0 -t aegisgate-mcp:lite .

## pentest: Run Docker pentest suite (7 security tests)
pentest:
	docker compose --profile pentest up -d
	@echo "Waiting for containers to start..."
	sleep 5
	docker exec mcp-pentest bash -c "cd /audit/scripts && bash run_pentest.sh"
	docker compose --profile pentest down -v

## clean: Remove build artifacts
clean:
	rm -f mcp-server cover.out cover.html

## help: Show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ': '