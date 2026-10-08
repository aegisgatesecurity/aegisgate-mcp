## Description

<!-- Brief description of the change -->

## Type of Change
- [ ] Bug fix (non-breaking)
- [ ] New feature
- [ ] Security improvement
- [ ] Documentation update
- [ ] Refactor / cleanup

## Testing
- [ ] All tests pass (non-CGO: `CGO_ENABLED=0 go test ./...`)
- [ ] All tests pass (CGO: `CGO_ENABLED=1 go test ./...`)
- [ ] Coverage ≥ 90%
- [ ] `gofmt -l .` returns empty
- [ ] `go vet ./...` passes (both CGO and non-CGO)
- [ ] OPSEC scan passes (`tools/opsec-scan.sh`)

## Checklist
- [ ] DCO signoff (`git commit -s`)
- [ ] No secrets / API keys committed
- [ ] No internal paths or documentation references
- [ ] Protected paths unchanged (internal/ml/, lib/, models/, internal/onnxruntime_go/)