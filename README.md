# redactlog

> Redaction-first HTTP logging middleware for Go services in regulated industries.

**Status**: under active development (pre-v1.0.0). Do not use in production yet.

See:

- [docs/architecture.md](docs/architecture.md) — full v1 architecture
- [docs/v1roadmap.md](docs/v1roadmap.md) — 12-week solo shipping plan
- [docs/](docs/) — ADRs 001–008
- [CLAUDE.md](CLAUDE.md) — contribution conventions (human and agent)

## Quick start

Coming in M9.

Quick reference for the loop you'll run repeatedly:

```bash
# Fast local loop
go test -short ./...

# Full local loop (pre-push)
go test -race ./...
golangci-lint run
govulncheck ./...

# Format everything
golangci-lint fmt

# Coverage
go test -race -coverprofile=coverage.out ./...
# open in browser
go tool cover -html=coverage.out  
# summary line
go tool cover -func=coverage.out | tail -1  

# Benchmarks (local, for benchstat before/after)
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench-before.txt
# ... make changes ...
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench-after.txt
# first time, install benchstat
go install golang.org/x/perf/cmd/benchstat@latest
# then compare
benchstat bench-before.txt bench-after.txt
# full script to run locally
cd redactlog && ./bench/benchmark.sh

# Fuzz a single target locally
go test -run=^$ -fuzz=FuzzRedactWalk -fuzztime=30s ./redact

# Update a single dependency
go get github.com/felixge/httpsnoop@latest && go mod tidy

# Tidy and check for drift
go mod tidy && git diff go.mod go.sum

# Preview pkg.go.dev rendering locally
pkgsite -http :6060
# then open http://localhost:6060/github.com/JAS0N-SMITH/redactlog

# Tag a release (pre-v1)
git tag -s v0.1.0 -m "v0.1.0: redact engine complete (M2)"
git push origin v0.1.0
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
