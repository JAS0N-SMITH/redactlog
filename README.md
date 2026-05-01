# redactlog

> Redaction-first HTTP logging middleware for Go services in regulated industries.
>
> **Compliant. Automatic. Transparent.** Drop in a middleware, wire a logger, and sensitive fields are scrubbed before log emission.

**Status**: v1.0.0 in progress (M9/12 complete). Pre-release; API stable; **not yet production-ready**.

---

## What it is

`redactlog` is a `slog.Handler` wrapper and HTTP middleware for Go (net/http + Gin) that redacts sensitive fields — credit card numbers, tokens, email addresses, headers — before a log line is emitted. It uses a compile-once **Pino-style path DSL** to match field names (e.g., `user.password`, `payment.cards[*].pan`) and **content-based detectors** (Luhn validator for PANs, regex for Bearer tokens) to catch unstructured secrets. A single **PCI compliance preset** handles the most common redaction patterns; for custom schemas, build a handler with `New()` and `WithRedactPaths()`.

Redaction is orthogonal to your logging framework. `redactlog` wraps your existing `slog.Logger` and transparently redacts attributes in-flight — no code changes to existing log calls, no performance cliff when you have 50 sensitive fields.

---

## When to use it

| Scenario | Use `redactlog`? | Alternative |
|----------|------------------|-------------|
| You must not log credit card numbers or auth tokens (PCI, SOC2, GDPR) | ✅ Yes — PCI preset, or custom paths | Hand-rolled `slog.ReplaceAttr`; zerolog/zap hooks |
| You log unstructured blobs (webhook bodies, error stack traces) and need content-based redaction (Luhn PAN detection) | ✅ Yes — `PANDetector`, or custom detectors | String preprocessing before logging |
| You want middleware that captures request/response bodies under byte limits with safe defaults | ✅ Yes — `h.Middleware()` or `h.MiddlewareForGin()` | httpsnoop directly; custom middleware |
| You already use slog and Gin/net/http; minimal integration | ✅ Yes | Roll your own; adopt a heavier APM/SIEM platform |
| You need audit chains, crypto-shredding, multi-tenant key management, or a Splunk exporter | ❌ No — v2+ feature | Roll your own; platform-specific tooling |

---

## Quick start: net/http

Wrap your logger with the PCI preset and attach the middleware to your router:

```go
package main

import (
	"log/slog"
	"net/http"
	"github.com/JAS0N-SMITH/redactlog"
)

func main() {
	h, _ := redactlog.NewPCI(
		redactlog.WithLogger(slog.Default()),
		redactlog.WithRequestBody(true),
		redactlog.WithResponseBody(true),
	)
	
	mux := http.NewServeMux()
	mux.HandleFunc("/pay", handlePayment)
	
	// Wrap the entire router with logging middleware
	http.ListenAndServe(":8080", h.Middleware()(mux))
}

func handlePayment(w http.ResponseWriter, r *http.Request) {
	logger := r.Context().Value(/* your logger */).(*slog.Logger)
	logger.Info("payment", slog.String("pan", "4111111111111111")) // outputs: pan: ***
	w.WriteHeader(200)
}
```

---

## Quick start: Gin

Register the middleware on your router:

```go
package main

import (
	"log/slog"
	"github.com/gin-gonic/gin"
	"github.com/JAS0N-SMITH/redactlog"
	"github.com/JAS0N-SMITH/redactlog/gin"
)

func main() {
	h, _ := redactlog.NewPCI(
		redactlog.WithLogger(slog.Default()),
		redactlog.WithRequestBody(true),
	)
	
	r := gin.New()
	r.Use(gin.New(h))           // redactlog middleware
	r.Use(gin.Recovery())       // panic recovery *after* redactlog
	
	r.POST("/pay", handlePayment)
	r.Run(":8080")
}

func handlePayment(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok", "pan": "4111111111111111"}) // body: pan: ***
}
```

---

## PCI preset

The `NewPCI()` constructor preconfigures redactlog for Payment Card Industry compliance. It includes:

**Field redaction** (Pino-style DSL):
- PAN fields: `pan`, `card.number`, `payment.card_number`, `card_pan`, etc.
- CVV fields: `cvv`, `cvc`, `card.security_code`, etc.
- Track data: `track1`, `track2`, `track_data`, etc.
- See [redactlog/preset_pci.go](redactlog/preset_pci.go) for the full path list.

**Content-based redaction** (requires matching content, not field name):
- **PAN detection**: Luhn validator + BIN regex. Matches 12–19-digit sequences with optional spaces/dashes. Masked as `411111******1111` (first 6, last 4, rest `*`).
- **Auth headers**: Bearer tokens and API key schemes. Replaces token/key portion while preserving scheme (`Bearer ***`).

**Header redaction**:
- Denylist: `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key*` (and user-supplied additions).

**What it does NOT redact**:
- Unstructured fields not in the redaction path list.
- Integers or boolean fields (only strings can contain PANs).
- Request/response status codes or content-type headers.
- Custom headers not on the denylist.

To customize, pass additional options to `NewPCI()`:

```go
h, _ := redactlog.NewPCI(
	redactlog.WithLogger(slog.Default()),
	redactlog.WithRedactPaths("custom.field", "my.secret[*]"),        // append custom paths
	redactlog.WithHeaderDenylist("X-Custom-Auth"),                     // append headers
	redactlog.WithSensitiveQueryParams("api_key", "session_id"),       // append query params
)
```

---

## Performance

`redactlog` is designed for zero-allocation on the no-match path (the common case). Redaction of 1 KB of JSON with 10 rules takes < 500 ns. HTTP middleware overhead (no body capture) is < 1 µs per request. Benchmarks are in [BENCHMARKS.md](BENCHMARKS.md).

---

## Stability guarantees

**After v1.0.0:**
- Exported symbols in packages `redactlog`, `redact`, `httpmw`, `gin` are subject to semantic versioning (no breaking changes in v1.x).
- The `Config` builder API (`New`, `NewPCI`, `WithLogger`, `WithRedactPaths`, etc.) is stable.
- DSL syntax (Pino-style paths) is stable.
- The single censor token `"***"` and PAN masking format (first-6/last-4) are stable.

**Not stable:**
- Internal packages (`internal/*`) are not exported and subject to change without notice.
- Undocumented or unexported symbols have no stability guarantee.

**Pre-v1.0.0:**
- The API may change until the v1.0.0 tag. If you depend on an unreleased version, pin the commit.

---

## Contributing and roadmap

Report bugs and request features in [GitHub Issues](https://github.com/JAS0N-SMITH/redactlog/issues).

The v1 roadmap is in [docs/v1roadmap.md](docs/v1roadmap.md). v2+ features (Merkle audit logs, GDPR preset, multi-framework adapters, vendor exporters) are listed in [docs/v2-ideas.md](docs/v2-ideas.md).

For contribution guidelines, see [CLAUDE.md](CLAUDE.md) (humans and Claude Code agents).

---

## Architecture and design

- [docs/architecture.md](docs/architecture.md) — full v1 design document
- [docs/ADR-001.md](docs/ADR-001.md) through [docs/ADR-008.md](docs/ADR-008.md) — architectural decision records
- [BENCHMARKS.md](BENCHMARKS.md) — comparative benchmarks vs. zap/zerolog/logr

---

## Development

Quick reference for local work:

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
go tool cover -html=coverage.out  # open in browser
go tool cover -func=coverage.out | tail -1  # summary line

# Benchmarks (local, for benchstat before/after)
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench-before.txt
# ... make changes ...
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench-after.txt
go install golang.org/x/perf/cmd/benchstat@latest
benchstat bench-before.txt bench-after.txt

# Fuzz a single target locally
go test -run=^$ -fuzz=FuzzRedactWalk -fuzztime=30s ./redact

# Update a dependency
go get github.com/felixge/httpsnoop@latest && go mod tidy

# Preview pkg.go.dev rendering locally
go install golang.org/x/pkgsite/cmd/pkgsite@latest
pkgsite -http :6060
# then open http://localhost:6060/github.com/JAS0N-SMITH/redactlog
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
