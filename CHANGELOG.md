# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-04-27

### Added

- `NewPCI()` now wires the full PCI-DSS preset: PAN/CVV/track-data redaction
  paths (`*.cvv`, `*.cvv2`, `*.cvc`, `*.pin`, `*.pan`, `*.card_number`,
  `*.cardNumber`, `*.track1`, `*.track2`, `*.card.number`, `*.card.cvv`,
  `*.payment.card.*`, `*.payment_method.card.number`) plus header denylist
  additions (`authorization`, `cookie`, `set-cookie`).
- `redact.PANDetector()` — content-based PAN detection. Uses a 13–19 digit
  regex with optional space/dash separators, validated by the Luhn algorithm,
  and masks results to first-6/last-4 per PCI DSS 4.0 §3.4.1
  (e.g., `4111111111111111` → `411111******1111`). Off by default (ADR-007);
  enabled by `NewPCI`. `redact.Engine.Redact` and the slog handler path both
  apply detectors to string leaves that survive path matching.
- `redact.AuthHeaderDetector()` — strips the token from `Bearer <token>` HTTP
  Authorization values, preserving the scheme name.
- `internal/luhn` — branchless Luhn checksum implementation used by
  `PANDetector`. Benchmarks at ≤ 50 ns for a 16-digit string.
- `preset_pci.go` — unexported PCI path and header-denylist constants consumed
  by `NewPCI`.
- `redact/detect.go` — `PANDetector`, `AuthHeaderDetector` (both satisfy the
  `redact.Detector` interface).
- `testdata/golden/` — 20 synthesized payment-payload golden tests (zero false
  negatives) and 20 non-payment golden tests (zero false positives), driven by
  `redact/golden_test.go` with an `-update` flag for regeneration.

## [0.4.0] - 2026-04-27

### Added

- `gin/middleware.go` — `New(h *redactlog.Handler) gin.HandlerFunc` thin adapter
  bridging Gin's `*gin.Context` to `httpmw` internals. Injects Gin's route
  template (`c.FullPath()`) as `http.route` post-`c.Next()` and reads Gin's
  internal status via `c.Writer.Status()` (required because Gin's
  `ResponseWriter` may not propagate `WriteHeader` through httpsnoop's hook).
- `gin/middleware.go` — `NewWithConfig(cfg redactlog.Config) (gin.HandlerFunc, error)`
  convenience constructor.
- `handler_test.go` — `TestHandlerLogger`, `TestHandlerMiddleware`,
  `TestHandlerMiddlewareWithRouteFunc`, `TestNilHandlerMiddleware` closing
  coverage on the three primary stable API entry points.

## [0.3.0] - 2026-04-26

### Added

- `httpmw/middleware.go` — `Middleware(cfg Config) func(http.Handler) http.Handler`
  framework-agnostic net/http middleware. Captures request/response metadata and
  bodies (configurable), scrubs headers per allow/deny-list, generates/propagates
  `X-Request-ID`, and emits all required OTel semconv v1.26.0 attributes:
  `http.request.method`, `http.response.status_code`, `url.path`, `server.address`,
  `client.address`, `network.protocol.version`, `user_agent.original`.
- `httpmw/body.go` — bounded request body tee using `io.LimitedReader` (N+1 for
  truncation detection) and `io.MultiReader` to restore `r.Body` for downstream handlers.
- `httpmw/response.go` — `httpsnoop.Wrap`-based response capture. Preserves
  `http.Flusher`, `http.Hijacker`, `http.Pusher`, `io.ReaderFrom`, and
  `http.ResponseController`. SSE (`text/event-stream`) short-circuits body
  buffering on first Flush per ADR-006.
- `httpmw/headers.go` — header scrubbing with allowlist/denylist modes using
  `http.CanonicalHeaderKey` comparison.
- `handler.go` — `Handler.Middleware()`, `Handler.MiddlewareWithRouteFunc()`,
  `Handler.MiddlewareForGin()` wired to `httpmw.Middleware`.
  `applyHTTPConfigDefaults` applies default deny list (authorization, cookie,
  set-cookie, proxy-authorization, x-api-key, x-auth-token, x-csrf-token,
  x-xsrf-token, x-session-id, x-forwarded-authorization) when no allowlist or
  denylist is configured.
- `options.go` — expanded functional option set: `WithRequestBody`,
  `WithResponseBody`, `WithMaxBodyBytes`, `WithContentTypes`,
  `WithHeaderDenylist`, `WithHeaderAllowlist`, `WithSensitiveQueryParams`,
  `WithRequestIDHeader`, `WithGenerateRequestID`, `WithSkipPaths`.

## [0.2.0] - 2026-04-26

### Added

- `handler.go` — `Handler`, a `slog.Handler` wrapper implementing all four
  methods (`Enabled`, `Handle`, `WithAttrs`, `WithGroup`). Redacts attributes
  via the `redact.Engine` trie before delegating to the inner handler. Resolves
  `slog.LogValuer` values before path matching. Passes `slogtest.TestHandler`
  conformance.
- `context.go` — `SetAttrs` / `attrsFromCtx` context-propagation helpers (~20
  LOC inline implementation, no `slog-context` dependency per ADR-005).
- `handler.go` — `Handler.Logger()` returning an `*slog.Logger` backed by the
  redacting handler; `Handler.Middleware()` stub (full implementation in M4).
- `redactlog.go` — `New` and `NewPCI` constructors; `Config.Build` validates
  and compiles the engine.
- `options.go` — full functional-option set: `WithLogger`, `WithRedactPaths`,
  `WithCensor`, `WithDetectors`, `WithClock`.
- `errors.go` — `ErrNoLogger`, `ErrInvalidPath`, `ErrBadCensor` sentinel errors.

### Fixed

- `Handler.WithAttrs` no longer double-emits pre-loaded attributes. Attributes
  passed via `WithAttrs` are propagated to the inner handler (so it can
  pre-encode them) and are not also replayed into the `slog.Record` in `Handle`.
  Previously, opening a group after `WithAttrs` caused those attributes to
  appear nested under the group, breaking `slogtest`'s empty-group invariant.

## [0.1.0] - 2026-04-19

### Added

- Initial project scaffolding.
- `redact/dsl.go` — Pino-style path DSL lexer/parser. Accepts dotted paths,
  bracket-quoted keys (`["x-api-key"]`), single-segment wildcards (`*`), and
  array wildcards (`[*]`); rejects `**`, numeric indices, negation, and
  glob char-classes per architecture §6.1 / ADR-002.
- `redact/compile.go` — `Program` type, immutable trie compiler. `*` and
  `[*]` collapse into one `wildChild` slot per architecture §6.4.
- `redact/walk.go` — recursive depth- and node-bounded walker
  (defaults: 32 / 10000) with multi-state trie traversal so overlap rules
  like `a.b.password` + `a.*.token` redact correctly. Fails closed to the
  censor token on bound exceedance per architecture §12.1. Resolves
  `slog.LogValuer` before path matching.
- `redact/redactor.go` — public `Engine` (opaque), `Options`, `Detector`
  interface, `Redactor` interface, `New`, `Engine.Program`,
  `Engine.RedactValue` (slog hot path), `Engine.Redact` (body-capture entry
  for `map[string]any` / `[]any` / scalars). `DefaultCensor = "***"`.

### Changed

- CI workflows pinned to `go-version: stable` (and `1.25` floor) to match
  `go.mod`'s 1.25.9 floor; previous draft used 1.23.
- `docs/v1roadmap.md` §M1, §M2 deliverables and §9 tooling table reconciled
  with `docs/architecture.md` (authoritative module layout uses
  `internal/{bufpool,canonheader,luhn,ringbuf}` rather than the earlier
  `internal/{trie,walker}` draft; M2 walker is recursive, not iterative;
  `MustNew` and `Engine.With` deferred to v2).
