# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
