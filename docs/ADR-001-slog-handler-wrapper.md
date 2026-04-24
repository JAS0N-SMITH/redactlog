# ADR-001: slog.Handler wrapper vs ReplaceAttr-only

**Status**: Accepted
**Date**: 2026-04-23

## Context

`redactlog` needs to intercept structured log records and redact sensitive fields before they reach any downstream sink. Go's `log/slog` offers two integration points: a `ReplaceAttr` function hook on the terminal handlers (`JSONHandler`, `TextHandler`), or a full `slog.Handler` wrapper that sits in front of the user's handler.

`ReplaceAttr` runs inside the terminal handler and sees attributes one at a time, after group hierarchies have been textually flattened. This makes path-based redaction ambiguous: a key `"password"` at the top level and a key `"password"` nested inside `slog.Group("req")` look the same. Additionally, `ReplaceAttr` cannot be plumbed into arbitrary third-party handlers (Datadog, Sentry, etc.) — only into `slog.HandlerOptions`-aware handlers.

The official Go team slog-handler-guide endorses the handler-wrapper pattern for cross-cutting transformations such as redaction.

## Decision

Implement a full `slog.Handler` wrapper (`redactlog.Handler`) that sits in front of the user's existing handler. All four methods — `Enabled`, `Handle`, `WithAttrs`, `WithGroup` — are implemented. Redaction happens in `Handle` and at `WithAttrs` time (pre-redacting accumulated attrs). `ReplaceAttr` is not used.

## Consequences

- Path-based redaction can be fully group-aware: `WithGroup("req")` followed by `slog.String("password", ...)` correctly matches DSL path `req.password`.
- `WithAttrs` pre-redacts accumulated attrs, so handlers cloned via `logger.With(...)` pay the redaction cost once, not on every `Handle` call.
- Works with any downstream `slog.Handler` regardless of implementation.
- Slightly more code than a `ReplaceAttr` shim; users who already use `ReplaceAttr` for formatting must layer ours in front (documented in README).
- Requires correct implementation of all four handler methods; skipping `WithGroup` or `WithAttrs` would break `slogtest.TestHandler` conformance.
