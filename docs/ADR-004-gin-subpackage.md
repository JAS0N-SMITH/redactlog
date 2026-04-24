# ADR-004: Dedicated gin/ subpackage vs adapter via gin.WrapH

**Status**: Accepted
**Date**: 2026-04-23

## Context

`redactlog` targets both `net/http` and Gin users. Three integration strategies were considered:

1. **`gin.WrapH` guidance** — document that users call `gin.WrapH(h.Middleware()(next))` themselves. Simple, but forces users to reason about the adapter and loses `gin.Context` niceties.
2. **Native `*gin.Context` reimplementation** — duplicate body capture, header scrubbing, and httpsnoop wrapping against the Gin API directly.
3. **Dedicated `gin/` subpackage** — a thin 30-line bridge that delegates all heavy work to `httpmw`, presented as `redactgin.New(h)`.

Go modules cannot scope a dependency to a single subdirectory, so `gin-gonic/gin` would appear in `go.mod` regardless. Keeping the import isolated to a subpackage lets `go list` and import-graph checks enforce that no other package in the module touches Gin.

## Decision

Create a dedicated `gin/` subpackage (`package gin`, imported as `redactgin` at usage sites). `redactgin.New(h)` returns a `gin.HandlerFunc` that bridges `*gin.Context` to the `net/http` middleware in `httpmw`. All body capture, header scrubbing, and httpsnoop wrapping live exclusively in `httpmw`; the Gin adapter is a 30-line wrapper. `gin-gonic/gin` is imported **only** in `gin/`.

## Consequences

- Gin and `net/http` users get identical redaction behavior by construction — there is no separate code path to maintain or diverge.
- `go get github.com/jas0n-smith/redactlog` does not drag in `gin-gonic/gin` for users who only use the `net/http` middleware. They import `gin/` explicitly.
- The "gin imports only in `gin/`" rule is enforceable via a CI script (`scripts/check-gin-scope.sh`).
- `gin.BodyBytesKey` cache integration and `c.Copy()` goroutine guidance are documented in the `gin/` package godoc.
- Panic recovery ordering (register `gin.Recovery()` after `redactgin.New(h)`) is documented; incorrect ordering causes the middleware to log a 200 on a panicking request.
- Mirrors the layout used by `go.opentelemetry.io/contrib/instrumentation/*` for framework-specific adapters.
