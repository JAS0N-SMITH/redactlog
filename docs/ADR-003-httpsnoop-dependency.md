# ADR-003: httpsnoop dependency vs vendor vs custom ResponseWriter wrapper

**Status**: Accepted
**Date**: 2026-04-23

## Context

HTTP middleware needs to capture the response status code and optionally mirror response body bytes without breaking the `http.ResponseWriter` interface. In production, `ResponseWriter` values may implement optional interfaces beyond the base three (`Write`, `WriteHeader`, `Header`): `http.Flusher`, `http.Hijacker`, `http.CloseNotifier`, `io.ReaderFrom`, `http.Pusher`, and deadliner interfaces added in later Go versions. A naïve wrapper struct that only embeds `http.ResponseWriter` silently drops these optional interfaces, breaking WebSocket upgrades (`Hijacker`), SSE streaming (`Flusher`), and HTTP/2 push (`Pusher`).

Candidates:

1. **`github.com/felixge/httpsnoop`** — code-generated wrapper that exhaustively handles all 128 combinations of the 7 interfaces, maintained, zero external dependencies.
2. **Vendor `httpsnoop` into `internal/`** — avoids the direct dependency but creates a silent divergence risk as upstream fixes bugs.
3. **Custom implementation** — maximum control but guaranteed to miss at least one interface combination.

## Decision

Depend directly on `github.com/felixge/httpsnoop`. Use `httpsnoop.Wrap` with a `httpsnoop.Hooks` value for response-writer capture in `httpmw/responsewriter.go`. No custom `ResponseWriter` wrapper type is defined.

## Consequences

- All 128 interface combinations are handled correctly by construction; WebSocket, SSE, and HTTP/2 push work without any per-interface code in `redactlog`.
- `httpsnoop` has zero transitive dependencies, so our dependency closure stays minimal.
- Upstream benchmark shows ~500 ns overhead per wrap call — negligible compared to body-scanning cost.
- Adds one direct dependency to `go.mod`. Any future upgrade to `httpsnoop` requires deliberate review (per §13 dependency discipline).
- Vendoring is explicitly not done; upstream security fixes and interface additions are picked up by bumping the version.
