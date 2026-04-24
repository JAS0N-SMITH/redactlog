# ADR-005: Context attrs via slog-context dependency vs own implementation

**Status**: Accepted
**Date**: 2026-04-23

## Context

HTTP middleware needs to attach per-request attrs (e.g., `request_id`, `user_id`) to a context so that `slog.Logger` calls made deep in the handler stack automatically include them. Two approaches:

1. **`veqryn/slog-context` or `samber/slog-context`** — third-party libraries that provide context-scoped slog attribute propagation.
2. **Own inline implementation** — `SetAttrs` / `attrsFromCtx` using `context.WithValue`, approximately 20 lines in `context.go`.

The "extractor-handler pattern" is well-understood: store `[]slog.Attr` under a package-private key in the context; the handler's `Handle` method pulls them out before emitting the record.

## Decision

Implement the pattern inline in `context.go` (~20 lines). Export `SetAttrs(ctx, ...slog.Attr) context.Context` as the only public API. No dependency on `veqryn/slog-context` or `samber/slog-context`.

## Consequences

- Eliminates two candidate dependencies; keeps `go.mod` minimal.
- The implementation is trivially small, easy to audit, and has no stability risk from a third-party maintainer.
- We own the code and can evolve the context key type without waiting for an upstream release.
- If `slog-context` becomes the de-facto standard for this pattern (e.g., adopted by the Go team), we reconsider in v2. The migration would be a drop-in rename of `redactlog.SetAttrs` to the library's equivalent.
- Users familiar with `samber/slog-context` will find `redactlog.SetAttrs` analogous; it is documented with a migration note for those coming from that library.
