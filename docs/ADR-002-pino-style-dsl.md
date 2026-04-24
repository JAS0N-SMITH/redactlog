# ADR-002: Pino-style path DSL vs GJSON vs JSONPath

**Status**: Accepted
**Date**: 2026-04-23

## Context

`redactlog` needs a user-facing syntax for specifying which fields to redact. Candidates considered:

1. **Pino-style / `fast-redact` subset** — dotted paths with bracket notation and wildcards (`a.b[*].c`, `a.*.b`, `a["x-key"]`).
2. **GJSON path syntax** — a read-oriented query language with filters and modifiers.
3. **JSONPath** (`$.req.body.password`) — the RFC 9535 standard with recursive-descent (`..`) operators.
4. **Custom grammar** — bespoke syntax designed from scratch.

The path syntax must compose cleanly with `slog.Group` hierarchies (dotted + indexed), be recognizable to backend engineers, and avoid operators that make it easy to accidentally over-redact.

## Decision

Implement a strict subset of Pino's `fast-redact` path syntax. Legal constructs: dotted paths (`a.b.c`), bracket notation for non-identifier keys (`a["x-key"]`), terminal wildcards (`a.*`), intermediate single-segment wildcards (`a.*.b`), array wildcards (`a[*]`, `a[*].b`), and top-level intermediate wildcards (`*.x`).

Explicitly rejected: recursive descent (`**`), numeric array indices (`a[0]`), negated paths (`!a.b`), glob character classes (`a.[pP]assword`).

## Consequences

- DSL is familiar to backend engineers who have done any Node.js work with Pino/fast-redact.
- Maps cleanly onto `slog.Group` hierarchies — both use dotted + indexed notation.
- Recursive descent is excluded, preventing accidental over-redaction of an entire document.
- Numeric array indices are not supported in v1 (rarely useful in log records; ambiguous under slog groups).
- GJSON's filter syntax (`#[name=="x"]`) is unavailable; users needing per-element conditional redaction must use a custom `Detector`.
- JSONPath's `$` prefix and `..` operator are not supported; engineers coming from JSON Schema may need to adjust.
- Paths are compiled into a trie at `New()` time — runtime walk is a map lookup per segment, not a regex scan.
