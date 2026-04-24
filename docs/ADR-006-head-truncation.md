# ADR-006: First-N head truncation vs first-N + last-M ring buffer

**Status**: Accepted
**Date**: 2026-04-23

## Context

HTTP body capture requires a size limit to prevent unbounded memory usage. Two strategies:

1. **Head truncation** — capture the first N bytes only, discard the rest. ~20 LOC, zero allocations after the initial buffer pool `Get`.
2. **Ring buffer (first-N + last-M)** — capture the first N bytes and the last M bytes, giving visibility into both request headers and error trailers. ~150 LOC, doubles per-request capture memory (two windows), adds non-trivial implementation complexity.

The debugging case for ring buffers is real: HTTP error responses typically include error details in the body trailer that head truncation would discard. However, the majority of production ops use cases (log ingestion, anomaly detection, PCI audit) care about the beginning of the request body, not the end.

## Decision

Implement head truncation only for v1. The `internal/ringbuf/` placeholder is reserved but not wired in. The `+ 1` trick on `io.LimitedReader` detects truncation: if we read one byte beyond the limit, we know more data was available, and `CapturedRequest.BodyTruncated` is set to `true`.

Ring buffer support is deferred to v2 behind `WithBodyRingBuffer(headN, tailM int)`.

## Consequences

- Implementation is ~20 LOC and integrates cleanly with the existing `sync.Pool[*bytes.Buffer]` buffer pool.
- Per-request memory overhead is bounded to `MaxBodyBytes` (default 64 KiB) plus one byte for truncation detection.
- Users debugging errors that appear only in response trailers will not see those bytes; they must rely on their application's own error logging.
- `BodyTruncated bool` on `CapturedRequest` and `CapturedResponse` gives users a signal that truncation occurred, so they can log separately if needed.
- `internal/ringbuf/placeholder.go` exists as an explicit marker; contributors must not wire it in without a v2 ADR.
