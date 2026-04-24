# ADR-008: Single censor token ("***") vs type-specific tokens

**Status**: Accepted
**Date**: 2026-04-23

## Context

When a field is redacted, a replacement value must be written in its place. Two approaches:

1. **Single token** — always emit `"***"` (or a user-configured alternative). Simple, uniform.
2. **Type-specific tokens** — emit `"[STRING]"`, `"[INT]"`, `"[EMAIL]"`, `"[PAN]"`, etc., indicating the original type or detector that triggered the redaction.

Type-specific tokens provide richer debuggability: an operator can distinguish "this was a string that contained something sensitive" from "this was an integer". However, they also leak information: a log showing `"ssn": "[STRING]"` tells an attacker that an SSN field exists in the payload even if the value is hidden. Compliance reviewers in fintech/healthtech prefer that redacted fields not advertise the category of data they contained.

Additionally, type-specific tokens complicate the censor interface: the redactor must know which detector matched, propagate that signal to the output stage, and keep the token vocabulary in sync with the detector registry.

## Decision

Use a single default censor token `"***"` for all redactions. The token is user-configurable via `WithCensor(s string)` — a user who prefers `"[REDACTED]"` sets it in one option. Type-specific tokens are not supported in v1; users who need richer placeholders implement a custom `Detector` that returns named strings from its `Detect` method.

## Consequences

- Redacted fields are indistinguishable from each other by value — no information leakage about which detector matched or what type was redacted.
- Simpler engine: the censor value is a single string on `Program`, propagated uniformly.
- Easier to grep in log analysis tools: one constant string to filter on.
- Shorter than `"[REDACTED]"` — reduces log volume at scale (billions of events in fintech/healthtech).
- Matches Pino's common deployment convention (many `fast-redact` users choose `"***"` or `"**"`).
- Debuggability trade-off: operators cannot tell from the log alone whether a field was redacted by path or by detector. Mitigation: internal telemetry under a reserved key records redaction counts by rule at DEBUG level (not surfaced in the main log line).
- Users who need type-specific tokens use a custom `Detector` returning a named placeholder string; this is documented in the `redact` package godoc.
