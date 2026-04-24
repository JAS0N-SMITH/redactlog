# ADR-007: Regex-based detection off by default (opt-in via detectors)

**Status**: Accepted
**Date**: 2026-04-23

## Context

Content-based detectors (e.g., `PANDetector` using Luhn + regex) can redact sensitive values that appear in unexpected fields — values that path-based rules would miss because the path was not listed. Two stances:

1. **On by default** — `PANDetector` always active; every string leaf is scanned for 13–19-digit sequences, Luhn-validated, and masked if matched.
2. **Off by default** — detectors are opt-in; users enable them explicitly or use a preset like `NewPCI()` that bundles them.

Regex detection is O(body size) on the hot path. Libraries that impose unexpected performance regressions get uninstalled. False positives are also possible: order IDs, phone strings with dashes, and UUIDs-as-digit-sequences can match the digit-count heuristic before Luhn filtering.

## Decision

Regex-based detection is **off by default**. `Config.Detectors` is nil when `New()` is called without explicit options. `NewPCI()` adds `PANDetector()` as a preset default — users who opt into PCI mode explicitly opt into PAN scanning. Path redaction (the primary feature) always runs.

## Consequences

- `New()` callers without detectors will not catch a PAN that leaks via an unexpected field; they must add `WithDetectors(redact.PANDetector())` or use `NewPCI()`. README documents this prominently.
- No latency surprise for users who use `New()` for non-PCI contexts (queue redaction, internal service logs) where regex scanning is inappropriate.
- `NewPCI()` is the one-line upgrade: switching from `New()` to `NewPCI()` automatically enables PAN scanning plus PCI-appropriate path defaults.
- Third-party detectors implementing the `Detector` interface can be added via `WithDetectors(...)` without any changes to the core engine.
- Per-detector false-positive risk is owned by the detector implementation; `PANDetector` uses Luhn validation to minimize false positives.
