# v2 ideas

Features requested during v1 development that are explicitly deferred.

Format:

```
## <feature name>
Date: YYYY-MM-DD
Proposer: <github handle or "internal">
Why v2: <one sentence>
```

## redact.MustNew and redact.Engine.With composition helpers
Date: 2026-04-24
Proposer: internal
Why v2: An earlier roadmap draft listed `MustNew` (panic-on-bad-DSL ergonomics, à la `regexp.MustCompile`) and `With` (engine composition / additive ruleset extension) on the public `Engine`; architecture.md §3.2 does not include them, so they are deferred to keep the v1 surface minimal and reviewable. Revisit once dogfooding (Phase A, week 4) shows whether the ergonomic gap is real.
