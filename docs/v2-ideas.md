# v2 ideas

Features requested during v1 development that are explicitly deferred.

Format:

```
## <feature name>
Date: YYYY-MM-DD
Proposer: <github handle or "internal">
Why v2: <one sentence>
```

## IIN-range sanity check in PANDetector
Date: 2026-04-30
Proposer: internal
Why v2: M6 roadmap listed IIN-range (Visa 4, MC 51-55 / 2221-2720, Amex 34/37, Discover 6011 / 622126-622925 / 644-649 / 65) as a risk mitigation for false positives. The negative golden corpus (20 cases: phone numbers, SSNs, UUIDs, timestamps, sequential/all-ones/all-nines 16-digit strings) shows zero false positives with regex+Luhn alone. Luhn already provides strong rejection of random numeric sequences. IIN-range adds implementation complexity for unconfirmed benefit in v1; defer to v2 once production usage patterns emerge.

## redact.MustNew and redact.Engine.With composition helpers
Date: 2026-04-24
Proposer: internal
Why v2: An earlier roadmap draft listed `MustNew` (panic-on-bad-DSL ergonomics, à la `regexp.MustCompile`) and `With` (engine composition / additive ruleset extension) on the public `Engine`; architecture.md §3.2 does not include them, so they are deferred to keep the v1 surface minimal and reviewable. Revisit once dogfooding (Phase A, week 4) shows whether the ergonomic gap is real.
