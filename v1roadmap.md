# Redactlog v1.0.0 roadmap: a solo 12-week plan

## 1. Executive summary

This roadmap sequences `redactlog` v1.0.0 across **10 milestones over 12 calendar weeks**, budgeted at **~115 engineering hours** (10 hrs/week average, with two explicit buffer weeks). The work proceeds bottom-up: scaffolding and the pure redaction engine first (so it can be dogfooded in the Fintech portfolio dashboard by week 4), then the slog handler, then HTTP/Gin adapters, then hardening, benchmarks, docs, and release. The plan is deliberately conservative — it assumes at least one lost week to life, day-job crunch, or the Fintech project, and it treats every ADR and public-API surface already enumerated in the v1 architecture doc as a hard scope fence.

**Headline numbers**

| Metric | Value |
|---|---|
| Total estimated hours | ~115 (range 100–135) |
| Calendar weeks | 12 (target) / 14 (contingency) |
| Weekly budget | 8–12 hrs, averaging 10 |
| Buffer weeks included | 2 |
| Milestones | 10 |
| Hard-gated release version | v1.0.0 |

**Milestone calendar** (start = Monday of week 1, today)

| # | Milestone | Target end (week #) | Hours |
|---|---|---|---|
| M1 | Project scaffolding | W1 | 8 |
| M2 | Redaction engine core | W3 | 20 |
| M3 | slog.Handler wrapper | W4 | 10 |
| M4 | net/http middleware | W6 | 16 |
| M5 | Gin adapter | W7 | 8 |
| M6 | PCI preset + detectors | W8 | 10 |
| M7 | Testing hardening (fuzz, property, slogtest) | W9 | 12 |
| M8 | Benchmarks vs samber/slog-gin | W10 | 8 |
| M9 | Documentation | W11 | 12 |
| M10 | Release prep → v1.0.0 | W12 | 10 |
| — | Buffer / slip absorption | interspersed | ~10 |

If W12 slips, v1.0.0 tags land by end of W14. That's the ceiling.

---

## 2. Milestone breakdown

### M1 — Project scaffolding
- **Goal.** Empty-but-correct repo: `go build` and `go test` succeed on a stub, CI runs green, license and module path final.
- **Hours.** 8 · **Calendar.** 1 week
- **Dependencies.** None.
- **Deliverables.**
  - `github.com/redactlog/redactlog` repo created, `go.mod` declaring Go **1.23** (gin v1.12.0 requires 1.23+; the architecture doc's 1.22+ floor is tightened at the gin subpackage only — see §Tooling below).
  - `LICENSE` (Apache-2.0), `README.md` (one-paragraph placeholder + quick-start skeleton), `.gitignore`, `.editorconfig`.
  - Package stubs: `redactlog/`, `redact/`, `httpmw/`, `gin/`, `internal/trie/`, `internal/walker/`, each with a `doc.go` containing the package comment from the architecture doc §2.
  - `.github/workflows/ci.yml` running lint + test matrix (Go 1.23/1.24/1.25 × ubuntu/macos/windows).
  - `.golangci.yml` (v2 format, see §9).
  - `CHANGELOG.md` with an `## [Unreleased]` section.
  - `docs/` folder with the 8 ADRs copied from the design doc.
- **Risks.** CI yak-shaving; golangci-lint v2 config syntax trips you up.
- **Definition of done.** Green CI on an empty commit; `go vet`, `golangci-lint run`, `govulncheck ./...` all clean; pkg.go.dev can theoretically resolve the module path (validate by running `GOPROXY=https://proxy.golang.org go list -m github.com/redactlog/redactlog@latest` once the first tag exists in M2).

### M2 — Redaction engine core
- **Goal.** `redact.New(rules...).Redact(ctx, value)` deep-walks a `map[string]any` / `[]any` / scalar tree and applies Pino-style path rules (`*`, `**`, wildcards, array indices) with predictable semantics and O(depth × rules) performance.
- **Hours.** 20 · **Calendar.** 2 weeks
- **Dependencies.** M1.
- **Deliverables.**
  - `redact/dsl.go` — path lexer/parser producing an AST. Grammar matches the architecture doc §4.2.
  - `internal/trie/trie.go` — compiled rule trie for O(1) per-segment dispatch.
  - `internal/walker/walker.go` — iterative (not recursive) depth-limited walker with cycle detection and a configurable max depth (default 32) and max node count (default 10 000).
  - `redact/redact.go` — public `Redactor` type with `New`, `MustNew`, `Redact`, `RedactValue`, `With` (composition).
  - Table-driven unit tests covering: exact paths, single-segment wildcard, deep wildcard, array indices, `*.token`, `**.password`, case sensitivity, overlapping rules, no-match passthrough.
  - Benchmarks: `BenchmarkRedact_Flat10`, `BenchmarkRedact_Nested5x5`, `BenchmarkRedact_1KBJSON`.
- **Risks.** DSL edge cases (escaped dots, bracket syntax for keys containing dots) blow up scope. Walker recursion vs iteration trade-off.
- **Definition of done.** 95%+ line coverage on `redact/` and `internal/`; benchmarks stable (<5% run-to-run variance on a quiet laptop); `BenchmarkRedact_Nested5x5` ≤ **1.5 µs/op, 0 allocs/op on the redacted copy's scalar path** (allocs allowed only where the walker must clone containers).

### M3 — slog.Handler wrapper
- **Goal.** `redactlog.NewHandler(next slog.Handler, r *redact.Redactor)` passes `slogtest.TestHandler` conformance and correctly redacts `slog.Attr` values (including `slog.Group`, `LogValuer`, and `context`-attached attrs).
- **Hours.** 10 · **Calendar.** 1 week
- **Dependencies.** M2.
- **Deliverables.**
  - `redactlog/handler.go` implementing all four `slog.Handler` methods: `Enabled`, `Handle`, `WithAttrs`, `WithGroup`.
  - Correct `WithGroup` prefix composition with the redactor's path DSL (groups become path segments).
  - `LogValuer` resolution before redaction (per architecture §5.3).
  - Context-propagated extra attrs via `redactlog.WithAttrs(ctx, ...)` helper.
  - `handler_test.go` including a `slogtest.TestHandler(h, results)` harness.
- **Risks.** `WithAttrs` / `WithGroup` immutability semantics — an incorrect share of state across handler clones is the classic slog bug. `slogtest` is strict and will surface it.
- **Definition of done.** `slogtest.TestHandler` returns zero errors; `WithGroup("a").WithGroup("b")` produces `a.b.<attr>` paths that the redactor can match via `a.b.*` rules.

### M4 — net/http middleware
- **Goal.** `httpmw.New(opts).Wrap(next)` returns an `http.Handler` that logs request/response via a `*slog.Logger` (built on the M3 handler), captures request/response bodies up to a size cap, scrubs headers by allow-list, and correctly reports status/bytes via **httpsnoop** per ADR-003.
- **Hours.** 16 · **Calendar.** 2 weeks
- **Dependencies.** M3.
- **Deliverables.**
  - `httpmw/middleware.go` — options struct (logger, redactor, header allow-list, body cap, sample rate, clock).
  - `httpmw/body.go` — bounded request body tee'ing (`io.LimitReader` + `io.MultiWriter` to a capped buffer; do not mutate `r.Body` type beyond `io.NopCloser` wrapping).
  - `httpmw/response.go` — httpsnoop-based capture of status, bytes written, and — critically — preservation of `http.Flusher`, `http.Hijacker`, `http.Pusher`, `io.ReaderFrom` via httpsnoop's wrapper map. Also preserve `http.ResponseController` semantics.
  - `httpmw/headers.go` — allow-list scrubbing with canonical-MIME-header-key comparison; default deny for `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key` variants.
  - OTel semconv attributes emitted: `http.request.method`, `http.response.status_code`, `url.path`, `server.address`, `client.address`, `network.protocol.version`, `user_agent.original`. **Upgrade import to `semconv/v1.26.0` → `v1.30.0`** (the architecture doc pinned v1.26.0; v1.40.0 is latest as of April 2026, but stable HTTP conventions have not changed — pick the latest patch the rest of your org uses, default to `v1.30.0` for stability, leave an ADR amendment note).
  - Tests: body-capture truncation, SSE passthrough (Flusher preserved), hijack (WebSocket upgrade) passthrough, header scrubbing.
- **Risks.** SSE / streaming / WebSocket edge cases. Bodies that are `chunked` with no `Content-Length`. Large bodies consuming memory if the cap is wrong. `ReaderFrom` being silently discarded, triggering a perf cliff for file downloads.
- **Definition of done.** Integration test with an SSE handler (writes 10 events, flushes each) passes with both Flusher and status captured. Hijack test upgrades to a raw TCP echo without middleware intervention. Memory ceiling per request verified < body-cap + 4 KB overhead.

### M5 — Gin adapter
- **Goal.** `ginmw.New(opts)` returns a `gin.HandlerFunc` that wraps the net/http middleware correctly across Gin's `c.Next()` flow and surfaces Gin's route template (`c.FullPath()`) as the `http.route` attribute.
- **Hours.** 8 · **Calendar.** 1 week
- **Dependencies.** M4.
- **Deliverables.**
  - `gin/middleware.go` — thin adapter that uses `c.Request` / `c.Writer`, defers to the shared `httpmw` internals, injects `http.route` from `c.FullPath()` post-`c.Next()`.
  - `gin/gin_test.go` — integration tests mounting the middleware on a `gin.New()` engine with a router, table-test across GET/POST/streaming/404/panic-recovery.
  - Go module tidy: the `gin/` subpackage adds `gin-gonic/gin v1.12.0` as a dependency; root module remains stdlib-only (per ADR-004).
- **Risks.** Gin 1.12 requires Go 1.23+ — align the whole module's `go.mod` to 1.23. Gin's `ResponseWriter` wrapper conflicts with httpsnoop's; verify double-wrapping does not break `Flusher`/`Hijacker`.
- **Definition of done.** `go test ./gin/...` passes; a Gin server with the middleware mounted, an SSE route, and a hijacked WebSocket route all pass integration tests.

### M6 — PCI preset and detectors
- **Goal.** `preset.PCI()` returns a `*redact.Redactor` preconfigured with path rules for common PAN/CVV/track-data field names, plus a `redact.Luhn()` value-level detector for free-text fields.
- **Hours.** 10 · **Calendar.** 1 week
- **Dependencies.** M2 (engine), M4 (to exercise in the full pipe).
- **Deliverables.**
  - `redact/preset/pci.go` with documented ruleset (card_number, pan, cardNumber, cvv, cvc, cvv2, track1, track2, expiry / exp_month / exp_year when combined with PAN).
  - `redact/detect/luhn.go` — branchless Luhn check, benchmarked at ≤ 50 ns for a 16-digit string.
  - `redact/detect/pan.go` — regex for 13–19 digit sequences with optional separators, composed with Luhn for low false-positive rate.
  - Golden-file tests: input JSON bodies with embedded PANs (valid + Luhn-failing) → expected redacted output.
- **Risks.** Regex over-matching (phone numbers, timestamps). Luhn alone is insufficient — combine PAN regex + Luhn + IIN-range sanity.
- **Definition of done.** Test corpus of 20 realistic payment payloads (Stripe, Adyen, Square webhook samples — synthesized, not real) all correctly redacted; zero false positives on a corpus of 20 non-payment payloads.

### M7 — Testing hardening
- **Goal.** Comprehensive test matrix: fuzz targets, property-based tests, golden files, `slogtest` conformance, race-detector runs in CI.
- **Hours.** 12 · **Calendar.** 1 week
- **Dependencies.** M2–M6.
- **Deliverables.**
  - Native Go fuzz targets: `FuzzDSLParse`, `FuzzWalkerValue`, `FuzzLuhn`, `FuzzHeaderScrub`. Seed corpora committed under `testdata/fuzz/`.
  - Property test (via `testing/quick` or `pgregory.net/rapid`): "redaction is idempotent — `Redact(Redact(x)) == Redact(x)`" and "redaction never grows the tree".
  - Golden-file framework in `internal/testutil/golden.go` with `-update` flag.
  - CI job running fuzz for 60s per target on every PR; 10 min per target on nightly cron.
  - Race-detector run in the main test matrix (`go test -race`).
- **Risks.** Fuzz finds a panic that requires a walker refactor — plan a day of buffer. `slogtest` reveals a `WithAttrs` bug already surfaced but deferred — address here, not in M3.
- **Definition of done.** 48 hours of cumulative fuzz time across targets with no new crashes; coverage ≥ **85% for `redact/` and `httpmw/`, ≥ 70% overall**.

### M8 — Benchmarks vs samber/slog-gin
- **Goal.** Publishable comparative benchmark: latency, allocs/op, throughput of `redactlog` vs `samber/slog-gin` (and `samber/slog-http` for the net/http tier) on identical workloads.
- **Hours.** 8 · **Calendar.** 1 week
- **Dependencies.** M5, M7.
- **Deliverables.**
  - `bench/` directory with a standalone Go module (separate `go.mod` to avoid polluting root deps) containing the comparison harness.
  - `bench/scenarios.go`: (1) tiny-request JSON echo, (2) 10 KB request body with 3 redacted fields, (3) 100 rps streaming for 10s SSE.
  - `BENCHMARKS.md` with `benchstat` output tables, methodology (hardware, Go version, samber version pinned), and reproducibility instructions.
  - Optional: `benchmark-action/github-action-benchmark` workflow on `push: main` writing to gh-pages.
- **Risks.** Benchmark-gaming (accidental over-optimization for microbench at the cost of real-world paths). Samber's feature superset means the comparison must be apples-to-apples — configure samber to do no body capture if redactlog isn't, and vice versa.
- **Definition of done.** Redactlog is **≤ 1.5× samber's ns/op at zero-redaction-rules parity**, and **≤ 3× at full PCI preset**. If worse, file a deferred perf issue and document in BENCHMARKS.md — do not block release.

### M9 — Documentation
- **Goal.** Every exported symbol has a useful godoc; `README.md` includes a 30-second quick-start for both net/http and Gin; every ADR is in `docs/` and cross-linked.
- **Hours.** 12 · **Calendar.** 1 week
- **Dependencies.** M1–M8.
- **Deliverables.**
  - Godoc on every exported symbol (enforce via `revive` rule `exported`).
  - Four runnable godoc `Example*` functions in `_test.go`: `ExampleNewHandler`, `Example_httpmw`, `Example_gin`, `ExampleRedactor_With`.
  - `README.md` sections: what it is, when to use it vs alternatives, quick-start (net/http), quick-start (Gin), PCI preset usage, performance summary (link to BENCHMARKS.md), status (`v1.0.0`), stability guarantees, a 3-line "future contributions" note pointing at Issues.
  - `docs/ADR-001.md` through `docs/ADR-008.md` finalized.
  - `docs/architecture.md` — single-page distillation of the design doc.
- **Risks.** Docs drift from code; godoc examples failing to compile after a last-minute API tweak.
- **Definition of done.** `go test ./...` passes including `Example*`; `go doc -all ./...` produces no undocumented-exported warnings from `revive`; pkg.go.dev renders a preview locally via `pkgsite -http :6060`.

### M10 — Release prep → v1.0.0
- **Goal.** Tag `v1.0.0`, publish a GitHub Release, confirm pkg.go.dev renders correctly, announce **nothing externally** (per scope constraints).
- **Hours.** 10 · **Calendar.** 1 week
- **Dependencies.** M1–M9.
- **Deliverables.**
  - `v1.0.0-rc.1` tag → smoke-test in the Fintech dashboard with `go get github.com/redactlog/redactlog@v1.0.0-rc.1`.
  - If clean for 3–5 days, tag `v1.0.0`.
  - `.goreleaser.yaml` (library mode: `builds: - skip: true`; changelog grouped by conventional-commit prefix).
  - GitHub Release notes generated via goreleaser.
  - CHANGELOG.md entry for v1.0.0.
  - Verify pkg.go.dev: visit `https://pkg.go.dev/github.com/redactlog/redactlog` and subpackages; if stale, click the "Request" button or `go get` from a fresh module.
  - GPG-sign the `v1.0.0` tag.
- **Risks.** Last-minute API change during rc testing → cascades into doc rewrites. Proxy.golang.org caching a buggy tag — use `retract` in a `v1.0.1` rather than deleting.
- **Definition of done.** Release checklist in §10 all ticked; pkg.go.dev green; dogfooded Fintech dashboard has been running on `v1.0.0` for at least 24h.

---

## 3. Week-by-week schedule

Assumptions: start = Monday W1; 10 hrs/week average; W6 and W10 reserved as partial buffer weeks. If a week's actual hours fall short, pull forward from the next week, never skip tests.

| Week | Focus | Hours | Outputs |
|---|---|---|---|
| **W1** | M1 scaffolding | 8 | Repo up, CI green, ADRs in `docs/`, first empty tag `v0.0.1` |
| **W2** | M2 part A — DSL parser + trie | 10 | `dsl.go`, `trie.go`, unit tests for parser |
| **W3** | M2 part B — walker + public API + benches | 10 | `walker.go`, `redact.go`, benchmarks green; tag **`v0.1.0`** |
| **W4** | M3 slog.Handler wrapper | 10 | `handler.go` + `slogtest` conformance; tag `v0.2.0`. **Begin dogfooding: redactor only, in Fintech dashboard.** |
| **W5** | M4 part A — httpmw core + httpsnoop + headers | 10 | `middleware.go`, `response.go`, `headers.go` |
| **W6** | M4 part B — body capture + streaming tests **(buffer week)** | 8 | SSE & hijack tests pass; tag `v0.3.0` |
| **W7** | M5 Gin adapter | 10 | `gin/middleware.go` + integration tests; tag `v0.4.0`. **Switch Fintech dashboard to full middleware.** |
| **W8** | M6 PCI preset + Luhn/PAN detectors | 10 | `preset/pci.go`, `detect/luhn.go`, golden tests; tag `v0.5.0` |
| **W9** | M7 fuzz + property + slogtest hardening | 12 | Fuzz corpora committed; coverage gates met; tag `v0.6.0` |
| **W10** | M8 benchmarks **(buffer week)** | 8 | `bench/` module, `BENCHMARKS.md`, optional gh-action |
| **W11** | M9 documentation sprint | 12 | Godoc, examples, README, architecture.md; tag `v1.0.0-rc.1` |
| **W12** | M10 rc soak + tag v1.0.0 | 10 | Final rc → v1.0.0 GPG-signed; pkg.go.dev verified |

Contingency weeks **W13–W14** absorb any slip from M4 (most likely) or M7 (second most likely). Do not use them for new scope.

---

## 4. Task dependency graph

```
              M1 (scaffolding)
                   │
                   ▼
              M2 (redact engine) ◄────────── CRITICAL PATH START
              │          │
              ▼          ▼
          M3 (slog)   M6 (PCI preset) ← depends on engine only
              │          │
              ▼          │
          M4 (httpmw) ◄──┤ (preset exercised in httpmw tests)
              │
              ▼
          M5 (gin)
              │
              ▼
          M7 (test hardening) ◄─────────── all feature milestones feed in
              │
              ▼
          M8 (benchmarks)
              │
              ▼
          M9 (docs)
              │
              ▼
          M10 (release) ◄──────────────── CRITICAL PATH END
```

**Critical path.** M1 → M2 → M3 → M4 → M5 → M7 → M9 → M10. Total critical-path hours ≈ **88**. The remaining ~27 hours (M6 + M8 + buffer slack) can happen in parallel slots when momentum on the critical path stalls.

**Parallelization opportunities for a solo dev.**
- M6 (PCI preset) only needs M2 complete — if W8 of the plan is blocked on M4/M5 debugging, jump to M6 early.
- M8 benchmarks can start after M5 even if M7 is incomplete; move bench harness into W9 if time permits.
- M9 docs can begin incrementally after M3 — every time a package lands, write its godoc immediately. This reduces the W11 doc-sprint risk.

---

## 5. Risk register

| Risk | Likelihood | Impact | Mitigation | Trigger signal |
|---|---|---|---|---|
| Scope creep (e.g., "just one more preset") | **H** | H | §8 scope-control rules; every new idea goes to a `v2-ideas.md` file, never into the current sprint | Any commit touching a file outside the current milestone's deliverables list |
| Burnout / motivation loss | M | H | Hard cap at 12 hrs/week; buffer weeks W6 and W10; ship a tagged `v0.x` every week for dopamine | Two consecutive weeks under 6 actual hours; skipping tests |
| Fintech dashboard competing for time | **H** | M | Dogfood redactlog inside the dashboard so progress on one counts for both; never let dashboard deadlines bump a redactlog milestone more than 1 week | Fintech feature PRs open while the redactlog weekly milestone is incomplete |
| Streaming/SSE/hijack edge cases in httpsnoop composition | M | **H** | Write the SSE + hijack integration tests in **W5**, not W6 — surface surprises early; fallback plan: escape-hatch option `DisableBodyCapture` to bypass httpsnoop wrapping entirely | Test takes > 4 hrs to pass; `http.Flusher` assertion fails after middleware wrap |
| `slogtest` conformance reveals design flaw in handler | M | H | Run `slogtest` on day 1 of M3, not day-end; budget a full day of M3 for `WithAttrs`/`WithGroup` semantics | Any `slogtest` failure pointing to state sharing across clones |
| Performance miss vs samber/slog-gin | M | M | Allocs-free hot path validated in M2 benchmarks **before** M4; perf ≤ 3× samber is acceptable for v1.0.0, not blocking — document and defer optimization | `BenchmarkRedact_*` > 2× over M2's target, or M8 shows > 4× samber |
| Dependency churn (gin v2, semconv bump, httpsnoop abandonment) | L | M | httpsnoop is stable-complete per verification; gin v2 not on horizon; semconv pinned via a single constant — move semconv import to an ADR amendment file so upgrades are grep-able | gin announces a v2 branch; httpsnoop archives repo; semconv introduces breaking HTTP attr renames |
| Go 1.23 floor conflicts with user environments | L | M | Document Go 1.23+ requirement prominently; `go.mod` declares it; CI matrix proves it | User issue filed about Go 1.22 build break |
| Fuzz finds walker panic late in cycle | M | M | Run fuzz targets locally in W6 (as soon as walker exists), not only in W9 CI | `go test -fuzz` crash within first 10 minutes |
| pkg.go.dev fails to render after v1.0.0 tag | L | M | Resolve a `v0.x` tag via `go get` in W3 to validate the module path end-to-end | pkg.go.dev shows "not available" 15 min post-tag |

---

## 6. Dogfooding strategy

The Fintech portfolio dashboard is the most honest reviewer you have. Use it in three phases.

**Phase A — Week 4: redactor only.** As soon as M3 is tagged (`v0.2.0`), import `redact` into the dashboard and replace whatever ad-hoc scrubbing exists today (log line string replacements, manual `map` filtering). The API surface is small — `redact.New(rules...).Redact(ctx, v)` — so integration cost is ~1 hour. This validates the DSL against *your own* real field names before the public API is locked. Any friction (a path you wished you could express; a rule that surprised you) is a feature gap to address in M3/M6, not later.

**Phase B — Week 7: full middleware on a non-prod branch.** After M5 tags (`v0.4.0`), cut a branch of the dashboard that replaces its existing Gin logging middleware with `redactlog/gin`. Run locally and in a staging environment for one week. Diff the logs: anything redactlog logs that the old middleware didn't (or vice versa) is a bug or a missing option. Do **not** merge to main yet.

**Phase C — Week 12: rc1 in production.** After `v1.0.0-rc.1`, merge the dashboard branch to main and deploy to production for the 3–5 day soak window. This is the truest test: real headers, real request shapes, real error paths, real volume.

**Feedback capture.** Keep a single `dogfood-notes.md` in the redactlog repo (not committed to main; in `.gitignore`). Every time you hit friction, write one line. Triage weekly: is it a v1 blocker, a v1 nice-to-have, or a v2 idea? Default answer is v2.

**Preventing cross-contamination.**
1. **No redactlog code changes from inside the dashboard repo.** If you find a bug, file a redactlog issue, fix it there, tag a `v0.x.y+1`, bump in the dashboard. This prevents a "local hack" in the dashboard from papering over an API flaw.
2. **Dashboard deadlines never bump redactlog milestones by more than one week.** If the dashboard needs a feature redactlog doesn't have, do the simplest stub in the dashboard and log the need for v2 — don't detour redactlog.
3. **If dogfooding reveals a design flaw after W9, escalate to `v1.0.0`-blocker status explicitly.** Don't paper over late-stage findings to meet a date; the architecture doc's 8 ADRs are the only safety net against a bad v1.

---

## 7. Quality gates

### Phase 1 — Core engine (M1–M2) exit criteria
- `go test ./...` green, `-race` clean.
- Coverage ≥ 90% on `redact/` and `internal/`.
- `BenchmarkRedact_Nested5x5` ≤ 1.5 µs/op on reference hardware.
- `golangci-lint run`, `go vet`, `govulncheck ./...` all clean.
- `doc.go` present in every package.
- Tag `v0.1.0` published to proxy.golang.org (`go list -m` resolves).

### Phase 2 — Middleware pipeline end-to-end (M3–M6) exit criteria
- `slogtest.TestHandler` passes with no errors.
- SSE integration test, hijack (WebSocket) integration test, panic-recovery integration test all green on both `httpmw` and `gin` packages.
- PCI preset golden tests cover ≥ 20 realistic payloads with 0 false negatives and 0 false positives on the negative corpus.
- Coverage ≥ 85% on `httpmw/` and `gin/`.
- `go test -race ./...` clean.
- `go mod why -m github.com/gin-gonic/gin` returns *only* paths under `./gin/...` (proves root-package isolation per ADR-004).

### Phase 3 — Production-quality tested & benchmarked (M7–M8) exit criteria
- ≥ 48 hours of cumulative native fuzz time across all targets with no new findings.
- Property tests (idempotence, no-growth) pass.
- Benchmark table published in `BENCHMARKS.md`, reproducible from `bench/` module with a single `make bench` or documented `go test -bench` command.
- Performance within stated envelope vs samber/slog-gin (≤ 1.5× at parity, ≤ 3× with full PCI preset).
- `govulncheck` clean against the full dep tree including the `bench/` module.

### Phase 4 — Release-ready (M9–M10) exit criteria
- 100% godoc on exported symbols (revive `exported` rule clean).
- Four runnable `Example*` functions compile and pass.
- README quick-starts (net/http + Gin) copy-paste into a fresh project and run.
- ADR-001..008 all present in `docs/`; `docs/architecture.md` written.
- CHANGELOG.md includes v1.0.0 section.
- pkg.go.dev renders all packages (check via the live URL after the rc tag).
- §10 release checklist every box ticked.

---

## 8. Scope control rules

Enforce these mechanically. When in doubt, defer.

1. **The ADR fence.** If a feature isn't covered by ADR-001 through ADR-008 or listed in §3 of the architecture doc's public API, it is v2. *Example:* A user-suggested `WithSampler(func(r *http.Request) bool)` option is attractive but isn't in the API surface — it goes to `v2-ideas.md`.
2. **The preset freeze.** Exactly one compliance preset ships in v1: PCI. GDPR, HIPAA, and SOC2 presets are v2 regardless of how easy they look. *Example:* You finish M6 in 6 hours instead of 10 — do not start a GDPR preset; use the saved time for extra fuzz corpus.
3. **The framework freeze.** Exactly two HTTP integrations ship in v1: `net/http` and `gin`. Chi, Echo, Fiber, and http.ServeMux patterns are v2. *Example:* A dogfooding friend asks for Echo support — file a v2 issue, link to it in README's "roadmap" section, close.
4. **Perf optimizations that require architectural changes are v2.** Fiddling with allocs, inlining, or sync.Pool within the existing walker is fine. Rewriting the walker to use unsafe pointers or a custom hash map is not. *Example:* Benchmarks show 2.5× samber — accept, document, defer optimization to v1.1.
5. **No CLI in v1.** The verifier CLI is explicitly v2 per the architecture doc. Do not add a `cmd/` directory. *Example:* You think "a quick `redactlog-check` to validate a rules file would help users" — it goes to v2.
6. **No crypto in v1.** Audit chains and crypto-shredding are v2. Any hash, HMAC, or signature primitive in the code is a scope violation. *Example:* You're tempted to add a `Hash()` helper for correlation IDs — use stdlib `hash/fnv` inline in the dashboard instead; do not ship it from redactlog.
7. **No vendor exporters.** Datadog, New Relic, Splunk exporters are v2. Redactlog writes `slog.Record`s only. *Example:* Datadog SDK has a nice pattern — note it, move on.
8. **API additions after W7 are frozen.** From M5 onward, no new exported symbols except those strictly required to fix a bug. *Example:* You realize an `Option` could be cleaner as a builder method — keep it as an option; rename in v2.
9. **Test-reveals-design-flaw protocol.** If M7 surfaces a design flaw, the only options are (a) fix it within v1 even if it delays release, or (b) retract the offending API and ship it disabled. Never ship known-broken behavior. *Example:* Fuzz finds a walker panic on cyclic data — fix the walker; don't "document the limitation."
10. **Dogfood-driven additions capped.** The Fintech dashboard may reveal needs, but at most two such needs become v1 changes. All others go to v2. Track them in `dogfood-notes.md` with a running count.

---

## 9. Tooling and infrastructure decisions

| Area | Decision | Rationale |
|---|---|---|
| CI provider | **GitHub Actions** | Free for public repos, `actions/setup-go@v5` includes module & build caching since 2023 (no separate cache step needed), integrates with goreleaser, benchmark-action, and golangci-lint-action out of the box. |
| CI workflows | `ci.yml` (lint + test + vet + govulncheck on PRs and pushes), `fuzz.yml` (60 s per target on PR, 10 min on nightly cron), `bench.yml` (push to main only), `release.yml` (tag-triggered, runs goreleaser) | Splitting lets the fast PR feedback loop stay under 3 minutes while slower jobs don't block merges. |
| Go version matrix | `['1.23', '1.24', '1.25']` × `[ubuntu-latest, macos-latest, windows-latest]` | Go's support policy is the latest two; include three for a 6-month buffer. Gin 1.12 requires 1.23+ so that is the floor. |
| Linting | **golangci-lint v2.x** with `linters.default: none` + explicit enable list: `errcheck, govet, staticcheck, revive, gosec, unused, ineffassign, gocritic, misspell, unparam, prealloc, bodyclose, noctx, errorlint, gocyclo, godot` | v2 config format is now required; explicit enable list is reproducible across v2 minor bumps. `revive`'s `exported` rule is the godoc-on-exports enforcer. |
| Formatting | `golangci-lint fmt` (gofumpt + gci + golines in one pass) | Single command, no extra tooling. |
| Test coverage | `go test -coverprofile=coverage.out ./...` + **Codecov** upload in CI | Codecov free tier sufficient; generates badge for README. Alternative: just check `go tool cover -func` against threshold in a CI step. |
| Coverage thresholds | Enforce in a CI step: `redact/` ≥ 85%, `httpmw/` ≥ 85%, overall ≥ 70% | Matches release checklist. Fail the PR, don't just report. |
| Benchmark tracking | **`benchmark-action/github-action-benchmark`** on `push: main` writing to a `gh-pages` branch chart; `benchstat` for local A/B comparisons | Free, GitHub-native, PR comments on regression ≥ 150%. Do **not** run on fork PRs (token exposure warning). |
| Fuzzing | **Native `go test -fuzz` only in v1**; OSS-Fuzz deferred to post-v1 if adoption justifies the 0.5–2 day onboarding | Native fuzzing is sufficient for an initial OSS library; OSS-Fuzz adds a Dockerfile, `build.sh`, and a PR to google/oss-fuzz — not worth the time until there is real demand. |
| Release tooling | **goreleaser v2.x in library mode** (`builds: - skip: true`) triggered by `v*` tags | Handles GitHub Release creation, grouped changelogs from conventional commits, checksums, and SBOM. No cross-compilation needed for a library. |
| Tagging | Manually tag from local after rc soak; GPG-signed for v1.0.0 | A solo dev doesn't need `svu` or `semantic-release` automation; a manual `git tag -s v1.0.0 -m "..."` is perfectly fine and avoids one more tool. |
| Documentation hosting | **pkg.go.dev for godoc** (automatic), `docs/` folder in repo for ADRs and architecture | No separate docs site needed for v1; if users ask, add mkdocs later. README is the landing page. |
| Local godoc preview | `go install golang.org/x/pkgsite/cmd/pkgsite@latest` → `pkgsite -http :6060` | Catches rendering issues before tagging. |
| Issue tracking | **GitHub Issues only**; labels: `bug`, `security`, `v2`, `good-first-issue` (even if unused) | Matches scope constraint of no community launch while still allowing adopters to file reports. |
| Security reporting | **GitHub private vulnerability reporting** enabled in repo settings + `SECURITY.md` with contact email | Prepares for a CVE scenario; zero-cost to set up. |
| Semver discipline | Strict: every exported API addition bumps minor; every removal/rename bumps major. Pre-1.0 breakage allowed in `v0.x`; after v1.0.0, any break requires `v2` module path (`/v2` suffix) per Go module rules. | The architecture doc's explicit v2 deferrals make a future `v2` likely — don't paint yourself into a corner. |
| Dependabot | Enabled for `gomod` + `github-actions` | Free, surfaces semconv/gin bumps automatically. |

---

## 10. v1.0.0 release checklist

Tick each box before pushing the `v1.0.0` tag. Do not push the tag with any box unchecked.

- [ ] All exported identifiers have godoc comments (verified by `revive` `exported` rule in CI).
- [ ] ADR-001 through ADR-008 present and linked from `docs/README.md`.
- [ ] `docs/architecture.md` written and links to ADRs.
- [ ] `README.md` includes: what, why, install, quick-start (net/http), quick-start (Gin), PCI preset usage, perf summary with link to `BENCHMARKS.md`, stability & versioning policy, future-contributions note.
- [ ] `CHANGELOG.md` has a `## [1.0.0] — YYYY-MM-DD` section with features grouped by package.
- [ ] `LICENSE` file is Apache-2.0, copyright line present.
- [ ] `SECURITY.md` with reporting email and supported-versions table.
- [ ] `.github/workflows/` contains ci, fuzz, bench, release workflows.
- [ ] No `CONTRIBUTING.md` (solo project), but README explicitly says "issues welcome; PRs considered after discussion in an issue first."
- [ ] Runnable godoc examples for the four primary use cases exist and pass `go test`.
- [ ] `go vet ./...` clean.
- [ ] `golangci-lint run ./...` clean.
- [ ] `govulncheck ./...` clean.
- [ ] `go test -race -coverprofile=coverage.out ./...` passes; coverage thresholds met (≥ 85% on `redact/` and `httpmw/`, ≥ 70% overall).
- [ ] At least 48 cumulative hours of fuzz time with no new findings; seed corpora committed under `testdata/fuzz/`.
- [ ] `BENCHMARKS.md` published with benchstat output and methodology.
- [ ] No `TODO` or `FIXME` comments in files matching `!(_test.go|internal/**)`.
- [ ] `rc.1` tag has soaked in the Fintech dashboard in production for ≥ 24 hours without incident.
- [ ] `pkg.go.dev/github.com/redactlog/redactlog` renders all packages after the rc tag (check before final).
- [ ] Release notes drafted in goreleaser config; preview-built via `goreleaser release --snapshot --clean`.
- [ ] Dependabot enabled; all current Dependabot PRs either merged or explicitly deferred.
- [ ] `go.mod` declares `go 1.23`; `gin-gonic/gin` import appears only under `./gin/...`.
- [ ] `v1.0.0` tag is GPG-signed (`git tag -s v1.0.0`); signature verifies (`git tag -v v1.0.0`).
- [ ] Post-tag: trigger `release.yml`; GitHub Release created; Release artifacts (checksums, SBOM) attached.
- [ ] Post-tag: `go install github.com/redactlog/redactlog@v1.0.0` succeeds from a clean `$GOPATH`.

---

## 11. Post-v1.0.0 immediate priorities (first 30 days)

The scope says no community launch — but adopters will still appear. Plan for it without inflating work.

**Triage cadence.** Check GitHub issues and PRs **twice a week** (e.g., Tuesday and Saturday evenings, 30 min each). Label within 48 hours; respond with an acknowledgment within 7 days even if the fix is longer. Silence kills OSS projects faster than bugs do.

**Patch-release discipline.** Expect one or two `v1.0.x` patches in the first month.
- `v1.0.1` is almost certainly needed for doc typos, a godoc example that slipped, or a CI-only issue. Budget 1–2 hours.
- `v1.0.2` may be needed for a real bug surfaced by an adopter (likely in httpsnoop-wrapping edge cases, or a DSL parser surprise). Budget 4–8 hours.
- Fix bugs on `main` → tag `v1.0.x` → auto-release. Do **not** branch; solo projects don't benefit from release branches until a `v2` ships.

**Breaking-change policy.** Zero breaking changes in v1.x. Any API mistake discovered post-release gets one of: (a) new parallel API added in v1.y (old one kept), (b) deprecation comment now, removal in v2.0.0, or (c) retraction via `retract` directive in go.mod if the API is dangerous.

**Security response plan.**
- Ensure `SECURITY.md` exists with a contact email (a dedicated alias, not your personal inbox — e.g., `security@<your-domain>`).
- Enable GitHub's **private vulnerability reporting** feature on the repo.
- Commit to a 48-hour acknowledgment SLA and a 14-day fix SLA for confirmed issues.
- If a CVE is filed: (1) confirm via a private fork; (2) prepare the patch on a private branch; (3) request a CVE ID via GitHub Security Advisories; (4) coordinate disclosure; (5) tag the patch release; (6) publish advisory. Keep this as a 1-page runbook in `docs/security-runbook.md`.

**Documentation gap backfill.** Every issue filed is a documentation signal. If two different users ask the same question within the first 30 days, that's a FAQ entry or a README addition — not a code change. Budget 1 hour per week for doc improvements.

**Dependency vigilance.** Dependabot will open PRs for gin, semconv, and httpsnoop (if ever). Review and merge within a week of opening, rerunning the full test suite including fuzz. Any dependency that breaks CI is a scope-limited fix, not a feature.

**No v2 work yet.** For the first 30 days post-release, the `v2-ideas.md` file grows but no code is written against it. Resist the temptation. Week-5-post-release is the earliest legitimate time to scope v1.1 or v2.

**Personal cadence.** Return to the Fintech dashboard as your primary evening project. Redactlog in its first month should be 2–4 hrs/week, not 10. Sustained 10 hrs/week for a second OSS month is the burnout trap the risk register warned about.

---

## Conclusion

The plan collapses to four bets. **First**: the redaction engine (M2) is the project — if it works correctly and fast, the rest is plumbing. **Second**: dogfooding in week 4 is the single highest-leverage quality gate, because it surfaces API friction before the surface is locked. **Third**: the httpsnoop / streaming composition in M4 is the likeliest source of schedule slippage, which is why W6 is a buffer week by design. **Fourth**: scope discipline is the only variable that turns a "12-week plan" into a "shipped 12-week plan" — the ADR fence and the v2-ideas file exist to make "no" the default answer. Tag `v1.0.0` in week 12. If not, tag it in week 14. Don't add anything in between.