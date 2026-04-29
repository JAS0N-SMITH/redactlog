# CLAUDE.md

> Guidance for Claude Code (and any agent following AGENTS.md conventions) working on `redactlog`.
> This file is loaded automatically at the start of every Claude Code session. Keep it accurate — stale rules are worse than missing rules.

<!-- Maintainer note: This file is intentionally longer than the ~200-line ideal because it consolidates
     project, ADR, style, and workflow guidance in one place for a solo-developer OSS project. If it
     grows further, move section 6 (Code Style) and section 14 (Tooling) into .claude/rules/ with
     `paths:` frontmatter so they only load when relevant. -->

## Table of contents

1. [Project overview](#1-project-overview)
2. [Critical scope fences (v1 only)](#2-critical-scope-fences-v1-only)
3. [Architecture reference](#3-architecture-reference)
4. [ADR summary and when to invoke](#4-adr-summary-and-when-to-invoke)
5. [Go development conventions](#5-go-development-conventions)
6. [Code style](#6-code-style)
7. [Testing requirements](#7-testing-requirements)
8. [Commit and branch discipline](#8-commit-and-branch-discipline)
9. [When to ask vs proceed](#9-when-to-ask-vs-proceed)
10. [Security and compliance defaults](#10-security-and-compliance-defaults)
11. [Performance discipline](#11-performance-discipline)
12. [Documentation expectations](#12-documentation-expectations)
13. [Dependency discipline](#13-dependency-discipline)
14. [Tooling and automation](#14-tooling-and-automation)
15. [Interaction patterns](#15-interaction-patterns)
16. [Glossary](#16-glossary)

---

## 1. Project overview

`redactlog` is a **redaction-first HTTP logging middleware for Go services in regulated industries** (fintech, healthtech). It wraps `log/slog` to guarantee that sensitive fields — PANs, emails, tokens, headers — are scrubbed before a log line is emitted, and exposes an `http.Handler` / Gin middleware that captures request/response metadata and bodies under the same redactor.

It is **not** a general-purpose audit system. It does not do tamper-evident chains, crypto-shredding, or compliance-framework presets beyond PCI in v1. It does not replace your SIEM, APM, or OTel exporter.

**Target user**: a Go backend engineer at a fintech/healthtech shop who needs PCI-DSS-defensible logs without rolling their own redaction pass.

**Authoritative references** (read these before large changes):

- Architecture & public API: `@docs/architecture.md`
- ADRs: `@docs/ADR-001-slog-handler-wrapper.md` … `@docs/ADR-008-single-censor-token.md`
- 12-week roadmap & milestones: `@docs/roadmap.md`
- Ecosystem gap analysis: `docs/gap-analysis.md`
- Deep research notes: `docs/research.md`

**Current milestone**: M7 — (week 9/12)

**Project facts** (do not contradict without opening an ADR):

| Fact | Value |
| --- | --- |
| Module path | `github.com/JAS0N-SMITH/redactlog` |
| Minimum Go | 1.25.9 |
| License | Apache-2.0 |
| Target release | v1.0.0, ~12 weeks solo, evenings/weekends |
| Direct deps | stdlib, `felixge/httpsnoop`, `go.opentelemetry.io/otel/semconv/v1.26.0`, `gin-gonic/gin` (gin subpackage only) |

---

## 2. Critical scope fences (v1 only)

**The prime directive: if a feature is not in `docs/architecture.md`'s public API surface, it is v2.** Do not implement it. Do not stub it. Write a one-liner in `docs/v2-ideas.md` with date, proposer, and a sentence of rationale, and move on.

### In scope for v1

- `redactlog.Config`, `Options`, `New`, `NewPCI` (the **only** preset)
- `redact/` engine: Pino-style path DSL, detectors (Luhn, regex opt-in), single `"***"` censor token
- `httpmw/` middleware for `net/http` using `felixge/httpsnoop`
- `gin/` adapter (thin — the **only** place `gin-gonic/gin` is imported)
- `internal/` helpers: buffer pool, canonical header, Luhn, ringbuf placeholder
- `slog.Handler` wrapper, not a `ReplaceAttr` shim
- Head-truncation body capture (fixed-size prefix; no ring buffer)

### Out of scope for v1 — do not implement

The following are **explicitly v2 or later**. A request to build any of these → reply "that's v2, logging in `v2-ideas.md`":

- Tamper-evident audit chains, Merkle logs, signed lines, verifier CLI
- Crypto-shredding, per-tenant key management
- GDPR / HIPAA / SOC2 / PII presets (only PCI in v1)
- `chi`, `echo`, `fiber`, `fasthttp`, `kratos`, or any adapter other than net/http + Gin
- Admin HTTP endpoints, vendor exporters (Datadog, Splunk, etc.)
- Ring-buffer body capture (ADR-006 picks head truncation)
- Type-specific censor tokens like `[REDACTED_PAN]` (ADR-008 picks single `"***"`)
- GJSON / JSONPath DSLs (ADR-002 picks Pino-style)
- `slog-context` dependency (ADR-005 picks ~20 LOC inline)

### Implementation fences (non-negotiable)

- **NEVER** `unsafe.Pointer`.
- **NEVER** a custom hash map or intrusive data structure.
- **NEVER** runtime reflection except through `slog.LogValuer`.
- **NEVER** `cgo`, `os/exec`, or network calls from the redaction engine.

### Handling requests that arrive mid-development

When a user asks for something borderline:

1. Check §2 in-scope list above.
2. Check `docs/architecture.md` public API.
3. Check ADRs.
4. If not present in any: record in `docs/v2-ideas.md` (format below) and continue current milestone.

```
## <feature name>
Date: YYYY-MM-DD
Proposer: <github handle or "internal">
Why v2: <one sentence>
```

---

## 3. Architecture reference

### Module layout

```
redactlog/
├── redactlog.go          # Config, Options, New, NewPCI — top-level API only
├── doc.go                # package comment
├── redact/               # redaction engine; usable standalone; no slog dependency
├── httpmw/               # framework-agnostic http.Handler middleware
├── gin/                  # Gin adapter — ONLY place gin-gonic/gin is imported
├── internal/
│   ├── bufpool/          # sync.Pool-backed buffer pool
│   ├── canonheader/      # canonicalised HTTP header names
│   ├── luhn/             # Luhn detector
│   └── ringbuf/          # placeholder for v2; do not wire in
├── docs/                 # architecture.md, ADR-*.md, roadmap.md, v2-ideas.md
├── bench/                # comparative benchmarks vs zap/zerolog/etc.
└── examples/             # example tests & runnable demos
```

### Dependency rules (enforce in CI with a depguard or import-check script)

- `redact/` imports **only** stdlib + `internal/luhn`, `internal/bufpool`.
- `httpmw/` imports `redact/`, `internal/*`, stdlib, `felixge/httpsnoop`, `semconv/v1.26.0`.
- `gin/` imports `httpmw/`, `redact/`, stdlib, and `gin-gonic/gin`. **No other package may import `gin-gonic/gin`.**
- Root package `redactlog` imports `redact/`, `httpmw/`, `internal/*`. It **must not** import `gin/`.
- `internal/*` imports stdlib only (keeps core allocation-free and testable in isolation).
- `bench/` is its own Go module so benchmark deps don't pollute `go.mod`.

### Public vs internal

- Anything under `internal/` is compiler-enforced private. Do not re-export.
- Anything in `redact/`, `httpmw/`, `gin/`, and root is `pkg.go.dev`-visible. Adding, renaming, or changing the signature of any exported symbol is an API change — see §9.
- **Experimental tag**: prefix godoc with `// EXPERIMENTAL:` and wrap in an `experimental` subpackage if needed. Never ship experimental APIs in v1 without a sunset date in the comment.

---

## 4. ADR summary and when to invoke

Read `@docs/ADR-00X.md` for full context. Short form:

| ADR | Decision | Cite when |
| --- | --- | --- |
| **001** | `slog.Handler` **wrapper**, not a `ReplaceAttr`-only helper | anything touching `handler.go`, `WithAttrs`, `WithGroup` |
| **002** | **Pino-style** path DSL (`a.b[*].c`), not GJSON, not JSONPath | DSL parser, rule compilation, trie walker |
| **003** | Depend on **`felixge/httpsnoop`**, don't vendor or reimplement | response-writer capture, status code hooks |
| **004** | **Dedicated `gin/` subpackage**, not `gin.WrapH` | Gin integration, middleware signature |
| **005** | Own **~20-line context attrs** implementation, not `slog-context` | context propagation of log attrs |
| **006** | **Head truncation only** in v1 (no ring buffer) | body capture size/strategy |
| **007** | **Regex redaction OFF by default**, opt-in via detectors | default `Config`, preset construction |
| **008** | **Single `"***"` censor token**, not type-specific | redaction output format |

### How to cite

In commits: `feat(redact): add trie walker per ADR-002`.
In code comments: `// Per ADR-006 we truncate at maxBodyBytes; ring buffer is v2.`
In PR/issue discussion: link the ADR file explicitly.

### When an ADR seems wrong

Do **not** silently violate it. The workflow is:

1. Note the concern in a comment or discussion, referencing the ADR.
2. Draft a **new** ADR (`docs/ADR-009-…md`) with Status: Proposed. Keep old ADRs immutable except for a trailing "Superseded by ADR-00X" line.
3. Block the affected code change until the new ADR is Accepted.
4. Update this file's §4 table.

---

## 5. Go development conventions

Go 1.23+ idioms are assumed. Highlights:

- **Errors are returned, not panicked.** Library code **NEVER** panics for flow control. The one acceptable panic is a programmer error at startup — e.g., a malformed DSL passed to `New()` is a configuration bug and may panic with a clear message. Runtime-path errors are wrapped and returned.
- **Error wrapping**: use `fmt.Errorf("compile rule %q: %w", rule, err)`. Sentinel errors are package-level `errors.New`:
  ```go
  var ErrInvalidDSL = errors.New("redactlog: invalid DSL expression")
  ```
- **No empty interfaces in public API.** Use generics for typed collections (Go 1.22+ type parameters). `any` is acceptable only where `slog` itself uses it.
- **No global state beyond constants.** No package-level singletons, no `init()`-wired registries. If an `init()` is truly required (it almost never is), comment with `// init: required because …`.
- **Receivers**: short names matching type initials (`func (h *Handler) …`, `func (r *Redactor) …`). Not `self`, `this`, or verbose names. No Hungarian notation. Never prefix `_` on unexported fields except deliberately unused placeholders.
- **`context.Context`** is the first argument of any function that does I/O, might block, or could be cancelled. Never store contexts in structs; pass them through.
- **Zero-allocation hot paths** are marked `// HOT: called on every request; benchmark before touching.` Changes to `// HOT` functions require a benchstat comparison in the PR/commit.
- **Prefer stdlib** when the delta to a third-party package is < 100 LOC. `slices`, `maps`, `cmp`, `log/slog`, `net/http`, `sync`, `errors` — lean on these.
- **Clock injection**: request-path code **never** calls `time.Now()` directly. It calls `cfg.Clock.Now()` (default `time.Now`, overridable in tests). This is required for golden-file determinism (§7).

Example:

```go
// HOT: called once per request.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
    now := h.cfg.Clock.Now() // not time.Now()
    if err := h.redact(&r); err != nil {
        return fmt.Errorf("redactlog: redact: %w", err)
    }
    return h.inner.Handle(ctx, r)
}
```

---

## 6. Code style

- **Formatting**: `gofmt` + `gofumpt` + `goimports`, enforced by `golangci-lint run` (config at `.golangci.yml`). Do not fight the formatter.
- **Line length**: soft 100, hard 120. Break long function signatures one argument per line.
- **Imports**: three groups separated by blank lines — stdlib, third-party, internal. `goimports -local github.com/JAS0N-SMITH/redactlog` handles this.
- **File naming**: `snake_case` for multi-word files (`response_writer.go`, not `responseWriter.go`). One logical concept per file; split when a file crosses ~500 LOC.
- **Package comments** live in `doc.go`, not at the top of an arbitrary file.
- **Godoc on every exported symbol.** First sentence starts with the symbol name, ends with a period:
  ```go
  // Redactor applies a compiled ruleset to slog records and HTTP payloads.
  // Redactors are safe for concurrent use.
  type Redactor struct { … }
  ```
- **Test files** live next to source: `redactor.go` → `redactor_test.go`. Use table-driven tests (`tests := []struct{ name string; … }{…}`) with `t.Run(tt.name, …)`.

---

## 7. Testing requirements

- **Every new exported function** gets at least one test. No exceptions.
- **Every redaction code path** gets property-based coverage (`testing/quick` or `pgregory.net/rapid` if added as a test-only dep). The redactor's correctness is the product.
- **`slogtest.TestHandler`** must pass on every commit that touches `handler.go`. Add to CI as `go test ./... -run TestSlogCompat`.
- **`-race` required** for local `go test` and in CI (`go test -race ./...`).
- **Golden file tests** live in `testdata/golden/`. Output must be deterministic: sort map keys, inject a fixed clock, seed any randomness. Update with `go test -update` wired to a `-update` flag.
- **Benchmarks** live in `_test.go` alongside code (`BenchmarkRedact`). The separate `bench/` module is **only** for comparative benchmarks against zap/zerolog/logr.
- **Fuzz targets** seed corpora under `testdata/fuzz/<Target>/`. CI runs `go test -fuzz=Fuzz… -fuzztime=60s` per PR; a nightly job runs `-fuzztime=10m`.
- **Never skip a test** without an issue link: `t.Skip("flaky on Windows, see #42")`. A bare `t.Skip()` is an automatic reviewer block.
- **Example tests** (`ExampleNewPCI`, etc.) are part of the test suite, not optional. See §12.

---

## 8. Commit and branch discipline

### Conventional Commits

```
<type>(<scope>): <subject>

<body — explains WHY, not WHAT>

<footer — BREAKING CHANGE:, Refs: #N, Co-authored-by:>
```

- **Types**: `feat`, `fix`, `docs`, `test`, `perf`, `refactor`, `chore`, `bench`.
- **Scopes** match module layout: `redact`, `httpmw`, `gin`, `handler`, `preset`, `ci`, `docs`, `internal`.
- **Subject**: imperative mood (`add`, not `adds`/`added`), lowercase, no trailing period, <72 chars.
- **Body wraps at 72 chars.** Explain the motivation and tradeoff; the diff shows the what.

Good: `feat(redact): add Luhn detector with Damm fallback per ADR-007`
Bad:  `Updated redactor to check credit card numbers.`

### Branches

- **Solo workflow**: commit directly to `main` for one-line fixes, doc typos, and changelog edits.
- **Feature branches** for anything multi-commit: `m<N>-<slug>`, e.g. `m4-httpmw-bodycapture`, `m6-gin-adapter`.
- **PRs against own repo** for feature branches: self-review, CI green, squash-merge. Yes, even solo — it forces a second reading.
- **Never force-push `main`** once a tag exists on it.

### Tags

- Format: `vMAJOR.MINOR.PATCH`, signed (`git tag -s v0.3.0 -m "…"`).
- Tag on: every milestone completion, every bug fix release, and **never more than 7 days of unreleased commits** on `main`. Stale unreleased changes are a smell.
- Pre-v1.0.0: `v0.X.Y` where `X` increments per milestone.

---

## 9. When to ask vs proceed

### Proceed without asking

- Task is a direct implementation of something listed in `docs/architecture.md`'s public API.
- Change is contained to a single package with clear, testable acceptance criteria.
- The test is mechanical (table-driven over existing types).
- Fixing a bug whose fix does not change a signature or contract.

### Ask before proceeding

- The change touches any exported symbol's signature (add, rename, remove, reorder parameters, change return type).
- The change adds a new exported symbol.
- The change adds or removes a line in `go.mod` / `go.sum` (direct dep change).
- The change crosses more than one package boundary.
- The change reduces test coverage or disables a test.
- The change pressures, bends, or contradicts any ADR.

### How to ask

State the concern in one sentence. Offer **2–3 alternatives**. Recommend one with rationale. Example:

> **Concern**: `NewPCI` currently returns `*Config`; the roadmap implies it should return `(Config, error)` so that DSL compile errors surface at construction rather than at first use.
>
> **Options**:
> 1. Keep `*Config`, panic on invalid DSL (programmer-error philosophy, §5).
> 2. Return `(Config, error)`; breaking change, but aligned with the rest of the API.
> 3. Add `MustNewPCI` wrapper that panics, keep `NewPCI` returning `(Config, error)`.
>
> **Recommendation**: option 3 — mirrors stdlib `regexp.MustCompile` / `template.Must` and preserves ergonomics. Requires an ADR amendment to ADR-001.

---

## 10. Security and compliance defaults

> The redaction engine's correctness **is the product**. A regression here is worse than a broken build.

- **Never optimize away a redaction pass.** A "fast path" that skips the redactor is a P0 bug, even if the input looks safe.
- **Never emit raw input** to any writer (stderr, file, sink) without going through the redactor first.
- **Fail-closed**: when a rule match is ambiguous, redact. When a detector errors, redact. When the config is malformed, refuse to start. It is always safer to over-redact.
- **Never log the redactor's own state** (rules, compiled patterns, attribute paths) above DEBUG level. A WARN log containing "failed to compile rule `cardholder.pan`" leaks the schema.
- **No `unsafe`. No cgo. No `os/exec`. No network calls from `redact/` or `httpmw/`.** No reflection beyond the `slog.LogValuer` interface.
- **Test fixtures** use obviously fake values:
  - PAN: `4111111111111111` (the canonical Visa test number) or `4242424242424242` — never scrape a real card.
  - Email: `alice@example.test`.
  - SSN: `000-00-0000`.
  - JWT: hand-construct, never paste a real token.
- **Fuzz findings that produce unredacted output** are P0 security bugs. Do not file them publicly. Use the GitHub private security advisory workflow; update `SECURITY.md` with the disclosure timeline.

---

## 11. Performance discipline

Targets from `docs/architecture.md` (abbreviated):

| Metric | Target |
| --- | --- |
| No-match path allocations per log line | 0 |
| Redact pass on 1KB record, 10 rules | < 500 ns |
| HTTP middleware overhead (no body) | < 1 µs |

Rules:

- **Measure before claiming.** Use `benchstat` to compare before/after across ≥ 10 runs each. A single-run "20% faster" claim is noise.
- **Zero-allocation goal** applies to the no-match path (the common case in production). Match paths may allocate reasonably.
- **`sync.Pool`** only after profiling shows allocation pressure. Premature pooling hides ownership bugs.
- **`// HOT` convention**: annotate functions on the middleware request path. Changes to HOT code require a benchstat diff in the commit message or PR.
- **Don't optimize without a benchmark** that proves the need. Readable code beats micro-optimized code when the benchmark is silent.
- When a benchmark regresses, **bisect first, optimize second**. `git bisect run go test -bench=. -run=^$ …`.

---

## 12. Documentation expectations

- **Godoc on every exported symbol.** pkg.go.dev is the first 100 words a potential user reads.
- **README has a quick-start in the first screenful.** No marketing paragraphs above the fold. Example: PCI preset wiring in ≤ 15 lines of Go.
- **CHANGELOG.md** follows Keep-a-Changelog + SemVer. Update with every user-visible change, **not** at release time. Unreleased entries live under `## [Unreleased]`.
- **ADRs are immutable.** To change a decision, write a new ADR that supersedes the old; link both ways.
- **Example tests are mandatory** for: the root package, each subpackage (`redact`, `httpmw`, `gin`), and each of the four primary use cases called out in `docs/roadmap.md` §4.
  ```go
  func ExampleNewPCI() {
      cfg := redactlog.NewPCI()
      // …
      // Output: { "msg": "ok", "pan": "***" }
  }
  ```

---

## 13. Dependency discipline

- **Every new direct dependency requires an ADR amendment or a new ADR.** No exceptions, including test-only deps in the main module.
- **`gin-gonic/gin` is a special case.** Go modules cannot scope a dependency to a single subpackage, so the root `go.mod` necessarily includes it. Enforce the "gin imports only in `gin/`" rule via a CI check:
  ```bash
  # scripts/check-gin-scope.sh
  if go list -deps -f '{{range .Imports}}{{.}}{{"\n"}}{{end}}' \
       $(go list ./... | grep -v /gin) | grep -q '^github.com/gin-gonic/gin$'; then
      echo "gin imported outside gin/ subpackage"; exit 1
  fi
  ```
- **`semconv/v1.26.0` is pinned.** Upgrading requires an ADR amendment and a migration note in CHANGELOG.
- **No `golang.org/x/exp/slog`** or similar indirect helpers once stdlib provides the primitive. Cleaning these up is a quarterly chore.
- **Monthly dep review**: `govulncheck ./...` + Dependabot PRs + `go mod tidy` + a deliberate re-reading of `go.mod`. Put it on the calendar.
- **Test-only deps** (e.g., `rapid`, `cmp`) go in `require` blocks as usual but must be audited for transitive bloat.

---

## 14. Tooling and automation

### Per-commit (local)

```bash
golangci-lint run
go vet ./...
go test -race ./...
```

### Per-push (local)

```bash
govulncheck ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1   # verify >= target
```

### Per-tag (release checklist from `docs/roadmap.md` §10)

Run the full checklist; do not rely on memory. Highlights: changelog updated, godoc spot-checked, `bench/` diffed vs previous tag, signed tag pushed, GitHub release drafted with highlights.

### CI matrix

- Lint (`golangci-lint`).
- Unit + race (`go test -race ./...`) on Linux + macOS, Go 1.23 and 1.24.
- Fuzz-short (`-fuzztime=60s` per target) on every PR.
- Benchmarks on `main` only (avoid PR noise), archived with `benchstat`.
- `govulncheck` weekly + on `main`.

### Local hook (optional)

A `.githooks/pre-commit` running `golangci-lint run --new-from-rev=HEAD~1` and `go test -race -short ./...` catches most problems before push. Install once with `git config core.hooksPath .githooks`. Not required — CI is the source of truth.

---

## 15. Interaction patterns

When collaborating on this repo, Claude Code should:

- **Anchor to the milestone.** "For M4 I need to add head-truncation to `httpmw/capture.go`." This grounds the conversation in roadmap context and makes scope drift visible.
- **Cite ADRs when making design arguments.** "Per ADR-003 we depend on `httpsnoop` rather than rolling our own `ResponseWriter` wrapper." Claims without an ADR citation for contested decisions should be resisted.
- **Follow the scope-check cascade** when asked for a feature:
  1. Is it in `docs/architecture.md`? If yes → proceed.
  2. Is it covered by an ADR? If yes → follow the ADR.
  3. Otherwise → propose (§9) or punt to `docs/v2-ideas.md`.
- **Use full paths**: `redact/trie/walker.go`, not `walker.go`. Ambiguity costs time.
- **Follow the module layout exactly** when creating new files. Do not invent `pkg/` or `cmd/` directories — this project doesn't use them.
- **When tests fail: fix the bug first, then the test.** If the test itself is wrong, say so and justify. Never silently mute a failure by loosening an assertion.
- **When benchmarks regress: bisect before optimizing.** A regression of unknown origin means we do not yet understand the change; optimizing without that understanding creates a second bug layered on the first.

---

## 16. Glossary

- **redactor** — the compiled, concurrency-safe engine that applies a ruleset to a log record or HTTP payload. Lives in `redact/`.
- **handler wrapper** — our `slog.Handler` implementation that delegates to a user-supplied inner handler after redaction (ADR-001).
- **detector** — a pluggable content-based redaction trigger (e.g., Luhn for PANs, regex for emails). Off by default except within a preset (ADR-007).
- **censor** — the replacement value written in place of a matched field. Always `"***"` in v1 (ADR-008).
- **DSL** — the Pino-style path mini-language, e.g., `user.cards[*].pan`, compiled into a trie at `New()` time (ADR-002).
- **trie** — the compiled rule structure, walked once per record to decide redaction.
- **walker** — the code that traverses an `slog.Record`'s attributes (or a JSON body) against the trie.
- **httpsnoop** — `github.com/felixge/httpsnoop`, the standard library of capturing response metadata from `http.ResponseWriter` (ADR-003).
- **semconv** — OpenTelemetry semantic conventions; we pin `v1.26.0` for HTTP attribute names (`http.request.method`, etc.).
- **slogtest** — `testing/slogtest`, stdlib's conformance suite for `slog.Handler` implementations.
- **PII** — Personally Identifiable Information.
- **PAN** — Primary Account Number (credit/debit card number). The canonical PCI-DSS redaction target.
- **PCI** — Payment Card Industry Data Security Standard (PCI-DSS). Our single v1 preset.
- **LogValuer** — `slog.LogValuer` interface; the one sanctioned form of reflection-like behavior in redactlog.
- **WithAttrs / WithGroup** — `slog.Handler` methods that must be implemented correctly for `slogtest` to pass; both are redaction-aware in our wrapper.

---

<!-- End of CLAUDE.md. If you are editing this file, update the "Current milestone" line in §1 and
     run `wc -l CLAUDE.md` afterwards. If we cross ~700 lines, split into .claude/rules/ with paths: frontmatter. -->