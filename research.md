# Building a redaction-first, audit-grade HTTP logger in Go

Designing a production-grade compliance logger for Go means making a small number of consequential choices early: **a safe-by-default redaction engine, a tamper-evident audit path separated from operational logs, a slog-native surface, and HTTP middleware that doesn't silently break streaming responses**. This report synthesizes research across redaction DSLs (pino-redact, Datadog SDS), tamper-evident designs (AWS CloudTrail, HashiCorp Vault, QLDB, Certificate Transparency), compliance rulesets (PCI-DSS v4.0.1, GDPR, HIPAA Safe Harbor, SOC 2 CC7), slog internals, `net/http`/Gin middleware pitfalls, OpenTelemetry semconv, and Go library craftsmanship — with explicit design implications for your library at each step. The goal is to give you a clear map of the decisions and the traps, not a blueprint.

The strongest single recommendation: **treat redaction, audit, and operational logging as three separable concerns that compose**, not as one monolithic path. Vault, CloudTrail, and Datadog all do this. Redaction keeps secrets out of log text; audit provides cryptographically-verifiable event evidence; operational logging is for SREs. A Go library that cleanly separates these three will be easier to adopt, easier to evolve, and easier to defend in an audit.

---

## 1. Redaction engine design

### Path DSLs: steal from pino, not from JSONPath

The most influential working reference is **fast-redact / pino-redact**. Both accept a small DSL — dot notation, bracket notation for non-identifier keys, and a *single* wildcard per path (e.g. `headers["X-Forwarded-For"]`, `users[*].email`). fast-redact compiles each path at init time into a specialized accessor function; the measured overhead is roughly **1–2% of `JSON.stringify` with static paths and ~25% with wildcards**. The design is mutate-then-restore (not deep-clone) because even the fastest JS clone was too slow. A recent rewrite, `@pinojs/redact`, moves to a selective-clone approach and reaches parity on large objects.

Comparing DSL options for Go:

- **Pino-style dot+bracket+single-`*`**: simplest, matches ~95% of real redaction needs, compiles to a cheap closure-tree. Go-idiomatic.
- **GJSON (`tidwall/gjson`)**: native Go, zero-alloc scanning, `#` for arrays, paired with `sjson` for mutation. Pragmatic middle ground.
- **JSONPath (RFC 9535)**: powerful (`..` recursive descent, filters) but implementations diverge and runtime ASTs are heavyweight.
- **JMESPath**: formal spec and test suite but its projection model is unfamiliar to most Go developers.

**Design implication**: ship a Pino-compatible subset as the core DSL. It's familiar to Node refugees, maps cleanly to Go's type system, and a path like `request.body.card.number` compiles to a trivial walk. Offer optional `gjson`-style array selectors for power users; keep full JSONPath/JMESPath out of v1.

### Compile once; walk a trie at runtime

Every mature redactor (fast-redact, Datadog SDS, `@pinojs/redact`) pre-compiles paths at config time. The Go-idiomatic equivalent is a **trie keyed by path segment** with explicit wildcard edges, built once when the handler is constructed and held in an immutable struct. On hot path, walk the trie alongside the decoded payload (`map[string]any`) or against typed structs via generated accessors. Avoid `reflect` in the hot path where you can; `LogValuer` gets you struct-level redaction allocation-free.

### Type-aware and path-aware redaction are complementary, not alternatives

**Type-aware** redaction (`type PAN string` implements `LogValue() slog.Value`) catches domain types wherever they appear — including in error messages, stack traces, and any third-party library that uses slog. **Path-aware** redaction (`request.body.ssn`) handles opaque JSON from HTTP bodies where types are unknown. Fintech and healthtech libraries need both.

A critical slog gotcha: **slog does not auto-resolve `LogValuer` on nested struct fields**. When you log `slog.Any("creds", Creds{Token: "s3cret"})`, slog treats the whole struct as `KindAny`, reflects/formats it, and never calls `Token.LogValue()`. This is why `mizutani/masq` exists — it walks attributes via `ReplaceAttr` and applies type-based redaction through reflection. Your library will need the same.

### Luhn is necessary but insufficient for credit-card detection

The Luhn algorithm catches typos, not adversaries. A random 16-digit number has a **10% chance of passing Luhn**. Production systems (Datadog SDS, AWS Macie, Google DLP) combine three gates: length bounds (13–19 digits per ISO/IEC 7812), **BIN prefix check** (Visa=4, MC=51–55 / 2221–2720, Amex=34/37, etc.), and **keyword proximity** — tokens like `card`, `pan`, `cvv` must appear within ~30 characters. Datadog ships this as a default. With all three gates, false-positive rate drops below 0.1%.

### Regex vs structural: use both, in that order

Structural redaction (path-based on parsed JSON) is precise and cheap; regex is comprehensive but risky. Go's built-in `regexp` uses **RE2 (Pike NFA), which runs in linear time and is immune to ReDoS by design** — a major advantage over Node (pino) and Java. The cost is no backreferences or lookarounds, which Datadog Observability Pipelines also forbids for the same reason.

Best practice, from Datadog and Arcjet: **structural first, regex second**, and make regex a per-rule opt-in with a max-input-length gate (e.g., skip regex on payloads larger than 1 MB). **Prefer allow-lists over deny-lists** — declare which fields are safe to log, default everything else to redaction.

### Benchmark across four axes

Redaction libraries publish numbers that aren't comparable because they don't disclose their test conditions. A credible benchmark varies **object size (small/medium/large), rule count (1/4/16/64), wildcard vs static paths, and hit rate (rules matching vs rules missing)**. Publish allocations and nanoseconds per event, plus a no-op baseline (JSON marshal without redaction) so users can compute pure overhead.

---

## 2. What the compliance frameworks actually require

### PCI-DSS v4.0.1: CVV/PIN/track never, PAN masked

PCI-DSS v4.0.1 (mandatory since March 31, 2025) draws a bright line: **Sensitive Authentication Data — full magnetic track data, CVV/CVC/CID/CAV2, and PINs — MUST NOT be stored after authorization, even encrypted** (Req 3.3). Primary Account Numbers may be displayed but only up to **first-6 and last-4 digits**; longer display requires a documented business need (Req 3.4). Where PAN is stored, it must be rendered unreadable via keyed hashing (plain SHA-256 is insufficient — Req 3.5.1.1), truncation, or strong encryption with key management.

Requirement 10 governs log content itself: record user ID, event type, date/time, outcome, origination, and affected resource for every access to cardholder data, admin action, and authentication event. **Retain audit logs ≥12 months, with ≥3 months immediately available**. As of March 31, 2025, automated log review is mandatory (Req 10.4.1.1).

For the library: ship a `PCI()` preset that strips full PAN, CVV, PIN, and track fields by path and by Luhn-plus-BIN regex. Provide a `MaskPAN()` helper that preserves first-6+last-4. Never redact the Req 10.2 audit fields (actor, action, outcome, timestamp) — those are mandated to appear.

### GDPR: the erasure paradox drives architectural choices

GDPR Article 4 defines personal data broadly (names, emails, IPs, cookie IDs, any identifier). Article 9 adds **special categories** — health, biometric, genetic, racial/ethnic, political, religious, sexual-orientation data — requiring stronger justification to process. Article 17's right to erasure creates a real tension with append-only logs.

The regulator-accepted resolution has three components: **minimize** personal data in logs, **pseudonymize** with a keyed hash so deleting the mapping table renders logs effectively anonymous, and apply **retention limits**. Recital 26 draws the crucial line: pseudonymized data is still personal data (GDPR applies); anonymized data falls outside GDPR scope only if re-identification is not "reasonably likely." A keyed HMAC of an email is pseudonymization, not anonymization.

This is why **crypto-shredding** (Section 3) matters: encrypt personal fields with per-subject keys; deleting the key renders the ciphertext unreadable, satisfying the spirit of erasure without violating append-only chain integrity.

### HIPAA: the 18 identifiers are an exact checklist

The HIPAA Safe Harbor list in 45 CFR 164.514(b)(2) is concrete and has been stable since 2002. The 18 identifier categories span names, geographic subdivisions smaller than a state (with a specific exception for 3-digit ZIP prefixes representing >20,000 people, and 17 listed ZIPs that must become `000`), all dates except year related to an individual (including all **ages over 89**), phone/fax/email, SSN, MRN, health-plan numbers, account numbers, certificate and license numbers, vehicle and device identifiers, URLs and IP addresses, biometric identifiers, full-face photos, and a catchall for any other unique code.

A `HIPAA()` preset should match all 18 by path and by regex with keyword proximity gates. Provide `TruncateZIP(zip)` and `AgeCap(n)` helpers for the non-obvious cases.

### SOC 2 CC7: capture the right events, don't redact them away

SOC 2's Common Criteria CC7.2 requires monitoring for anomalies indicating malicious acts and errors; CC7.3 requires evaluation of security events. Auditors expect coverage of authentication success/failure, authorization decisions, privilege escalations, configuration changes, data access to sensitive resources, admin actions, and system errors. Retention is typically 12 months to align with PCI.

Crucially, SOC 2 wants these events **visible and identifiable**. A redaction library that obliterates actor IDs or event types in pursuit of PII minimization will fail a SOC 2 review. Design presets to preserve security-relevant fields; optionally pseudonymize actor IDs with a keyed hash.

### Cross-framework data type overlap

The sensitive data types that appear in every framework are **names, emails, phone numbers, SSNs, IP addresses, geolocation, financial identifiers, and authentication material**. A shared default list of redaction rules covers 80% of obligations across PCI/GDPR/HIPAA/SOC 2; regulation-specific presets layer on top.

### Version presets; don't auto-update

Regulated customers need audit-reproducibility: the same config, run tomorrow, must produce the same redaction. Model after Datadog's 90+ versioned SDS rules: expose presets as **frozen, dated rulesets** (`PCI_v4_0_1_2024_06()`) plus a `PCILatest()` alias for those who want HEAD. Track regulation version and last-reviewed date as metadata on each preset. Additive changes only within a preset version; subtractive changes require a new version.

---

## 3. Audit logging and tamper-evident design

### The canonical record schema is older than blockchain

Across CloudTrail, QLDB, Vault, and the Crosby-Wallach paper, every tamper-evident record carries the same core fields: **sequence number, timestamp, actor, action, resource, outcome, previous-hash, current-hash**. This matches the SOC 2 and OCSF canonical who/what/where/when/how pattern. OCSF 1.3+ (backed by AWS, Splunk, IBM, Linux Foundation) is the fastest-growing standard; CADF (DMTF DSP0262) is mature but older. Plan to ship an OCSF adapter and a minimal SOC2-core adapter; let users plug in others.

Canonicalization is the **single biggest correctness risk**: hash and signature verification depends on deterministic serialization. Use RFC 8785 JCS or deterministic CBOR, not `json.Marshal` (struct field tags can drift on refactor). Canonicalize without the `hash` field, then append and rehash.

### Hash chain vs signatures: use both, asymmetrically

HMAC-SHA256 is fast (~500 MB/s/core with SHA-NI), trivially integrated, and sufficient when the verifier lives in the same trust domain. Asymmetric signatures (Ed25519 preferred over RSA-2048 — smaller, safer, deterministic) matter when **external auditors or regulators need to verify without holding the signing key**, which is the fintech/healthtech reality.

CloudTrail's pattern is the right baseline: **HMAC/hash every event, sign only periodic digest files (hourly batches)**. Ed25519 signs ~70k sigs/s/core; RSA-2048 only ~1k/s, so per-event RSA is a dead-end. Include `key_id` and public-key fingerprint in every digest so key rotation is auditable.

For the library: stdlib `crypto/hmac` + `crypto/sha256` as default chain link, pluggable `Signer` interface with Ed25519 and KMS-backed implementations (AWS KMS, GCP KMS, Vault Transit) for digest signing.

### Merkle trees are a v2 feature

A linear hash chain is sufficient for single-writer, single-verifier deployments with under ~10M events/month — the vast majority of SOC 2 fintech apps. Merkle trees (Certificate Transparency, QLDB) become worth the complexity when you need **O(log n) inclusion proofs, consistency proofs across log states, or multi-tenant "prove my events without downloading the log"** patterns. Start linear; add an optional Merkle mode later using `github.com/transparency-dev/merkle` rather than rolling your own.

### Crypto-shredding resolves the GDPR / append-only tension

Encrypt PII fields with per-subject data encryption keys (DEKs), wrap DEKs with a KMS-managed key-encryption key (KEK), destroy the subject's KEK on erasure request. The ciphertext persists in immutable logs but is cryptographically unreadable. This is how Apple's "Erase all content and settings," Spotify's Padlock, and MongoDB CSFLE all work.

Two critical design constraints: **hash the ciphertext, not the plaintext** (otherwise key destruction invalidates the chain); and **emit the erasure itself as a chained audit event** containing the destroyed `kek_id` and requester. S3 Object Lock in Compliance mode is WORM — no one, not even root, can delete objects before retention expires — which means GDPR erasure can only be satisfied by crypto-shredding, never by physical deletion. Document this explicitly.

### Append-only storage: three viable tiers

- **File-based**: `O_APPEND` on Linux gives per-`write()` atomicity regardless of size, but POSIX only portably guarantees this up to `PIPE_BUF` (4096 bytes). Keep records ≤4 KiB or length-frame them. `fsync` after batch flush; rename-and-reopen for rotation with a chain-rollover record pointing to the closed file's hash.
- **Database**: PostgreSQL with INSERT-only grants and `BEFORE UPDATE/DELETE` triggers that raise exceptions. Superusers can still bypass; defense-in-depth via logical replication to WORM storage. QLDB is being deprecated; Aurora PostgreSQL with ledger extensions is the migration target.
- **Object storage with immutability**: **S3 Object Lock in Compliance mode** (Cohasset-assessed for SEC 17a-4(f), FINRA 4511, CFTC 1.31) is the gold standard. GCS Bucket Lock and Azure immutable blob storage are equivalents. Must be enabled at bucket creation; irreversible.

### Separate operational from audit logs

Vault is explicit: *"Audit logs differ from server logs… If no audit device can log, Vault refuses to service the request."* The distinction matters because **retention differs** (30–90 days operational vs 6–7 years audit per SEC 17a-4 and HIPAA), **failure semantics differ** (ops best-effort, audit fail-closed), **consumers differ** (SRE vs Security/Compliance/Legal), and **access control differs** (SoD required by SOC 2 CC 6.1).

Architect as two distinct types: a `Logger` delegating to `log/slog` and an `Auditor` that returns errors callers must handle. Support `OnAuditFailure` policies (Block | Alert | Drop) with the Vault-style default being Block. Dual-writer with quorum (`require_n_success=1|2`) handles sink outages gracefully.

### Performance: async with group commit

SHA-256 hashing is free at these volumes (500k records/s/core). The dominant cost is **`fsync` (0.5–5 ms NVMe, 5–30 ms EBS)** and **KMS signing calls (10–30 ms RTT)**. Standard solution: async group commit borrowed from MySQL binlog and MariaDB Aria — a leader goroutine drains the queue, computes batch hash and signature, fsyncs once, releases all waiters. Batching 100 events → 100k events/s on NVMe.

Expose `Sync() error` for test/shutdown and a strict-sync mode for fintech flows where durability must precede response. Never call KMS sync per event.

### Ship a verifier CLI

External auditors ask "how do I verify your logs?" The answer should not be code you haven't written. Ship a `verify` CLI with subcommands for chain walk, digest signature verification, inclusion/consistency proofs (Merkle mode), and online S3 walking. Output in both human and JSON formats; non-zero exit code on any invalidity for CI integration. AWS's `aws cloudtrail validate-logs` is the reference shape.

---

## 4. slog integration: implement all four methods, don't embed

### Handler architecture

Custom handlers must implement `Enabled`, `Handle`, `WithAttrs`, and `WithGroup`. The official `golang/example/slog-handler-guide` contains several subtle rules: `WithAttrs`/`WithGroup` must **copy** the handler, never mutate; slices must be cloned with `slices.Clip` before append to avoid aliasing; **unopened groups** must not emit a `g:` prefix until an attr actually arrives; pre-format `WithAttrs` content once into a `preformatted []byte` rather than re-formatting per `Handle` call.

**Do not embed `slog.Handler`** and override only some methods — embedded defaults return the wrong type and lose attrs/groups. A wrapper for redaction must implement all four methods.

### LogValuer limits and ReplaceAttr costs

`LogValuer` is essential for type-driven redaction (the `Secret` pattern) but has the nested-struct-field gotcha discussed in Section 1. Use it for top-level attributes and in your own types; for nested fields inside user-supplied structs, fall back to `ReplaceAttr`.

`ReplaceAttr` is called **for every non-group attribute on every record**. Setting even a no-op `ReplaceAttr` adds an allocation per attribute with TextHandler (GitHub issue #61774). Built-in attrs (time, level, msg) only appear when `len(groups) == 0`, which is the filter for zeroing time in tests. For a redaction library, write a type-switch fast path before reflection, and document the per-attribute cost.

### Context propagation: no stdlib blessing, two viable patterns

slog deliberately does not ship `FromContext`/`NewContext` — the team removed them from the proposal (issue #58243). Two community patterns:

1. **Context-aware extractor handler** (`veqryn/slog-context`): middleware calls `slogctx.Prepend(ctx, "request_id", rid)`; the handler extracts at `Handle` time. No logger stored in ctx; third-party code doesn't need to know.
2. **Explicit logger passing**: middleware stores logger in `gin.Context` / request ctx; handlers retrieve. Dependencies visible.

For HTTP middleware, the extractor pattern is superior: users can set request-scoped attrs from anywhere (handlers, sub-handlers, libraries) and the middleware picks them up at log time. This is exactly how `go-chi/httplog.SetAttrs(ctx, …)` works.

### Multi-handler for ops+audit dual-write

`samber/slog-multi` provides `Fanout` (broadcast to N handlers), `Router`/`FirstMatch` (conditional routing), `Pipe` (middleware chain). Dual-write pattern: Fanout to an ops sink and an audit sink, each with its own redaction `Pipe` so neither sees raw secrets. Wrap with `RecoverHandlerError` so a failing sink never panics the request. Go 1.24+ also has stdlib `slog.MultiHandler`.

### OTel slog bridge auto-injects trace context

`go.opentelemetry.io/contrib/bridges/otelslog` maps `slog.Record` fields to OTel log records: `Time`→Timestamp, `Message`→Body, `Level`→Severity (Debug→1, Info→9, Warn→13, Error→17), and — the key feature — **calls `trace.SpanContextFromContext(ctx)` in `Handle` and attaches TraceID/SpanID/TraceFlags automatically**. Requires callers to use `*Context` methods (`InfoContext`, `LogAttrs`) so ctx reaches Handle.

**Design implication**: accept `*slog.Logger` from the user — don't hardcode a handler. Users pass `otelslog.NewLogger(...)` and get log-trace correlation free. Combine with `slog-multi.Fanout` to keep a human-readable stdout handler alongside.

### Performance patterns

Prefer `logger.LogAttrs` over `logger.Info` — it takes `...slog.Attr` directly, avoiding the `any`→Attr conversion and its allocations. Pre-attach request-scoped fields via `logger.With(...)` at middleware entry so per-log Handle only formats the delta. Avoid `fmt.Sprintf`; use typed constructors (`slog.String`, `slog.Int`, `slog.Duration`). Gate `AddSource: true` carefully — `runtime.Callers` is measurable at Debug volumes.

---

## 5. HTTP middleware patterns: the response writer is the trap

### Tee, don't read-all

The naive pattern — `body, _ := io.ReadAll(r.Body); r.Body = io.NopCloser(...)` — eagerly buffers everything, breaks streaming, and defeats `http.MaxBytesReader`. The correct pattern uses `io.TeeReader` + `io.LimitReader`:

```go
r.Body = &teeBody{
    Reader: io.TeeReader(io.LimitReader(r.Body, maxBytes), buf),
    orig:   r.Body,
    buf:    buf,
}
```

This copies only what the handler consumed, preserves streaming, and caps memory. Always pair with `http.MaxBytesReader` at the edge for DoS protection. Never use `httputil.DumpRequest` in production — it buffers everything and emits `\r\n` HTTP wire format.

### ResponseWriter wrapping: use httpsnoop or its pattern

This is where naive middleware breaks production systems. The `net/http` optional interfaces — `Flusher` (SSE), `Hijacker` (WebSockets), `Pusher` (HTTP/2 push), `ReaderFrom` (sendfile fast-path), `CloseNotifier`, and Go 1.20+'s `ResponseController` deadliners — are detected by downstream libraries via type assertion. A `struct { http.ResponseWriter; ... }` wrapper silently claims to implement all of them via promoted methods, then panics or no-ops when called. This is the bug that hit `urfave/negroni` (issue #265, fixed in v3).

`felixge/httpsnoop` solves it with a 1423-line code-generated file: at wrap time it probes which of **7 optional interfaces** the underlying writer implements, then a `switch` over **2⁷ = 128 cases** returns an anonymous struct embedding only the real capability set. Type assertions return truthful results.

For your library, either **depend on httpsnoop directly or vendor its generated code**. Do not write your own minimal wrapper — you will break SSE, WebSockets, or `ReverseProxy` sendfile throughput.

Also: ignore 1xx status codes (Early Hints, Switching Protocols); track `headerWritten` via both `WriteHeader` and `Write` paths; hook `ReadFrom` to catch `io.Copy` fast-paths that bypass `Write`.

### Streaming and compression: know when not to buffer

**Never buffer `text/event-stream`, `application/grpc*`, or long-lived chunked responses.** Detection heuristics: Content-Type prefix match; `Transfer-Encoding: chunked` without `Content-Length`; handler-invoked `Flush()` is the definitive signal — hook it and flip the writer into pass-through mode, discarding buffered bytes. Sentry and Cloudflare have shipped SSE-breaking bugs of exactly this shape.

For compression: **log before compression, not after**. Install the logger closer to the handler than the gzip middleware, so your wrapper sees plaintext. Recommended ordering: `MaxBytesReader → Recovery → Logger → Compression → Handler`. Offer a `LogAfterCompression bool` escape hatch for users needing wire bytes.

### Content-type policy and body caps

**Allow-list by default**: `application/json`, `application/*+json` (RFC 6839), `application/x-www-form-urlencoded`, `text/*`, `application/xml`, `application/yaml`. Deny multipart/form-data, binary types, SSE, gRPC. Use `mime.ParseMediaType` to strip parameters.

For multipart: never log raw bodies. Filenames routinely contain PII (`passport-scan-john-doe-1985.jpg`). Emit structured metadata only — part names, content-types, sizes, content hashes.

For bounded capture, the **first-N + last-M ring buffer** pattern is richer than simple head truncation — errors often surface near the tail of large responses. 64 KiB total (48 KiB head, 16 KiB tail) is a reasonable default, matching `samber/slog-gin`. Always mark truncation explicitly: `body_truncated: true, body_total_bytes: N`.

### Context key hygiene

Use **unexported `struct{}` types or pointer types** as context keys. Zero-sized `struct{}` keys avoid the interface-boxing allocation that `int`-typed keys incur (8 B/op, 1 alloc/op). Never use `string` keys — they collide across packages. Expose typed accessors, never the raw key.

The library's canonical API should be `SetAttrs(ctx context.Context, attrs ...slog.Attr)` — one function that works in Gin (`c.Request.Context()`) and `net/http` (`r.Context()`) alike, with a mutable attr set stored under an unexported key.

---

## 6. Gin integration: three specific pitfalls

**gin.WrapH / gin.WrapF** handle the simple direction. The standard `func(http.Handler) http.Handler` middleware chain signature doesn't map cleanly; use `github.com/gwatts/gin-adapter` when you need it. For your library, ship one implementation as `func(http.Handler) http.Handler` (the portable contract) and a thin Gin adapter.

**Body binding pitfalls**: `c.ShouldBind` and friends consume the body. `c.ShouldBindBodyWith` caches bytes in `c.Keys` under `gin.BodyBytesKey` — but *also* consumes `c.Request.Body`. If middleware calls `ShouldBindBodyWith` and the handler later reads `c.Request.Body` raw, it fails. The correct middleware pattern: **tee once, stash bytes in `gin.BodyBytesKey`**, let downstream handlers use `ShouldBindBodyWith*` to decode from your cached bytes.

**Panic recovery ordering**: register `gin.Recovery()` first — its outermost `defer` runs last on unwind, ensuring panics in downstream handlers produce a 500 that your logger records. If you want the logger to *capture* the panic value itself, give the logger its own `defer recover()` or offer a `RecoverPanics` option.

**Goroutine safety**: `*gin.Context` is pooled. A goroutine holding the original context after the handler returns will race against the next request. **Always call `c.Copy()` before spawning goroutines**, or extract primitive values synchronously. The library's async log shipping must honor this or document loudly.

**Exposing context**: canonical path is `c.Request.Context()`. Don't use `*gin.Context` as `context.Context` across async boundaries, even though it satisfies the interface. Gin's `ContextWithFallback` makes `c.Value(k)` delegate to request ctx, but the idiomatic pattern is to pass `c.Request.Context()` explicitly.

`samber/slog-gin`'s architecture is a solid reference — but note that it only *hides* sensitive headers (deletes them), whereas a redaction library should replace values with `"***"` so auditors can see which headers were present. Its `newBodyReader`/`newBodyWriter` pattern is directly reusable.

---

## 7. API design: zap's hybrid, safe-by-default

### Functional options with a serializable Config

Dave Cheney's functional options pattern is canonical for extensible APIs. Zap's hybrid — exported `Config` struct (JSON-unmarshallable from YAML/env) plus functional `Option` with an unexported `apply` method — is the strongest pattern for a compliance library. The Config handles declarative bootstrapping; options handle programmatic overrides (custom redactors, clocks, sinks) that can't be serialized. The unexported `apply` method prevents third parties from implementing `Option`, preserving future-compatibility.

### Safe-by-default specifics

For a redaction library, safe-by-default has concrete meanings:

- Deny-by-default body capture (opt-in via `WithCaptureRequestBody`)
- Preset sensitive-header denylist (Authorization, Cookie, Set-Cookie, Proxy-Authorization, X-Api-Key)
- Default PII scrubber running over attribute values (email, phone, bearer token, JWT, credit card)
- Bounded sizes for everything captured (64 KiB default)
- Silent truncation explicit in log output

Every relaxation (`WithCaptureRequestBody`, `WithHeaderAllowlist`) is a deliberate, named option. Users can't accidentally leak secrets.

### Progressive disclosure

The zap ladder is the model:

- `httplog.New()` — safe defaults, returns a working `slog.Handler`
- `httplog.NewProduction()` / `NewDevelopment()` — named presets
- `httplog.New(WithLevel(...), WithRedactor(...))` — functional tuning
- `httplog.Config{...}.Build(WithClock(fake))` — full declarative + runtime

Document each tier in the first screenful of the package doc.

### Testability is a v1 feature

Export `WithClock(Clock)`, `WithSink(io.Writer)`, and ship an `httplogtest` subpackage with an observer-style handler (à la `zaptest/observer`) so users can write assertions without plumbing a JSON parser into every test.

### v1 backward-compat: opaque types and internal/

Adopt the Go 1 compatibility promise at v1.0.0. Make `Option` an interface with an unexported method. Return `*Logger` with only methods, no exported fields. Put regex sets, default denylists, and response-writer wrappers under `internal/` so users can't lock onto them. Reserve `Experimental*` prefix for unstable options (grpc-go's convention). Hyrum's law guarantees that anything observable becomes someone's dependency; minimize observable surface.

---

## 8. Naming and positioning

### Verdict on a shortlist

Go package naming conventions are strict: lowercase, no underscores, no mixed-case, short, no stutter. Availability research across `pkg.go.dev` and GitHub yields this shortlist (full availability checks in the research annex):

| Name | Verdict | Fit for regulated-industry positioning |
|---|---|---|
| **`redactlog`** | Appears available as top-level module | Best balance: clear, greppable, low stutter, SEO-friendly |
| **`attestlog`** | Appears available | Strongest positioning — "attest" implies cryptographic evidence, matches audit-grade claim |
| **`trustlog`** | Appears available | Brand-forward; aligns with Vanta/Drata compliance vocabulary |
| **`auditgate`** | Appears available | Branded-descriptive hybrid; "gate" evokes middleware choke point |
| `custos` / `probity` | Appears available | Distinctive Latin roots; require more marketing investment |

**Names to avoid**: `redact` alone (crowded — CockroachDB, Pingcap, Replicated, etc.); `auditrail` (`botchris/go-auditrail` owns it); `pii-shield` (`aragossa/pii-shield` is a direct competitor); `safelog` (Palantir's safe-logging-go ecosystem); `sentinel`, `aegis`, `vault`, `paladin`, `warden`, `ledger` (all established Go projects); anything with a `-go` suffix (non-idiomatic).

**Top recommendation**: `redactlog`. It communicates the unique value prop (redaction-first), is discoverable via search, reads well at call sites (`redactlog.Middleware(...)`), and is not conflicted. If you want stronger differentiation on the audit/crypto side, `attestlog` is the number-two choice.

### Positioning language

Adjacent compliance tools use verbs of assurance (*prove, attest, verify, continuously*) and containment metaphors (*vault, seal, shield*). Vanta's tagline is "Automate compliance, manage risk, and prove trust continuously"; HashiCorp Vault leads with identity and secrets management. Avoid destruction framing (scrub, kill, strip) — buyers in regulated industries want seriousness and containment.

Viable taglines for your library:

1. "Audit-grade HTTP logging for Go — redaction-first, compliance-ready."
2. "HTTP logs your auditors will love. PII your compliance team will trust."
3. "Tamper-evident, redaction-first request logging for fintech and healthtech Go services."
4. "The missing compliance layer between `net/http` and your log pipeline."

---

## 9. OpenTelemetry semantic conventions: pin to a version, follow the migration path

### HTTP spans are stable since v1.23.0

The HTTP semantic conventions became **stable in semconv v1.23.0 (November 2023)**; current release is v1.40.0. The rename from legacy to stable form is complete and instrumentations are expected to either emit stable-only or dual-emit during migration.

Core attribute names your library should emit (all stable):

**Required on server spans**: `http.request.method`, `url.path`, `url.scheme`. **Conditionally required**: `http.response.status_code` (if received), `http.route` (if routed), `error.type` (on error), `server.port`, `url.query`, `network.protocol.name` (if not HTTP). **Recommended**: `client.address`, `network.peer.address`, `network.peer.port`, `network.protocol.version`, `server.address`, `user_agent.original`. **Opt-in**: `client.port`, `http.request.header.<key>`, `http.response.header.<key>`, `http.request.body.size`, `http.response.body.size`.

**Method well-known values** (stable): `CONNECT`, `DELETE`, `GET`, `HEAD`, `OPTIONS`, `PATCH`, `POST`, `PUT`, `TRACE`, `_OTHER`. Unknown methods normalize to `_OTHER`; override via `OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS`.

**Span status rules**: unset for 1xx–3xx (unless max redirects); 4xx is unset on SERVER, Error on CLIENT; 5xx is Error. Client cancellations are not errors.

### Migration ghosts: http.method → http.request.method

Legacy renames your library must not emit: `http.method` → `http.request.method`; `http.status_code` → `http.response.status_code`; `http.url` → `url.full`; `http.scheme` → `url.scheme`; `http.target` → `url.path` + `url.query`; `net.peer.*`/`net.host.*` → `client.*`/`server.*`. Duration metrics changed from milliseconds to seconds. Honor the `OTEL_SEMCONV_STABILITY_OPT_IN` env var (`http` for stable-only, `http/dup` for dual-emit) if you support users mid-migration.

### Log records carry trace context explicitly

The OTel Logs Data Model (stable) defines top-level `TraceId`, `SpanId`, `TraceFlags` fields on every `LogRecord`, plus `SeverityNumber` (TRACE=1–4, DEBUG=5–8, INFO=9–12, WARN=13–16, ERROR=17–20, FATAL=21–24). W3C Trace Context defines 32-hex trace-id and 16-hex span-id (lowercase). Zero values are invalid. Your middleware should extract via `trace.SpanContextFromContext(ctx)` and let the OTel slog bridge inject — don't roll your own formatting.

### Stay aligned: pin semconv version, dual-emit on breakage

Go's `go.opentelemetry.io/otel/semconv/v1.26.0` (and v1.27, v1.28, v1.30, v1.32, v1.34, v1.36, v1.37, v1.39, v1.40) are versioned packages. Pick the latest stable at release and document the pin. Expect breaking changes in non-HTTP domains (RPC's `rpc.system` → `rpc.system.name` in v1.40). Issue #7297 notes multi-library semconv version conflicts — another reason to pin and document.

---

## 10. Testing and benchmarking strategy

### Unit testing with slogtest conformance

Capture slog output by writing a JSON handler to a `bytes.Buffer`, strip timestamps via `ReplaceAttr`, parse line-per-line. Run `slogtest.TestHandler` against your custom handler to prove slog-spec conformance. For richer assertions, `thejerf/slogassert` exposes `AssertPrecise` / `AssertMessage`. Every middleware test should assert both the positive invariant (expected fields present) *and* the negative (no raw secret substring in buffer) — the negative invariant catches encoder-level bugs.

### Property-based testing catches encoding leaks

The core invariant is: *"for all requests R and configured secrets S in R, no element of S appears verbatim in log output."* Use `leanovate/gopter` or `pgregory.net/rapid` for shrinking-capable generators. Generate secrets with metacharacters (JSON escapes, HTML entities, unicode zero-width joiners) to catch encoding round-trips — a token like `abc\u0031\u0032\u0033` rendering as `abc123` in the output is a real bug class.

### Fuzz for bypass

Go 1.18+ native fuzzing (`testing.F`) with coverage-guided mutation. Seed corpus with known bypass shapes: Authorization variants (case, whitespace, unicode), Cookie headers, URL-encoded forms, JSON with escape-encoded chars, zero-width joiners in values, NFC vs NFD normalization. Every failing fuzz case goes into `testdata/fuzz/FuzzRedactionBypass/` as a permanent regression. Schedule nightly `-fuzz=... -fuzztime=5m` in CI; consider OSS-Fuzz for continuous fuzzing.

### Fair benchmarking vs samber/slog-gin and go-chi/httplog

Pin competitors via a dedicated `benchmarks/go.mod` (zap does this). Drive each middleware with the same handler, same request shapes, same `slog.Handler` target (`slog.NewJSONHandler(io.Discard, nil)`). Vary payload size (0, 1 KB, 64 KB, 1 MB); measure both with redaction ON (fair for your goals) and OFF (pure overhead baseline). Use `b.SetBytes` for MB/s. Run `-count=10 -benchtime=3s` and publish `benchstat` output. Use `b.Loop()` on Go 1.24+ to prevent dead-code elimination.

### Integration tests with golden files

Run a real `gin` server via `httptest.NewServer`; capture log output; normalize timestamps, durations, and request IDs via `ReplaceAttr` before comparing against `testdata/*.golden`. Standard `-update` flag pattern to regenerate. Pair every golden test with an explicit substring-absence assertion for each known-secret value — this fires loudly on leakage even if the golden drifts.

**CI gates**: `go test -race`, `go vet`, `staticcheck`, `govulncheck`. Run benchmarks on self-hosted runners (shared CI has too much variance for benchstat).

---

## Conclusion: five decisions that shape the library

**First, commit to separation of concerns.** Redaction (keeps secrets out of text), audit (cryptographically-verifiable evidence), and operational logging (SRE visibility) are three different products with different failure modes, retention, and consumers. Building them as one path creates compromises that will surface in a SOC 2 review or a GDPR erasure request.

**Second, build the redaction engine around Pino-style paths compiled to a trie, combined with type-aware redaction via `LogValuer`.** This hybrid handles both opaque JSON bodies and domain types (PAN, Secret) uniformly. Ship regulation presets as dated, frozen rulesets; never auto-update.

**Third, choose CloudTrail's pattern for tamper-evidence**: HMAC-SHA256 chain every event, Ed25519-sign periodic digest files, not every event. Async with group commit. S3 Object Lock Compliance mode is the default durable sink. Ship a verifier CLI — auditors will ask.

**Fourth, let slog do the work.** Accept `*slog.Logger` from callers. Use `samber/slog-multi` Fanout for ops+audit dual-write with independent redaction pipes. Let the OTel slog bridge inject trace context. Don't invent a logging abstraction.

**Fifth, treat the `http.ResponseWriter` wrapping problem as solved by `felixge/httpsnoop`.** Either depend on it or vendor its 128-case generated switch. Rolling your own will break SSE, WebSockets, or `ReverseProxy` throughput in ways that surface only in production.

The unique positioning for this library is not "yet another HTTP logger" — it's **"the compliance-grade layer between your framework and your log pipeline"**, where `redactlog` or `attestlog` are honest names. Regulated-industry buyers recognize the gap; no current Go library fills it cleanly. samber/slog-gin ships hidden headers but not redaction; go-chi/httplog ships body capture without compliance framing; cockroachdb/redact is a secret-marker library without HTTP awareness. A library that combines redaction, audit-grade chaining, compliance presets, and idiomatic slog+Gin+net/http integration in one coherent package has no direct competitor as of April 2026.