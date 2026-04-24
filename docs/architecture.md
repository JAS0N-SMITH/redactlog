# redactlog v1 — architecture design document

`redactlog` is a redaction-first HTTP logging middleware for Go services in regulated domains. **v1 ships a compile-once path-DSL redactor, a Gin + `net/http` middleware pair, a `slog.Handler` wrapper that composes in front of the caller's logger, safe-by-default body capture built on `felixge/httpsnoop`, and one PCI preset.** Everything else — audit chains, Merkle proofs, multi-framework adapters, vendor exporters — is explicitly out of scope and deferred to v2. This document is the canonical design reference for implementing v1.

Target Go version: **1.22+** (for `slog` maturity and `slices`). License recommendation: **Apache 2.0** (patent grant matters for enterprise adoption in fintech/healthtech; see §15).

---

## 1. Executive summary

`redactlog` v1 is **the compliance-grade layer between your framework and your log pipeline**. It accepts a `*slog.Logger` the user already configured, wraps a `slog.Handler` that redacts sensitive fields using a Pino-style path DSL plus `slog.LogValuer` type-awareness, and provides HTTP middleware for Gin and `net/http` that captures request/response bodies and metadata under strict byte limits with a header denylist. Field names follow OpenTelemetry HTTP semantic conventions (stable as of semconv v1.26). One compliance preset ships: **PCI basics** — PAN detection via Luhn+BIN regex with first‑6/last‑4 masking, CVV/PIN stripping, and an `Authorization`/`Cookie` header denylist.

**Target user.** A Go backend engineer on a fintech or healthtech team whose SRE or compliance reviewer has flagged "plaintext secrets in logs" as a release blocker. They already use `slog`, they already use Gin or `net/http`, and they don't want to rewrite their logging stack — they want a drop-in middleware with defensible defaults.

**Non-goals for v1.** Tamper-evident audit chains, crypto-shredding, verifier CLIs, GDPR/HIPAA/SOC2 presets, chi/echo/fiber adapters, runtime-reconfigurable admin endpoints, vendor-specific exporters (Splunk/Datadog/CloudWatch EMF), canonical-log-line helpers, composite samplers. These are named in §16 to set expectations; none are architected here.

---

## 2. Module layout

Assumed module path: `github.com/JAS0N-SMITH/redactlog`. One repository, one module, one major-version suffix omitted until v2 (`/v2` on breaking change, per Go module rules).

```
redactlog/
├── go.mod                         // module github.com/JAS0N-SMITH/redactlog
├── go.sum
├── LICENSE                        // Apache-2.0
├── README.md
├── doc.go                         // package-level godoc, stability guarantees
│
├── redactlog.go                   // Config, Option, New, NewPCI, Build
├── handler.go                     // Handler (slog.Handler wrapper): Enabled/Handle/WithAttrs/WithGroup
├── context.go                     // SetAttrs, attrs-from-context extractor
├── options.go                     // every functional option (With*)
├── preset_pci.go                  // NewPCI, PCI path list, PAN regex, Luhn
├── errors.go                      // ErrInvalidPath, ErrBuild, sentinel errors
├── semconv.go                     // stable attribute names (pinned to v1.26)
│
├── redact/                        // public: the redaction engine, usable standalone
│   ├── doc.go
│   ├── redactor.go                // Redactor interface, New(paths, opts) (*Engine, error)
│   ├── dsl.go                     // DSL lexer + parser (tokens, bracket/dot, wildcards)
│   ├── compile.go                 // trie compiler; Program output type
│   ├── walk.go                    // runtime walk over slog.Value / any
│   ├── logvaluer.go               // LogValuer integration helpers (Secret[T], Masked)
│   └── detect.go                  // regex-based detectors (PAN/Luhn); Detector interface
│
├── httpmw/                        // public: framework-agnostic http.Handler middleware
│   ├── doc.go
│   ├── middleware.go              // Middleware(cfg) func(http.Handler) http.Handler
│   ├── capture.go                 // request-body TeeReader, pooled buffers
│   ├── responsewriter.go          // httpsnoop.Wrap integration, body mirror
│   ├── headers.go                 // denylist, allowlist, canonicalization
│   ├── query.go                   // sensitive query param scrubbing
│   ├── requestid.go               // X-Request-ID extract-or-generate
│   └── stream.go                  // streaming/SSE/chunked detection
│
├── gin/                           // public: thin Gin adapter, depends on gin-gonic/gin
│   ├── doc.go
│   └── middleware.go              // New(cfg) gin.HandlerFunc
│
├── internal/
│   ├── buffer/
│   │   └── pool.go                // sync.Pool[*bytes.Buffer] with cap guard
│   ├── canonheader/
│   │   └── canon.go               // textproto.CanonicalMIMEHeaderKey helpers
│   ├── luhn/
│   │   └── luhn.go                // Valid(string) bool, digit iterator
│   └── ringbuf/                   // reserved but NOT used in v1 (see ADR-006)
│       └── placeholder.go
│
├── testdata/
│   ├── golden/                    // expected redacted JSON outputs
│   └── fuzz/                      // fuzz seed corpus
│
├── examples/
│   ├── gin/main.go
│   └── nethttp/main.go
│
└── bench/
    └── comparative_test.go        // vs samber/slog-gin baseline
```

**Rationale.**

- **Root package `redactlog`** holds only the user-facing constructor surface (`Config`, `New`, `NewPCI`, options). Keeping it thin means `import "github.com/JAS0N-SMITH/redactlog"` gives you exactly what 90% of users need, mirroring `uber-go/zap`'s top-level `zap.NewProduction()` ergonomics.
- **`redact/`** is a reusable subpackage so teams can redact non-HTTP data (queue payloads, DB rows) with the same DSL. This is the only subpackage that may be imported in tight loops; it is allocation-budgeted.
- **`httpmw/`** owns the framework-agnostic `net/http` middleware. Body capture, `httpsnoop` wrapping, and header scrubbing live here — nowhere else. This is the layer the Gin adapter delegates to.
- **`gin/`** is its own subpackage so `go get github.com/JAS0N-SMITH/redactlog` does **not** drag in `gin-gonic/gin`. Users who want Gin pay for Gin explicitly. This mirrors `go.opentelemetry.io/contrib/instrumentation/*` layout.
- **`internal/`** is genuinely internal. `luhn`, `buffer`, `canonheader` are implementation details with no stability promise.
- **`bench/`** isolates comparative benchmarks so `go test ./...` stays fast; CI invokes it separately.

---

## 3. Public API surface

Stability tiers:
- **Stable** — covered by semver; breakage requires `/v2`.
- **Experimental** — `// Experimental:` godoc tag; may change in minor releases.
- **Internal** — under `internal/`, not importable.

### 3.1 Root package `redactlog`

```go
// Package redactlog provides a redaction-first slog.Handler wrapper and HTTP
// middleware for regulated services.
package redactlog

// Stable.
type Config struct {
    // Logger is the downstream slog.Logger. Required.
    Logger *slog.Logger

    // RedactPaths is the list of Pino-style DSL paths to redact.
    RedactPaths []string

    // Censor is the replacement token. Default "***". See ADR-008.
    Censor string

    // Detectors run regex/content-based redaction after path redaction.
    // Default: empty (opt-in; see ADR-007).
    Detectors []redact.Detector

    // HTTP governs request/response capture. Zero value = safe defaults.
    HTTP HTTPConfig

    // Clock is injected for tests. Default: time.Now.
    Clock func() time.Time
}

// Stable.
type HTTPConfig struct {
    CaptureRequestBody   bool           // default false
    CaptureResponseBody  bool           // default false
    MaxBodyBytes         int            // default 65536 (64 KiB)
    ContentTypes         []string       // default see §7
    HeaderDenylist       []string       // default see §7; merged with defaults
    HeaderAllowlist      []string       // if set, overrides denylist
    SensitiveQueryParams []string       // default {"token","access_token","api_key","key","signature"}
    RequestIDHeader      string         // default "X-Request-ID"
    GenerateRequestID    bool           // default true
    SkipPaths            []string       // exact-match path skip list
}

// Stable.
type Option interface{ apply(*Config) }

// Stable constructors.
func New(opts ...Option) (*Handler, error)         // general-purpose
func NewPCI(opts ...Option) (*Handler, error)      // PCI preset; merges PCI defaults

// Stable.
func (c *Config) Build() (*Handler, error)         // explicit builder for Config literal users

// Stable functional options (selection; full list in §10).
func WithLogger(l *slog.Logger) Option
func WithRedactPaths(paths ...string) Option
func WithCensor(token string) Option
func WithDetectors(d ...redact.Detector) Option
func WithRequestBody(enabled bool) Option
func WithResponseBody(enabled bool) Option
func WithMaxBodyBytes(n int) Option
func WithContentTypes(ct ...string) Option
func WithHeaderDenylist(h ...string) Option
func WithHeaderAllowlist(h ...string) Option
func WithSensitiveQueryParams(q ...string) Option
func WithRequestIDHeader(name string) Option
func WithSkipPaths(paths ...string) Option
func WithClock(f func() time.Time) Option

// Stable. The slog.Handler wrapper; also exposes HTTP middleware constructors.
type Handler struct{ /* see §4 */ }

// Stable slog.Handler implementation.
func (h *Handler) Enabled(ctx context.Context, lvl slog.Level) bool
func (h *Handler) Handle(ctx context.Context, r slog.Record) error
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler
func (h *Handler) WithGroup(name string) slog.Handler

// Stable. Returns net/http middleware bound to this Handler's config.
func (h *Handler) Middleware() func(http.Handler) http.Handler

// Stable. Logger returns an *slog.Logger backed by this redacting Handler.
func (h *Handler) Logger() *slog.Logger

// Stable. Context-scoped attribute helper (see §9).
func SetAttrs(ctx context.Context, attrs ...slog.Attr) context.Context

// Stable sentinel errors.
var (
    ErrNoLogger    = errors.New("redactlog: Config.Logger is required")
    ErrInvalidPath = errors.New("redactlog: invalid redaction path")
    ErrBadCensor   = errors.New("redactlog: censor must be non-empty")
)
```

### 3.2 Subpackage `redact`

```go
package redact

// Stable.
type Engine struct{ /* opaque */ }

// Stable.
type Options struct {
    Censor    string       // default "***"
    Detectors []Detector   // default nil
}

// Stable.
func New(paths []string, opts Options) (*Engine, error)

// Stable. Redact returns a redacted copy; does not mutate in place.
func (e *Engine) Redact(v any) any

// Stable. RedactValue redacts an slog.Value; primary hot-path entrypoint.
func (e *Engine) RedactValue(v slog.Value) slog.Value

// Stable.
type Redactor interface {
    RedactValue(v slog.Value) slog.Value
}

// Stable. Program is the compiled trie; exposed for debugging / pprof labels.
type Program struct{ /* opaque; String() returns DSL recap */ }
func (e *Engine) Program() *Program

// Stable. Detector runs regex/content checks over string leaves.
type Detector interface {
    // Name identifies the detector in logs (e.g., "pan", "email").
    Name() string
    // Detect returns (replacement, matched). matched==false -> leave value alone.
    Detect(s string) (string, bool)
}

// Stable. Standard detectors ship built-in.
func PANDetector() Detector       // Luhn+BIN, first-6/last-4 mask
func AuthHeaderDetector() Detector // Strips "Bearer <...>" to "Bearer ***"

// Stable. Secret[T] is a LogValuer wrapper that always redacts.
type Secret[T any] struct{ V T }
func (s Secret[T]) LogValue() slog.Value

// Stable. Masked string: shows first-N/last-M, censors middle.
type Masked struct {
    V       string
    First   int
    Last    int
    Censor  string
}
func (m Masked) LogValue() slog.Value
```

### 3.3 Subpackage `httpmw`

```go
package httpmw

// Stable.
type Config struct { /* same shape as redactlog.HTTPConfig plus redactor ref */ }

// Stable.
func Middleware(cfg Config) func(http.Handler) http.Handler

// Experimental. Exposed for advanced users composing their own slog plumbing.
type CapturedRequest struct {
    Method      string
    URL         *url.URL        // query already scrubbed
    Header      http.Header     // denylist already applied
    BodyBytes   []byte          // truncated to MaxBodyBytes; nil if not captured
    BodyTruncated bool
    Size        int64
    RequestID   string
    ReceivedAt  time.Time
}

type CapturedResponse struct {
    Status        int
    Header        http.Header
    BodyBytes     []byte
    BodyTruncated bool
    Size          int64
    WrittenAt     time.Time
    Duration      time.Duration
    Streaming     bool // true if Flush was called before body finalization
}
```

### 3.4 Subpackage `gin`

```go
package gin // import as redactgin to avoid gin-gonic/gin collision

// Stable.
func New(h *redactlog.Handler) gin.HandlerFunc

// Stable. Convenience when you want to build Config inline.
func NewWithConfig(cfg redactlog.Config) (gin.HandlerFunc, error)
```

### 3.5 "Hello world" — both frameworks, under 10 lines

**net/http:**
```go
h, _ := redactlog.NewPCI(redactlog.WithLogger(slog.Default()))
http.ListenAndServe(":8080", h.Middleware()(mux))
```

**Gin:**
```go
h, _ := redactlog.NewPCI(redactlog.WithLogger(slog.Default()))
r := gin.New()
r.Use(redactgin.New(h))
r.Run(":8080")
```

### 3.6 Realistic usage

```go
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

h, err := redactlog.New(
    redactlog.WithLogger(logger),
    redactlog.WithRedactPaths(
        "req.body.password",
        "req.body.ssn",
        "req.body.card.cvv",
        "req.body.user.*.token",
        `req.headers["x-internal-key"]`,
        "res.body.accounts[*].balance",
    ),
    redactlog.WithDetectors(redact.PANDetector()),
    redactlog.WithRequestBody(true),
    redactlog.WithResponseBody(true),
    redactlog.WithMaxBodyBytes(32 * 1024),
    redactlog.WithHeaderAllowlist("content-type", "user-agent", "x-request-id"),
    redactlog.WithSensitiveQueryParams("token", "jwt", "hmac"),
    redactlog.WithSkipPaths("/healthz", "/metrics"),
)
if err != nil { log.Fatal(err) }

http.ListenAndServe(":8080", h.Middleware()(mux))
```

---

## 4. Core types and interfaces

### 4.1 `Handler` — the slog.Handler wrapper

```go
type Handler struct {
    inner     slog.Handler     // user's handler, e.g. slog.NewJSONHandler
    redactor  *redact.Engine   // compiled once, shared across all clones
    groups    []string         // accumulated from WithGroup
    attrs     []slog.Attr      // accumulated from WithAttrs (pre-redacted at call time)
    http      HTTPConfig       // shared via pointer-free copy on clone
    clock     func() time.Time
    ctxKey    ctxAttrsKey      // for SetAttrs extraction
}

// Enabled delegates to inner (redaction is orthogonal to level filtering).
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
    return h.inner.Enabled(ctx, l)
}

// Handle is the redaction entrypoint. It:
//   1. Pulls context-scoped attrs (SetAttrs callers).
//   2. Rebuilds a slog.Record with redacted attrs; record.Message is redacted too.
//   3. Delegates to inner.Handle.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error

// WithAttrs returns a new Handler with attrs pre-redacted and appended.
// MUST NOT mutate receiver (per slog.Handler contract).
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler

// WithGroup appends a group; group path is used as the root path prefix
// when matching DSL paths against attrs.
func (h *Handler) WithGroup(name string) slog.Handler
```

All four methods are **required** by `slog.Handler`. Skipping `WithGroup` breaks `slog.Group(...)` semantics; skipping `WithAttrs` causes every `logger.With(...)` call to drop redaction context. The official Go team handler guide (`github.com/golang/example/slog-handler-guide`) is explicit that wrappers must return new handlers, not mutate.

### 4.2 `Redactor` and the compiled `Program`

```go
type Redactor interface {
    RedactValue(v slog.Value) slog.Value
}

// Program is the compiled output of DSL parsing + trie building.
type Program struct {
    root      *trieNode
    hasWild   bool
    depthMax  int
    detectors []Detector
    censor    string
}

type trieNode struct {
    children   map[string]*trieNode // exact segment match
    wildChild  *trieNode            // segment == "*" (single-segment wildcard)
    leaf       bool                 // match terminates here -> redact
    arrayWild  bool                 // this segment was "[*]" syntax
}
```

### 4.3 Body capture types

See §3.3 `CapturedRequest` / `CapturedResponse`. Both are value types; they never escape middleware goroutines and are converted into `slog.Attr` before `Handle` is called.

### 4.4 Response writer wrapper

`httpmw/responsewriter.go` does **not** define a wrapper type. Per ADR-003, it uses `httpsnoop.Wrap` with a `httpsnoop.Hooks` value. The seven interfaces `httpsnoop` preserves (pkg.go.dev/github.com/felixge/httpsnoop) are:

1. `http.ResponseWriter` (always)
2. `http.Flusher`
3. `http.CloseNotifier`
4. `http.Hijacker`
5. `io.ReaderFrom`
6. `http.Pusher`
7. `interface{ SetReadDeadline(time.Time) error; SetWriteDeadline(time.Time) error }` (the `deadliner` interface, Go 1.8+)

Plus the internal `fullDuplexEnabler` added in Go 1.21 for H2/H3 full-duplex. All 128 combinations are exhaustively tested upstream (`wrap_generated_gteq_1.8_test.go`).

### 4.5 `Config` — every field documented

| Field | Type | Default | Purpose |
|---|---|---|---|
| `Logger` | `*slog.Logger` | **required** | Downstream logger whose `Handler` we wrap. Build returns `ErrNoLogger` if nil. |
| `RedactPaths` | `[]string` | `nil` | Pino-style DSL paths; compiled once at Build. |
| `Censor` | `string` | `"***"` | Replacement token. Empty string rejected. |
| `Detectors` | `[]redact.Detector` | `nil` | Post-path content detectors. PCI preset adds `PANDetector()`. |
| `HTTP.CaptureRequestBody` | `bool` | `false` | Opt-in. See ADR-007. |
| `HTTP.CaptureResponseBody` | `bool` | `false` | Opt-in. |
| `HTTP.MaxBodyBytes` | `int` | `65536` | 64 KiB per samber/slog-gin convention. Rejects if <0. |
| `HTTP.ContentTypes` | `[]string` | see §7 | JSON/form/text only. Skip on `multipart/*`. |
| `HTTP.HeaderDenylist` | `[]string` | see §7 | Merged with built-in defaults unless `HeaderAllowlist` set. |
| `HTTP.HeaderAllowlist` | `[]string` | `nil` | If non-nil, only listed headers are logged. |
| `HTTP.SensitiveQueryParams` | `[]string` | see §7 | Replaced with censor in `url.query`. |
| `HTTP.RequestIDHeader` | `string` | `"X-Request-ID"` | Checked inbound; echoed outbound. |
| `HTTP.GenerateRequestID` | `bool` | `true` | UUIDv4 if no header present. |
| `HTTP.SkipPaths` | `[]string` | `nil` | Exact-match; regex deferred to v2. |
| `Clock` | `func() time.Time` | `time.Now` | Test injection. |

### 4.6 `Option` with unexported method

```go
type Option interface {
    apply(*Config)
}

// Internal implementation — unexported method prevents external types
// from satisfying the interface (zap idiom).
type optionFunc func(*Config)
func (f optionFunc) apply(c *Config) { f(c) }

func WithCensor(s string) Option {
    return optionFunc(func(c *Config) { c.Censor = s })
}
```

This is the **zap Option pattern**: unexported method + unexported concrete type means the option surface is closed (no third-party `Option` implementations), so we can evolve internals without breaking semver.

---

## 5. Data flow diagrams

### 5.1 Request lifecycle

```
                ┌──────────────────────┐
   HTTP client  │  *http.Request       │
   ───────────► │  r.Body (io.Reader)  │
                └──────────┬───────────┘
                           │
              ┌────────────▼────────────────┐
              │ httpmw.Middleware           │
              │ 1. skip? -> next            │
              │ 2. extract/gen X-Request-ID │
              │ 3. scrub r.URL.RawQuery     │
              │ 4. if capture: tee Body     │
              │    into pooled buffer       │
              │    (LimitReader MaxBytes)   │
              │ 5. httpsnoop.Wrap(w, hooks) │
              │    hooks.Write -> mirror    │
              │    hooks.Flush -> streaming │
              │ 6. ctx = SetAttrs(..request_id)
              └────────────┬────────────────┘
                           │
                ┌──────────▼───────────┐
                │ user's http.Handler  │ (business logic; may emit own logs)
                └──────────┬───────────┘
                           │
              ┌────────────▼────────────────┐
              │ deferred: build CapturedReq │
              │ / CapturedResp as []slog.Attr│
              │ with semconv field names    │
              └────────────┬────────────────┘
                           │
              ┌────────────▼────────────────┐
              │ handler.Logger().LogAttrs() │
              │ ─► redactlog.Handler.Handle │
              │    walks record, redacts,   │
              │    delegates to inner       │
              └────────────┬────────────────┘
                           │
                ┌──────────▼──────────┐
                │ user's slog.Handler │ (JSON/Text/whatever)
                └──────────┬──────────┘
                           │
                     log pipeline
```

### 5.2 Redaction pipeline

```
  input slog.Value
       │
       ▼
  ┌──────────────┐   KindGroup / KindAny (map/slice) ─► recurse
  │ walk(value,  │
  │   node,      │   KindString ────────────► detectors -> maybe censor
  │   depth)     │
  └──────┬───────┘   KindInt/Float/Bool ────► pass through (type-safe)
         │
         ▼
  if node.leaf || matched detector
         │
         ▼
     emit slog.StringValue(censor)

  wildcard rule:
    at each level, lookup children[key]; if absent, try wildChild
    array [*] matches every element regardless of index
```

### 5.3 slog.Record through redactlog to user handler

```
caller                       redactlog.Handler         user's slog.Handler
  │                                │                          │
  │ logger.Info("msg",             │                          │
  │   slog.Group("req",            │                          │
  │     slog.String("auth", ...))) │                          │
  ├───────────────────────────────►│                          │
  │                                │ Handle(ctx, rec):        │
  │                                │   1. ctxAttrs := Get(ctx)│
  │                                │   2. new := rec.Clone()  │
  │                                │   3. new.AddAttrs(ctx..) │
  │                                │   4. walk attrs via      │
  │                                │      redactor.Program    │
  │                                │   5. for each group path │
  │                                │      prepend h.groups    │
  │                                │   6. replace attrs       │
  │                                ├─────────────────────────►│
  │                                │                          │ writes JSON
  │                                │◄─────────────────────────┤
  │◄───────────────────────────────┤
```

---

## 6. Redaction engine design

### 6.1 DSL syntax

`redactlog` implements a **strict subset of Pino's `fast-redact` path syntax** — the parts that are unambiguous in Go and compose with `slog.Group` hierarchies.

Legal constructs:

| Form | Meaning | Example |
|---|---|---|
| `a.b.c` | Dotted path | `req.body.password` |
| `a["b-c"]` | Bracket notation for non-identifier keys | `req.headers["x-api-key"]` |
| `a.*` | Terminal wildcard: every child of `a` | `req.body.secrets.*` |
| `a.*.x` | Intermediate wildcard: single segment | `users.*.password` |
| `a[*]` | Array wildcard: every element | `res.body.accounts[*]` |
| `a[*].x` | Array element field | `res.body.cards[*].cvv` |
| `*.x` | Top-level-intermediate wildcard | `*.taxId` |

Explicitly **illegal** in v1 (rejected at Build with `ErrInvalidPath`):

- Recursive descent (`**`) — rejected; too easy to over-redact.
- Numeric array indices (`a[0]`) — rejected; rarely useful in log records, ambiguous under slog groups.
- Negated paths (`!a.b`) — rejected.
- Glob character classes (`a.[pP]assword`) — rejected.

Ten example strings with semantics:

1. `req.body.password` — exact leaf.
2. `req.headers.authorization` — exact leaf (note: header denylist handles this too; DSL is for body).
3. `req.headers["x-api-key"]` — bracket form for hyphenated key.
4. `req.body.user.*` — redact every property of `user`.
5. `req.body.items[*].secret` — redact `secret` on each array element.
6. `res.body.accounts[*]` — redact every account entirely.
7. `*.ssn` — redact `ssn` under any top-level group.
8. `req.body.*.token` — redact `token` on any direct child of `req.body`.
9. `req.body.nested.*.credential` — scoped intermediate wildcard.
10. `req.body.config.keys[*]` — every element of a keys array.

### 6.2 Compilation strategy

At `New()` time, each path is lexed (tokens: DOT, LBRACK, RBRACK, STAR, IDENT, QSTRING) and inserted into a **trie** keyed by segment. Wildcards occupy a dedicated `wildChild` slot per node. Build failure returns `ErrInvalidPath` wrapping the offending path with column info.

```go
// Pseudocode
func New(paths []string, opts Options) (*Engine, error) {
    root := &trieNode{children: map[string]*trieNode{}}
    for _, p := range paths {
        segs, err := lex(p)
        if err != nil { return nil, fmt.Errorf("%w: %q: %v", ErrInvalidPath, p, err) }
        insert(root, segs)
    }
    return &Engine{prog: &Program{root: root, censor: opts.Censor, detectors: opts.Detectors}}, nil
}
```

The trie is **immutable** post-build. All `Redact` calls share it without locking.

### 6.3 Runtime walk

```go
func (e *Engine) walkAttr(a slog.Attr, node *trieNode, depth int) slog.Attr {
    child, _ := node.children[a.Key]
    wild := node.wildChild

    switch {
    case child != nil && child.leaf:
        return slog.String(a.Key, e.prog.censor)
    case wild != nil && wild.leaf:
        return slog.String(a.Key, e.prog.censor)
    case a.Value.Kind() == slog.KindGroup:
        next := child
        if next == nil { next = wild }
        if next == nil && !hasDetectors(e) { return a } // no descent needed
        return slog.Group(a.Key, walkGroup(a.Value.Group(), next, depth+1)...)
    case a.Value.Kind() == slog.KindString:
        // Detectors apply after path check; path had no hit here.
        return applyDetectors(a, e.prog.detectors)
    default:
        return a
    }
}
```

Type handling:

- **String** — candidate for detectors (PAN, auth tokens).
- **Int/Int64/Uint64/Float64/Bool/Duration/Time** — pass-through; detectors do not run on non-string leaves (a credit-card number as an int is still logged — users should type it as string or wrap in `Masked`).
- **Array/Slice (`KindGroup` with numeric indices OR `KindAny` holding a slice)** — iterate; if `node.arrayWild` or `wild` matches, redact each.
- **Nested groups** — recurse.
- **Null / `KindAny` with `nil`** — pass-through; redacting nil wastes cycles.

### 6.4 Wildcard semantics

- A single `*` matches **exactly one segment** (never zero, never many). `a.*.b` matches `a.x.b` but not `a.b` nor `a.x.y.b`.
- `[*]` matches every array index. Under `slog`, arrays are typically rendered via `slog.Any([]T)`; the engine type-asserts to `[]any` / `[]slog.Value` and iterates.
- **Leaf-position wildcards** redact **all children** of the parent. `a.*` under `{a: {x:1, y:2}}` yields `{a: {x:"***", y:"***"}}`.

### 6.5 LogValuer integration

`slog.LogValuer` is `interface{ LogValue() slog.Value }`. The walk **resolves `LogValuer` before matching paths** so user-defined redactors compose:

```go
type APIKey string
func (k APIKey) LogValue() slog.Value { return slog.StringValue("***") }
```

Used via `slog.Any("api_key", APIKey(raw))`. The engine calls `v.Resolve()` (recursive, cycle-safe per stdlib) before the trie walk. Two built-in helpers ship:

- `redact.Secret[T]` — generic always-redact wrapper.
- `redact.Masked` — first/last visible characters.

### 6.6 Default censor

**`"***"`** (three asterisks), chosen over `"[REDACTED]"`. Justification:

- Shorter → smaller log volume at scale (fintech/healthtech services emit billions of events).
- Visually obvious in text logs and JSON.
- Matches Pino's convention (`fast-redact`'s default is `[REDACTED]`, but Pino docs show many deployments using `"***"` or `"**GDPR COMPLIANT**"`; we bias to terseness).
- Configurable via `WithCensor`; users who prefer `"[REDACTED]"` set it in one line.

See ADR-008 for why a single token is chosen over type-specific tokens.

### 6.7 Regex-based detection

The `Detector` interface runs **after** path matching on `KindString` leaves that survived path redaction. `PANDetector()`:

```go
// Regex: 13–19 consecutive digits, optionally separated by spaces or dashes.
var panRegex = regexp.MustCompile(`(?:\d[ -]?){12,18}\d`)

func (panDetector) Detect(s string) (string, bool) {
    return panRegex.ReplaceAllStringFunc(s, func(match string) string {
        digits := stripNonDigits(match)
        if !luhn.Valid(digits) { return match } // not a real PAN
        if len(digits) < 13 || len(digits) > 19 { return match }
        return digits[:6] + strings.Repeat("*", len(digits)-10) + digits[len(digits)-4:]
    }), true
}
```

**Luhn validation before redaction** prevents false positives on order numbers, phone strings with dashes, and UUIDs-as-digits. Per PCI DSS 4.0 Requirement 3.4.1, displayable PANs are limited to **first 6 and last 4** (BIN + last four); everything between is masked.

### 6.8 Performance target

Target on an M-class laptop CPU, Go 1.22, `-race` off:

| Workload | Budget | Rationale |
|---|---|---|
| No-match walk (1 group, 5 string attrs) | **< 150 ns/op, 0 allocs** | Dominates no-redaction-configured case; must be close to zero-cost. |
| Single leaf match | **< 400 ns/op, ≤ 1 alloc** | One string rewrite. |
| Nested (3 deep, 1 match) | **< 900 ns/op, ≤ 2 allocs** | Recursion cost plus one rewrite. |
| PAN detector on 64 KiB JSON body | **< 250 µs, amortized** | Regex is the bottleneck; body scanning is acceptable because it's opt-in. |

Baseline to beat: `samber/slog-gin` with `WithRequestBody=true` + manual post-hoc regex (our prior research clocked this at ~3× slower due to double-pass). Zero-alloc target for no-match is achievable because `slog.Value` is a value type (16 bytes) and the trie lookup is a map access.

---

## 7. HTTP middleware design

### 7.1 Request body capture

```go
// Pattern (mirrors samber/slog-gin's newBodyReader, but pooled):
if cfg.CaptureRequestBody && contentTypeAllowed(r.Header.Get("Content-Type")) {
    buf := pool.Get()
    limited := &io.LimitedReader{R: r.Body, N: int64(cfg.MaxBodyBytes) + 1}
    r.Body = &teeCloser{
        tee:   io.TeeReader(limited, buf),
        close: r.Body.Close,
    }
    // Deferred: reader := &CapturedRequest{...; BodyTruncated: buf.Len() > MaxBodyBytes}
}
```

`sync.Pool[*bytes.Buffer]` with a **cap guard**: buffers larger than 128 KiB are dropped on `Put` to prevent memory hoarding under attack (bomb-sized bodies). The `+ 1` on LimitedReader is how we detect truncation: if we read one extra byte beyond the limit, we know more was available.

### 7.2 Response body capture via `httpsnoop`

```go
func wrapWriter(w http.ResponseWriter, buf *bytes.Buffer, max int) http.ResponseWriter {
    return httpsnoop.Wrap(w, httpsnoop.Hooks{
        Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
            return func(b []byte) (int, error) {
                if buf.Len() < max {
                    room := max - buf.Len()
                    if len(b) < room { buf.Write(b) } else { buf.Write(b[:room]) }
                }
                return next(b)
            }
        },
        WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
            return func(code int) { /* capture status */ ; next(code) }
        },
        Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
            return func() { markStreaming(); next() }
        },
    })
}
```

The seven interfaces preserved (see §4.4) matter because production services rely on `Hijacker` for WebSockets and `Flusher` for SSE; rolling our own wrapper would silently break them. Upstream `httpsnoop` has ~500 ns overhead (per its README benchmark), negligible compared to body-scanning cost.

### 7.3 Content-type allowlist

Default allowlist (bodies are captured **only** for these):

```
application/json
application/x-www-form-urlencoded
application/xml, text/xml
text/plain
text/html          (opt-in; off by default in HTTPConfig.ContentTypes)
application/vnd.api+json
application/problem+json
```

Everything else (`multipart/*`, `application/octet-stream`, `image/*`, `video/*`, `application/grpc`, `application/pdf`) is **metadata-only**: size and content-type are logged; body is not.

### 7.4 Streaming detection

If `Flush()` is called **before** the middleware's deferred block runs, the response is flagged `Streaming=true`, `BodyBytes` is truncated to what was buffered up to that point, and `BodyTruncated=true`. SSE (`text/event-stream`) is detected at `WriteHeader` time via `Content-Type` inspection and short-circuits body capture entirely (no buffer allocation).

### 7.5 Body size limit

**64 KiB default** — matches `samber/slog-gin`'s `RequestBodyMaxSize` / `ResponseBodyMaxSize` exactly (64 * 1024). Configurable via `WithMaxBodyBytes`. Minimum 1 KiB; zero rejected at Build.

### 7.6 First-N truncation (not ring buffer)

**Decision: simple head truncation for v1.** Ring-buffered first-N + last-M would give better error debuggability (you see error trailers) but doubles capture memory per request and adds a nontrivial implementation. Deferred to v2. See ADR-006.

### 7.7 Multipart handling

For `multipart/form-data` and `multipart/mixed`: bodies are **never captured**. A single metadata attr is emitted:

```go
slog.Group("http.request.body",
    slog.String("multipart.boundary", boundary),
    slog.Int("content_length", int(r.ContentLength)),
    slog.Bool("captured", false),
)
```

File uploads are out of scope for structured logging, period.

### 7.8 Header denylist

Default denylist (lowercased, canonicalized at match time via `textproto.CanonicalMIMEHeaderKey`):

```
authorization              — bearer tokens, basic auth
cookie                     — session IDs
set-cookie                 — server-issued sessions
proxy-authorization        — proxy creds
x-api-key                  — common API auth
x-auth-token               — Zendesk/Atlassian-style
x-csrf-token               — CSRF tokens (leak is a CSRF issue)
x-xsrf-token               — angular variant
x-session-id               — session linkage
x-forwarded-authorization  — proxy passthrough
```

Derived from the union of samber/slog-gin's `HiddenRequestHeaders` (`authorization`, `cookie`, `set-cookie`, `x-auth-token`, `x-csrf-token`, `x-xsrf-token`) and OWASP logging cheat-sheet additions. `HeaderAllowlist` overrides the denylist when set — we log **only** allowlisted headers, which is the safer posture for regulated envs.

### 7.9 Sensitive query params

Default: `token`, `access_token`, `api_key`, `key`, `signature`, `jwt`, `code`. Replaced with censor in `url.query` attribute. Implementation scans `r.URL.Query()`, substitutes, re-encodes. Raw `url.full` is never emitted (only `url.path` and the scrubbed `url.query`).

### 7.10 Request ID

Check `cfg.RequestIDHeader` (default `X-Request-ID`). If present, propagate unchanged. Otherwise generate a UUIDv4 (Go's `crypto/rand`; we accept the one non-stdlib dep alternative of `google/uuid` ONLY if a reviewer insists, otherwise inline a 20-line UUID generator in `internal/`). The ID is:

1. Set on the response header (`w.Header().Set(...)`).
2. Attached to `r.Context()` via `SetAttrs(ctx, slog.String("request_id", id))`.
3. Emitted as top-level attr on the request-completion log line.

---

## 8. Gin adapter design

**File:** `gin/middleware.go`. **Package name:** `gin` (imported as `redactgin` at usage sites to avoid colliding with `gin-gonic/gin`).

```go
package gin

import (
    "github.com/gin-gonic/gin"
    "github.com/JAS0N-SMITH/redactlog"
)

func New(h *redactlog.Handler) gin.HandlerFunc {
    wrapped := h.Middleware() // returns func(http.Handler) http.Handler
    return func(c *gin.Context) {
        // Bridge: present gin's flow as an http.Handler invocation.
        next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Reinject modified request (body tee) into gin.
            c.Request = r
            c.Next()
        })
        wrapped(next).ServeHTTP(c.Writer, c.Request)
    }
}
```

The Gin middleware **wraps the `net/http` implementation**, never duplicates it. All body capture, header scrubbing, and httpsnoop wrapping happen in `httpmw`. This means Gin users get identical behavior to `net/http` users by construction.

**`gin.BodyBytesKey` integration.** When `c.Request.Body` is consumed downstream via `c.ShouldBindJSON` etc., Gin's `binding.Default` already handles re-reading. However, if a user has prior middleware that caches to `gin.BodyBytesKey`, we check that cache first before tee-reading, avoiding double-buffering:

```go
if cached, ok := c.Get(gin.BodyBytesKey); ok {
    // Prior middleware already cached; reuse and skip our tee.
    use(cached.([]byte))
}
```

**`c.Copy()` guidance.** Users who spawn goroutines **must** pass `c.Copy()` (gin's documented pattern). Our middleware does not spawn goroutines, but if the user does, our context-scoped attrs (`SetAttrs`) ride along on `c.Copy().Request.Context()` correctly.

**Panic recovery ordering.** Documented guidance: register `gin.Recovery()` **after** `redactgin.New(h)` so the logger sees the panic as a 500 response (recovery catches before response completes). If recovery is first, we log a 200 because we never see the panic. This ordering rule goes in the package godoc.

---

## 9. slog integration

### 9.1 Why a dedicated handler wrapper (not ReplaceAttr)

We implement a full `slog.Handler`. **ReplaceAttr is insufficient** because:

1. It only sees **top-level attrs one at a time**, after groups are flattened textually — path context is ambiguous.
2. It cannot introspect `slog.KindGroup` cleanly without re-parsing.
3. It runs inside the terminal handler (JSONHandler/TextHandler), so users who bring their own handler must manually plumb it in.
4. Per the official Go team slog-handler-guide, wrapper handlers are the sanctioned pattern for cross-cutting transformations.

See ADR-001.

### 9.2 All four methods

```go
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
    return h.inner.Enabled(ctx, l)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
    // 1. Extract context-scoped attrs.
    ctxAttrs := attrsFromCtx(ctx, h.ctxKey)

    // 2. Build a new Record so we don't mutate the caller's.
    out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
    // Replay accumulated WithAttrs (pre-redacted at WithAttrs time, so cheap).
    for _, a := range h.attrs { out.AddAttrs(a) }
    // Redact context attrs.
    for _, a := range ctxAttrs { out.AddAttrs(h.redactor.walkAttr(a, root)) }
    // Redact record attrs under group path.
    r.Attrs(func(a slog.Attr) bool {
        out.AddAttrs(h.redactor.walkAttrUnderGroups(a, h.groups))
        return true
    })
    return h.inner.Handle(ctx, out)
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
    clone := *h
    redacted := make([]slog.Attr, len(as))
    for i, a := range as { redacted[i] = h.redactor.walkAttr(a, h.rootForGroups()) }
    clone.attrs = append(append([]slog.Attr(nil), h.attrs...), redacted...)
    clone.inner = h.inner.WithAttrs(redacted) // propagate for handler-native optimization
    return &clone
}

func (h *Handler) WithGroup(name string) slog.Handler {
    if name == "" { return h }
    clone := *h
    clone.groups = append(append([]string(nil), h.groups...), name)
    clone.inner = h.inner.WithGroup(name)
    return &clone
}
```

Three correctness requirements enforced:

- **Goroutine safety on `Handle`.** No shared mutable state during Handle — the trie is immutable, `h.attrs`/`h.groups` are copy-on-write at WithAttrs/WithGroup time.
- **Immutability of record attrs.** We build a new Record via `slog.NewRecord(...)` rather than mutating `r` (the stdlib docs say callers may reuse Records).
- **Group paths prefix DSL matching.** `WithGroup("req")` means a subsequent `slog.String("body.password", ...)` matches DSL path `req.body.password`. Implementation: `walkAttrUnderGroups` descends the trie through `h.groups` first, then matches attr keys.

### 9.3 Context propagation

```go
type ctxAttrsKey struct{}

func SetAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
    existing, _ := ctx.Value(ctxAttrsKey{}).([]slog.Attr)
    merged := append(append([]slog.Attr(nil), existing...), attrs...)
    return context.WithValue(ctx, ctxAttrsKey{}, merged)
}

func attrsFromCtx(ctx context.Context, _ ctxAttrsKey) []slog.Attr {
    v, _ := ctx.Value(ctxAttrsKey{}).([]slog.Attr)
    return v
}
```

The **extractor-handler pattern**: attrs are stored in the request context by middleware and pulled by `Handle` at emit time. This replaces `veqryn/slog-context` — we implement the 20-line pattern inline, avoiding a dependency. See ADR-005.

**Usage:**
```go
ctx := redactlog.SetAttrs(r.Context(), slog.String("user_id", uid))
logger.InfoContext(ctx, "processed payment") // user_id appears, redacted if DSL matches
```

### 9.4 Group semantics

- `logger.WithGroup("req").Info("x", slog.String("password", ...))` → attr key internally `req.password`, matches DSL `req.password`.
- Nested groups compose: `WithGroup("req").WithGroup("body")` → prefix `req.body.*`.
- The inner handler is notified via `inner.WithGroup(name)` so JSONHandler still nests correctly.

---

## 10. Configuration model

### 10.1 Config struct

Defined in §3.1; fields documented in §4.5.

### 10.2 Functional options (complete list)

| Option | Default | Notes |
|---|---|---|
| `WithLogger(l)` | **required** | Must be set. |
| `WithRedactPaths(p...)` | `nil` | Appended, not replaced. |
| `WithCensor(s)` | `"***"` | Non-empty enforced. |
| `WithDetectors(d...)` | `nil` | Appended. |
| `WithRequestBody(b)` | `false` | |
| `WithResponseBody(b)` | `false` | |
| `WithMaxBodyBytes(n)` | `65536` | Min 1024, max 1 MiB. |
| `WithContentTypes(ct...)` | see §7.3 | Replaces default list. |
| `WithHeaderDenylist(h...)` | see §7.8 | Appended to defaults. |
| `WithHeaderAllowlist(h...)` | `nil` | If set, overrides denylist. |
| `WithSensitiveQueryParams(q...)` | see §7.9 | Appended. |
| `WithRequestIDHeader(name)` | `"X-Request-ID"` | |
| `WithGenerateRequestID(b)` | `true` | |
| `WithSkipPaths(p...)` | `nil` | Exact match only. |
| `WithClock(f)` | `time.Now` | Test only. |

### 10.3 Preset constructors

```go
func New(opts ...Option) (*Handler, error)      // plain
func NewPCI(opts ...Option) (*Handler, error)   // preset: PAN detector + PCI paths + strict denylist

// Equivalent to:
func NewPCI(opts ...Option) (*Handler, error) {
    defaults := []Option{
        WithDetectors(redact.PANDetector()),
        WithRedactPaths(
            "*.cvv", "*.cvv2", "*.cvc", "*.pin",
            "*.card.number", "*.card.cvv",
            "*.payment.card.*",
        ),
        WithHeaderDenylist("authorization", "cookie", "set-cookie"),
    }
    // User opts override/extend defaults; user-provided WithLogger required.
    return New(append(defaults, opts...)...)
}
```

### 10.4 Environment variable overrides

**Decision: no env var support in v1.** Argument against: env-var config is a common anti-pattern for security-sensitive libraries (it shifts the config surface outside version control and makes compliance review harder). Compliance teams want the redaction path list to live in Go source, reviewable at PR time. Users who need runtime tuning wire their own env parsing into `Config`.

### 10.5 Validation

`Config.Build()` returns errors for:

- `ErrNoLogger` — `Logger == nil`.
- `ErrBadCensor` — empty string.
- `ErrInvalidPath` — any DSL path fails to parse; error message includes path and column.
- `fmt.Errorf("MaxBodyBytes=%d out of range [1024, 1048576]")` — bounds check.
- `fmt.Errorf("unknown content-type %q")` — (warning only in v1; doesn't fail build).

All errors wrap sentinels for `errors.Is` compatibility.

---

## 11. OTel semantic conventions mapping

**Pinned version: `go.opentelemetry.io/otel/semconv/v1.26.0`.** The HTTP conventions stabilized at v1.23 and v1.26 is the current LTS-like target as of April 2026. The `semconv.go` file imports constants from this single version so upgrades are one-line changes.

### 11.1 Field names (stable HTTP conventions)

| Attribute | Value | Emission | Go constant |
|---|---|---|---|
| `http.request.method` | `GET`, `POST`, ... | always | `semconv.HTTPRequestMethodKey` |
| `http.request.method_original` | raw method if non-standard | conditional | `semconv.HTTPRequestMethodOriginalKey` |
| `http.response.status_code` | `200`, `500`, ... | always (when response sent) | `semconv.HTTPResponseStatusCodeKey` |
| `http.route` | `/users/:id` | always if available | `semconv.HTTPRouteKey` |
| `http.request.body.size` | bytes | always | `semconv.HTTPRequestBodySizeKey` |
| `http.response.body.size` | bytes | always | `semconv.HTTPResponseBodySizeKey` |
| `url.path` | `/api/v1/users/42` | always | `semconv.URLPathKey` |
| `url.query` | scrubbed query | always if present | `semconv.URLQueryKey` |
| `url.scheme` | `https` | always | `semconv.URLSchemeKey` |
| `url.full` | **not emitted** (credential-leak risk) | never | — |
| `server.address` | host | always | `semconv.ServerAddressKey` |
| `server.port` | int | opt-in | `semconv.ServerPortKey` |
| `client.address` | remote IP | always | `semconv.ClientAddressKey` |
| `client.port` | int | opt-in | `semconv.ClientPortKey` |
| `user_agent.original` | full UA | always | `semconv.UserAgentOriginalKey` |
| `network.protocol.version` | `1.1`, `2`, `3` | always | `semconv.NetworkProtocolVersionKey` |
| `error.type` | error class | conditional (5xx or panic) | `semconv.ErrorTypeKey` |

Body attrs (extension, not in semconv): `http.request.body.content` (string, captured+redacted), `http.response.body.content`, `http.request.body.truncated` (bool). These use an `http.*` namespace intentionally so downstream tools treat them as HTTP-scoped.

### 11.2 Status-code to span-status mapping

Even though v1 emits no spans, the `Handler` sets log-record `error.type` per the server-side rule from the HTTP semconv spec:

- **5xx** → `error.type = "http.<code>"` and log level promoted to `ERROR`.
- **4xx** → no `error.type`, level stays at configured `ClientErrorLevel` (default `WARN`).
- **1xx/2xx/3xx** → no error, level `INFO`.

This mirrors OTel's server-side `ERROR`/`UNSET` rule: 4xx on server side does not imply an application error (bad client input is normal).

### 11.3 Version pinning strategy

- Pin exactly one `semconv` version (`v1.26.0`) in `semconv.go`.
- Export our own constants that wrap semconv constants, so a semconv upgrade is a one-file diff:
  ```go
  // semconv.go
  const (
      AttrHTTPRequestMethod = string(semconv.HTTPRequestMethodKey)
      AttrHTTPRoute         = string(semconv.HTTPRouteKey)
      // ...
  )
  ```
- Document the pinned version in README and godoc.
- When semconv bumps to v1.30+, release `redactlog` minor bump with the change noted.

---

## 12. Error handling strategy

### 12.1 Redaction failure — fail closed (redact more)

If the walk encounters a pathological value (cyclic `LogValuer`, malformed nested group), the attr is **replaced with `slog.String(key, censor)`** rather than passed through. The invariant: **it is never correct to emit unredacted data on an error path.**

```go
defer func() {
    if rec := recover(); rec != nil {
        out = slog.String(a.Key, e.prog.censor) // safe default
        // log internal telemetry via inner handler under a reserved key
    }
}()
```

### 12.2 Body capture failure — log the failure, don't block

If body tee-reading errors (network reset, Body.Close() panics), the request proceeds normally. The log line gets `slog.String("http.request.body.capture_error", err.Error())` and body content is omitted. We **never** call `next.ServeHTTP` inside a branch that could abort on capture error.

### 12.3 Inner `slog.Handler` errors

`Handler.Handle` returns the error from `inner.Handle` unchanged. This propagates to `slog.Logger` which discards it (per stdlib behavior). We log nothing extra — slog is best-effort by design, and duplicating the error would create infinite loops.

### 12.4 `Config.Build()` rejects

See §10.5. All validation happens at Build time, not request time. The middleware itself cannot fail to initialize; once built, it is panic-free on the request path.

### 12.5 Panic safety

The middleware wraps each request in a `recover()`:

```go
defer func() {
    if rec := recover(); rec != nil {
        // Log panic attrs; rethrow so user's recovery middleware sees it.
        logPanic(ctx, rec)
        panic(rec)
    }
}()
```

We **rethrow** — swallowing panics would hide production bugs and interfere with framework recovery (gin's `gin.Recovery()`, net/http's default ServeHTTP recovery). Our only responsibility is to emit the log line first.

---

## 13. Testing strategy

### 13.1 Package structure

```
redactlog_test.go          — unit tests for root package
handler_test.go            — Handler slog-conformance + redaction
redact/redactor_test.go    — DSL parse, compile, walk
redact/detect_test.go      — PAN/Luhn correctness
httpmw/middleware_test.go  — end-to-end net/http with httptest
httpmw/capture_test.go     — body limit, truncation, content-type gating
gin/middleware_test.go     — gin.Engine-based integration
fuzz/redact_fuzz_test.go   — Go 1.22 native fuzzing
bench/comparative_test.go  — samber/slog-gin baseline
testdata/golden/*.json     — frozen expected outputs
```

### 13.2 slogtest conformance

Mandatory. `testing/slogtest.TestHandler(h, fn)` enforces:

- `WithAttrs` returns independent handler.
- `WithGroup` prefixes correctly.
- Zero-time records (`r.Time.IsZero()`) are emitted without time attr.
- Empty group names are inlined.
- Attrs appearing more than once are all logged.
- `Record.NumAttrs()` and iteration consistency.
- `Handle` processes attrs in order.

A single test wires our `Handler` with an in-memory `slog.JSONHandler` and runs `slogtest.TestHandler` over it; any failure breaks CI.

### 13.3 Redaction invariants — property tests

```go
func TestInvariant_SecretNeverLeaks(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        secret := rapid.StringMatching(`[a-zA-Z0-9]{20,}`).Draw(t, "secret")
        attrs := randomAttrsContaining(t, secret, "password")
        // Given DSL "*.password", any emission must not contain secret.
        out := emit(engine("*.password"), attrs)
        if strings.Contains(out, secret) {
            t.Fatalf("LEAK: %s in %s", secret, out)
        }
    })
}
```

Similar invariants: PAN never appears in output if it Luhn-validates; `Authorization` header never appears when denylisted; `Cookie` values never appear as substrings of emitted JSON.

### 13.4 Golden-file tests

For each of ~15 representative scenarios (plain GET, POST JSON with PII, multipart upload, SSE response, gzip response, redirect, 500 panic), a golden JSON file under `testdata/golden/` is diffed against the actual emission. Goldens are regenerated via `go test -update`.

### 13.5 Benchmark targets

```go
BenchmarkNoRedaction_slogging_gin    // baseline: samber/slog-gin on same route
BenchmarkNoRedaction_redactlog       // our no-match path
BenchmarkWithRedaction_redactlog     // realistic: 5 paths, 1 detector
BenchmarkBodyCapture_64KB            // full body path
```

**Pass criteria:** no-redaction path within **20% of samber/slog-gin**; with-redaction path within **2× of samber/slog-gin** (given we're doing real work samber doesn't).

### 13.6 Fuzz corpus seeds

Seed files in `testdata/fuzz/FuzzRedactor/`:
- `seed_basic_pan`: `{"card":"4111111111111111"}`
- `seed_nested_deep`: 20-level deep JSON with secrets at each level
- `seed_wildcard_array`: `{"users":[{"pw":"x"},{"pw":"y"}]}`
- `seed_hyphen_keys`: `{"x-api-key":"v"}`
- `seed_unicode_keys`: non-ASCII attribute names
- `seed_cycle_logvaluer`: a `LogValuer` that returns itself
- `seed_huge_string`: 1 MiB string leaf

Fuzz targets: `FuzzDSLParse`, `FuzzRedactor`, `FuzzPANDetect`.

---

## 14. Key architectural decisions (ADRs)

### ADR-001: slog.Handler wrapper vs ReplaceAttr-only
**Decision.** Implement a full `slog.Handler` wrapper.
**Alternatives.** (a) Provide a `ReplaceAttr func` the user plugs into their JSONHandler/TextHandler. (b) Provide both.
**Rationale.** ReplaceAttr runs inside the terminal handler and sees a flattened key; group hierarchies are ambiguous. The wrapper approach lets us redact at the right semantic level, integrates with `WithGroup`/`WithAttrs` precomputation, and works across any downstream handler (JSON, text, Datadog, Sentry). Official Go slog-handler-guide endorses this pattern.
**Tradeoffs.** Slightly more code; users who already have a `ReplaceAttr` for formatting must layer ours in front (documented).

### ADR-002: Pino-style path DSL vs GJSON vs JSONPath
**Decision.** Pino-style (a subset of `fast-redact`).
**Alternatives.** (a) `tidwall/gjson` path syntax. (b) JSONPath (`$.req.body.password`). (c) Custom grammar.
**Rationale.** Pino's DSL is battle-tested on billions of Node.js log events, familiar to backend devs who've done any Node work, and maps cleanly onto `slog.Group` hierarchies (both are dotted + indexed). GJSON is read-oriented with filters we don't need. JSONPath is overkill and has ambiguous recursive-descent semantics.
**Tradeoffs.** We inherit Pino's quirks (e.g., no numeric indices in v1). We explicitly reject Pino's recursive-descent extension for safety.

### ADR-003: httpsnoop dependency vs vendor vs custom
**Decision.** Depend on `github.com/felixge/httpsnoop` directly.
**Alternatives.** (a) Vendor the code into `internal/`. (b) Write our own wrapper. (c) Use `nhooyr.io/websocket`-style minimal approach.
**Rationale.** httpsnoop exhaustively handles 128 combinations of the 7 ResponseWriter interfaces, is code-generated for correctness, maintained, and tiny (<500 LOC). Rolling our own guarantees we miss `Hijacker` or `ReaderFrom` in some corner and break WebSockets. Vendoring trades dependency for silent divergence risk.
**Tradeoffs.** +1 dep. Mitigation: httpsnoop itself has zero deps beyond stdlib, so our transitive closure stays tiny.

### ADR-004: Dedicated Gin subpackage vs adapter via gin.WrapH
**Decision.** Dedicated `gin/` subpackage that wraps our net/http middleware.
**Alternatives.** (a) Tell users to use `gin.WrapH(h.Middleware()(next))`. (b) Reimplement the middleware natively against `*gin.Context`.
**Rationale.** `gin.WrapH` exists but forces users to think about the adapter layer and loses `gin.Context` niceties (`c.Set`, `c.Get` for request IDs). A native reimplementation duplicates body-capture logic, doubling maintenance. Our subpackage is a 30-line bridge that delegates all heavy work to `httpmw`.
**Tradeoffs.** Users pay for a 30-line adapter. Acceptable.

### ADR-005: Context attrs via slog-context dependency vs own implementation
**Decision.** Own implementation (20 lines in `context.go`).
**Alternatives.** Depend on `veqryn/slog-context` or `samber/slog-context`.
**Rationale.** The pattern is trivially small. Pulling a dep for ~40 lines of code is over-engineering, pollutes our minimal-dep promise, and couples our API to a third-party's stability.
**Tradeoffs.** We maintain it. If slog-context becomes de-facto standard, we reconsider in v2.

### ADR-006: First-N truncation vs first-N + last-M ring buffer
**Decision.** Head truncation only for v1.
**Alternatives.** Ring buffer with head+tail windows.
**Rationale.** Head truncation is ~20 LOC, zero-allocation once pooled. Ring buffer is ~150 LOC and doubles per-request memory. The debugging benefit of seeing error trailers is real but narrow — most ops use cases want to see the start of the request anyway. Deferrable.
**Tradeoffs.** Users debugging an error that appears only in trailers are blind. Ring buffer lands in v2 behind `WithBodyRingBuffer(headN, tailM int)`.

### ADR-007: Regex redaction on/off by default
**Decision.** Off by default; users opt-in by adding detectors.
**Alternatives.** On by default with the PAN detector always active.
**Rationale.** Regex detection is O(body size) and can have false positives. Libraries that surprise users with perf regressions get uninstalled. The `NewPCI()` preset turns it on explicitly — if you opted into PCI mode, you opted into PAN scanning. Path redaction (the main feature) runs always.
**Tradeoffs.** A user calling `New()` without detectors won't catch a PAN that leaks via an unexpected field. Mitigation: README documents this loudly; `NewPCI()` is the one-line upgrade.

### ADR-008: Single replacement token (`"***"`) vs type-specific tokens
**Decision.** Single `"***"` default; user-configurable.
**Alternatives.** Type-specific tokens (`"[STRING]"`, `"[INT]"`, `"[EMAIL]"`).
**Rationale.** Type-specific tokens leak information (you learn an SSN was there, as opposed to just "something was"). Compliance review prefers uniform redaction. Simpler to document, simpler to grep.
**Tradeoffs.** Debuggability suffers slightly; users who want richer tokens use a custom `Detector` that returns named placeholders.

---

## 15. Open questions / deferred decisions

- **License.** Apache-2.0 recommended (patent grant matters for enterprise; Kubernetes, etcd, OTel all use it). MIT is viable if the maintainer prefers minimalism. Decide before first tag.
- **Module path.** Placeholder `github.com/JAS0N-SMITH/redactlog`; actual org TBD. If hosted under a personal account, `github.com/<maintainer>/redactlog` with a redirect is fine.
- **Option naming consistency.** `WithRequestBody(true)` vs `WithCaptureRequestBody(true)` — current draft uses the shorter form; reconfirm before tag.
- **UUID generation.** Inline `crypto/rand`-based UUIDv4 (20 LOC, zero deps) vs `google/uuid` dep. Current decision: inline. Confirm with a reviewer.
- **Error surface.** Should `Handler.Handle` swallow inner errors or propagate? Current: propagate. May revisit if slog `Logger` changes error discipline.
- **Default `ContentTypes`.** Include `text/html`? Current: no (too noisy for most APIs). Reconfirm.
- **Semconv version.** Pin v1.26.0 for launch; plan upgrade cadence (every six months or on stable bumps).
- **Fuzz budget.** Minimum fuzz minutes per release — suggest 10 minutes CI, 4 hours nightly on OSS-Fuzz if accepted.
- **Panic rethrow policy.** Rethrow after logging (current) vs return 500 (convenient). Current choice aligns with Go idioms; confirm with design review.
- **`SkipPaths` matching.** Exact match only in v1. Regex (`SkipPathRegexps`) deferred — but users will ask; decide whether to add as a minor bump.

---

## 16. v2 roadmap (high-level only)

These are **named, not designed**. No architectural commitment.

- **Tamper-evident audit chain.** HMAC-chained log entries with per-entry digest; Merkle tree rollup for periodic attestation; designed so verification is offline-capable.
- **Crypto-shredding.** Per-subject key destruction for GDPR right-to-erasure; encryption keys referenced by log entries, destroying key renders entries unreadable.
- **Additional compliance presets.** `NewGDPR()` (PII-focused with erasure hooks), `NewHIPAA()` (PHI categories, minimum necessary), `NewSOC2()` (audit-trail conventions).
- **Verifier CLI.** `redactlog-verify` binary that validates audit-chain integrity from an exported log stream.
- **Framework adapters.** `chi/`, `echo/`, `fiber/` subpackages following the Gin adapter pattern.
- **Runtime admin endpoint.** Guarded HTTP endpoint for viewing (not editing) current redaction config, for audit review.
- **Vendor exporters.** Direct emission to Splunk HEC, Datadog, CloudWatch EMF with vendor-specific field mapping.
- **Canonical log line / wide events.** Helpers for the Stripe-style single-log-per-request pattern.
- **Composite samplers.** Per-route, per-user, per-error-class sampling with `slog-sampling` compatibility.
- **First-N + last-M ring buffer** (see ADR-006).
- **Ring-buffer streaming capture** for long SSE connections.

---

## Conclusion

`redactlog` v1's core bet is that **a small, opinionated, compile-once redactor plus a boringly-correct HTTP middleware is more valuable to regulated Go services than a feature-rich toolkit**. The architecture intentionally fixes the easy decisions (one censor token, one preset, one DSL, head truncation, no env vars) so the hard ones (path taxonomy, LogValuer composition, context attr plumbing) get the design attention they deserve. Every boundary in the module layout — root/redact/httpmw/gin — maps to a dependency boundary users will respect, and every ADR closes a door rather than opening one, so v2 can land without breaking v1 imports. A contributor reading this document should be able to start implementation in `redact/dsl.go` and `handler.go` today, with the rest of the tree filling in predictably around the two anchor files.