package redactlog

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/JAS0N-SMITH/redactlog/httpmw"
	"github.com/JAS0N-SMITH/redactlog/redact"
)

// Handler is a slog.Handler wrapper that redacts attributes before delegating
// to an inner handler. It implements all four slog.Handler methods and supports
// group composition via WithGroup and context-scoped attributes via SetAttrs.
//
// A Handler is safe for concurrent use and should be shared across the
// lifetime of the service. Create one via New or NewPCI.
type Handler struct {
	inner  slog.Handler
	engine *redact.Engine
	groups []string
	clock  func() time.Time
	logger *slog.Logger
	http   HTTPConfig
}

// Build validates cfg, compiles the redaction engine, and returns a Handler
// wrapping cfg.Logger's handler. It returns ErrNoLogger if cfg.Logger is nil,
// ErrBadCensor if cfg.Censor is empty (after defaults), or an error wrapping
// ErrInvalidPath if any DSL path fails to parse.
func (c *Config) Build() (*Handler, error) {
	if c.Logger == nil {
		return nil, ErrNoLogger
	}

	censor := c.Censor
	if censor == "" {
		censor = redact.DefaultCensor
	}
	if censor == "" {
		return nil, ErrBadCensor
	}

	opts := redact.Options{
		Censor:    censor,
		Detectors: c.Detectors,
	}
	engine, err := redact.New(c.RedactPaths, opts)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}

	// Apply defaults and validate HTTPConfig.
	httpCfg, err := applyHTTPConfigDefaults(c.HTTP)
	if err != nil {
		return nil, err
	}

	return &Handler{
		inner:  c.Logger.Handler(),
		engine: engine,
		clock:  clock,
		logger: c.Logger,
		http:   httpCfg,
	}, nil
}

// applyHTTPConfigDefaults applies default values to HTTPConfig and validates bounds.
func applyHTTPConfigDefaults(cfg HTTPConfig) (HTTPConfig, error) {
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 65536 // 64 KiB default
	}
	if cfg.MaxBodyBytes < 1024 || cfg.MaxBodyBytes > 1048576 {
		return HTTPConfig{}, fmt.Errorf("MaxBodyBytes=%d out of range [1024, 1048576]", cfg.MaxBodyBytes)
	}

	// Default content types if not overridden.
	if len(cfg.ContentTypes) == 0 {
		cfg.ContentTypes = []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"application/xml",
			"text/xml",
			"text/plain",
			"application/vnd.api+json",
			"application/problem+json",
		}
	}

	// Default header denylist if not overridden (and no allowlist set).
	if len(cfg.HeaderAllowlist) == 0 && len(cfg.HeaderDenylist) == 0 {
		cfg.HeaderDenylist = []string{
			"authorization",
			"cookie",
			"set-cookie",
			"proxy-authorization",
			"x-api-key",
			"x-auth-token",
			"x-csrf-token",
			"x-xsrf-token",
			"x-session-id",
			"x-forwarded-authorization",
		}
	}

	// Default sensitive query params if empty.
	if len(cfg.SensitiveQueryParams) == 0 {
		cfg.SensitiveQueryParams = []string{
			"token",
			"access_token",
			"api_key",
			"key",
			"signature",
		}
	}

	// Default request ID header name.
	if cfg.RequestIDHeader == "" {
		cfg.RequestIDHeader = "X-Request-ID"
	}

	// Default generate request ID is true.
	if !cfg.GenerateRequestID {
		cfg.GenerateRequestID = true
	}

	return cfg, nil
}

// Enabled delegates to the inner handler. Redaction is orthogonal to level
// filtering, so we use the inner handler's decision directly.
func (h *Handler) Enabled(ctx context.Context, lvl slog.Level) bool {
	if h == nil || h.inner == nil {
		return false
	}
	return h.inner.Enabled(ctx, lvl)
}

// Handle redacts all attributes in the record and delegates to the inner
// handler. It extracts context-scoped attributes via attrsFromCtx, redacts
// them, adds them to the record, redacts record attributes under the current
// group path, and finally delegates to the inner handler.
//
// Handle never mutates the input record; it builds a fresh slog.Record and
// returns the error (if any) from the inner handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h == nil || h.inner == nil {
		return nil
	}

	// Build a fresh record so we don't mutate the caller's.
	// WithAttrs-derived attrs are pre-loaded in h.inner via the propagation in
	// WithAttrs; replaying them here would cause double-emission and would
	// incorrectly place pre-group attrs under a subsequently opened group.
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

	// Extract and add context-scoped attrs (redacted under current groups).
	for _, a := range attrsFromCtx(ctx) {
		out.AddAttrs(h.engine.RedactAttrInGroups(a, h.groups))
	}

	// Redact and add record attrs under current groups.
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.engine.RedactAttrInGroups(a, h.groups))
		return true
	})

	return h.inner.Handle(ctx, out)
}

// WithAttrs returns a new Handler with the given attributes appended. The
// attributes are pre-redacted at this call time (not at Handle time) under
// the current group path, so they are cheap to emit later. The receiver is
// not mutated; the returned handler is a new value.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	if h == nil {
		return h
	}

	clone := *h
	redacted := make([]slog.Attr, len(as))
	for i, a := range as {
		redacted[i] = h.engine.RedactAttrInGroups(a, h.groups)
	}

	// Propagate redacted attrs to inner so it owns them; Handle does not replay
	// them into the record to avoid double-emission.
	clone.inner = h.inner.WithAttrs(redacted)

	return &clone
}

// WithGroup returns a new Handler with the given group name appended to the
// group path. Subsequent attributes are redacted under the full accumulated
// group path (e.g., WithGroup("req").WithGroup("body") -> group path
// ["req", "body"]). The receiver is not mutated; the returned handler is a
// new value.
func (h *Handler) WithGroup(name string) slog.Handler {
	if h == nil {
		return h
	}
	if name == "" {
		return h
	}

	clone := *h
	// Accumulate groups (copy-on-write: don't share with parent).
	clone.groups = append(append([]string{}, h.groups...), name)
	// Propagate to inner handler so groups are nested correctly.
	clone.inner = h.inner.WithGroup(name)

	return &clone
}

// Logger returns a new *slog.Logger backed by this Handler.
func (h *Handler) Logger() *slog.Logger {
	if h == nil {
		return nil
	}
	return slog.New(h)
}

// Middleware returns an http.Handler middleware that wraps the given handler
// with request/response logging via this Handler's slog.Handler wrapper.
// The middleware captures request/response metadata and bodies (configurable),
// scrubs headers per the allowlist/denylist, and logs via h.Logger().
func (h *Handler) Middleware() func(http.Handler) http.Handler {
	if h == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	cfg := httpmw.Config{
		Logger:               h.logger,
		Redactor:             h.engine,
		CaptureRequestBody:   h.http.CaptureRequestBody,
		CaptureResponseBody:  h.http.CaptureResponseBody,
		MaxBodyBytes:         h.http.MaxBodyBytes,
		ContentTypes:         h.http.ContentTypes,
		HeaderDenylist:       h.http.HeaderDenylist,
		HeaderAllowlist:      h.http.HeaderAllowlist,
		SensitiveQueryParams: h.http.SensitiveQueryParams,
		RequestIDHeader:      h.http.RequestIDHeader,
		GenerateRequestID:    h.http.GenerateRequestID,
		SkipPaths:            h.http.SkipPaths,
		Clock:                h.clock,
	}

	return httpmw.Middleware(cfg)
}
