package redactlog

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

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
	attrs  []slog.Attr
	clock  func() time.Time
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

	return &Handler{
		inner:  c.Logger.Handler(),
		engine: engine,
		groups: nil,
		attrs:  nil,
		clock:  clock,
	}, nil
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
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

	// Add pre-redacted attrs from WithAttrs (these are already redacted at call time).
	out.AddAttrs(h.attrs...)

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

	// Accumulate pre-redacted attrs (copy-on-write: don't share with parent).
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), redacted...)

	// Propagate to inner handler so it can apply any handler-native optimizations.
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
// with request/response logging. This is a stub for M3; the full
// implementation with body capture and header scrubbing is wired in M4.
func (h *Handler) Middleware() func(http.Handler) http.Handler {
	if h == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	// M3 stub: pass through. M4 implements the full middleware.
	return func(next http.Handler) http.Handler { return next }
}
