package redactlog

import (
	"context"
	"log/slog"
)

type ctxAttrsKey struct{}

// SetAttrs attaches redaction-scoped attributes to a context. These attributes
// are extracted by the Handler and emitted with every log line made via that
// context. Typical use is to attach a request ID or user ID in middleware,
// which then appears in all logs for that request.
//
// Attributes are redacted under the accumulated group path just like record
// attributes, so a DSL path like "request_id" or "user.*" can target them.
//
// The function returns a new context with the attributes appended to any
// existing scoped attributes; the input context is not mutated.
func SetAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	existing, _ := ctx.Value(ctxAttrsKey{}).([]slog.Attr)
	merged := make([]slog.Attr, len(existing)+len(attrs))
	copy(merged, existing)
	copy(merged[len(existing):], attrs)
	return context.WithValue(ctx, ctxAttrsKey{}, merged)
}

// attrsFromCtx extracts redaction-scoped attributes from the context. It is
// called internally by the Handler during each Handle call. A nil context or a
// context without SetAttrs-attached attributes returns nil.
func attrsFromCtx(ctx context.Context) []slog.Attr {
	v, _ := ctx.Value(ctxAttrsKey{}).([]slog.Attr)
	return v
}
