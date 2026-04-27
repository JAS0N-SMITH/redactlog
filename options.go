package redactlog

import (
	"log/slog"
	"time"

	"github.com/JAS0N-SMITH/redactlog/redact"
)

// Config holds all configuration for a Handler. Fields are typically not set
// directly; instead use functional Option values with New or NewPCI.
type Config struct {
	// Logger is the downstream slog.Logger whose handler we wrap. Required.
	Logger *slog.Logger

	// RedactPaths is a list of Pino-style DSL paths to redact.
	// See architecture.md §6.1 for syntax. An empty list is valid and produces
	// a redactor that performs no path-based redaction (but may still apply
	// detectors to string leaves, if configured).
	RedactPaths []string

	// Censor is the replacement token written in place of redacted values.
	// Default is "***" (see ADR-008). Must be non-empty after defaults are
	// applied; Config.Build rejects empty values.
	Censor string

	// Detectors run regex/content-based redaction after path redaction.
	// Default is empty (no detectors; opt-in per ADR-007). The PCI preset
	// adds the PANDetector.
	Detectors []redact.Detector

	// HTTP governs request/response capture for the middleware. It is a stub
	// in M3; M4 fills in all the body/header/query options. Zero value is safe.
	HTTP HTTPConfig

	// Clock is injected for deterministic testing. Default is time.Now.
	Clock func() time.Time
}

// HTTPConfig governs HTTP middleware request/response capture behavior.
type HTTPConfig struct {
	// CaptureRequestBody enables buffering the inbound request body. Default false.
	// Per ADR-007, detection is opt-in; set to true to log request bodies.
	CaptureRequestBody bool

	// CaptureResponseBody enables buffering the outbound response body. Default false.
	CaptureResponseBody bool

	// MaxBodyBytes limits captured body size. Default 65536 (64 KiB).
	// Requests with bodies exceeding this limit are truncated and marked truncated.
	// Minimum 1024; zero rejected by Build. Maximum 1 MiB.
	MaxBodyBytes int

	// ContentTypes restricts body capture to specific MIME types (e.g., application/json).
	// Default is [application/json, application/x-www-form-urlencoded, text/plain, …].
	// Bodies with Content-Type outside this list are metadata-only (size, type, but no content).
	ContentTypes []string

	// HeaderDenylist specifies headers never to log. Default includes Authorization,
	// Cookie, Set-Cookie, Proxy-Authorization, X-Api-Key, and variants.
	// If HeaderAllowlist is non-empty, this is ignored; only allowlisted headers are logged.
	HeaderDenylist []string

	// HeaderAllowlist, if non-empty, inverts the default: only these headers are logged.
	// Overrides HeaderDenylist when set. Use for strict compliance where an allowlist
	// is safer than a denylist.
	HeaderAllowlist []string

	// SensitiveQueryParams specifies query parameter names to redact.
	// Default includes "token", "access_token", "api_key", "key", "signature".
	// Values are replaced with the censor token in url.query logs.
	SensitiveQueryParams []string

	// RequestIDHeader is the header name to check for (and propagate) a request ID.
	// Default "X-Request-ID". If present inbound, it is echoed outbound and attached
	// to the log record. If absent and GenerateRequestID is true, a UUIDv4 is generated.
	RequestIDHeader string

	// GenerateRequestID controls whether to synthesize a UUIDv4 request ID if none
	// is present in the RequestIDHeader inbound. Default true.
	GenerateRequestID bool

	// SkipPaths lists exact-match request paths to skip logging entirely (e.g., /healthz).
	// Exact match only in v1; regex deferred to v2.
	SkipPaths []string
}

// Option is a functional option for configuring Config. The interface type
// has an unexported apply method, following the zap pattern, so external
// code cannot create Option-satisfying types and the surface can evolve
// without breaking semver.
type Option interface {
	apply(*Config)
}

type optionFunc func(*Config)

func (f optionFunc) apply(c *Config) { f(c) }

// WithLogger sets the downstream slog.Logger. Required; Config.Build returns
// ErrNoLogger if not set.
func WithLogger(l *slog.Logger) Option {
	return optionFunc(func(c *Config) { c.Logger = l })
}

// WithRedactPaths appends paths to the redaction path list. Paths are
// cumulative across multiple WithRedactPaths calls. An empty paths list is
// valid and produces a no-op redactor.
func WithRedactPaths(paths ...string) Option {
	return optionFunc(func(c *Config) { c.RedactPaths = append(c.RedactPaths, paths...) })
}

// WithCensor sets the replacement token. If provided multiple times, the last
// value wins. Empty string is rejected by Config.Build (ErrBadCensor). If not
// set, defaults to "***" (see ADR-008).
func WithCensor(token string) Option {
	return optionFunc(func(c *Config) { c.Censor = token })
}

// WithDetectors appends detectors to the detector list. Detectors are
// cumulative across multiple WithDetectors calls. An empty detector list is
// valid and produces a no-op detector stage. The PCI preset adds the PAN
// detector; most v1 deployments rely on path-based redaction and not content
// detectors (M6 and later).
func WithDetectors(d ...redact.Detector) Option {
	return optionFunc(func(c *Config) { c.Detectors = append(c.Detectors, d...) })
}

// WithClock injects a custom clock function for testing. Default is time.Now.
// The clock is used by the middleware layer (M4) for request/response
// timestamping and is not currently used by M3.
func WithClock(f func() time.Time) Option {
	return optionFunc(func(c *Config) { c.Clock = f })
}

// WithRequestBody enables request body capture. Default false.
// When true, request bodies are buffered (up to MaxBodyBytes) and logged
// if the Content-Type is in the ContentTypes allowlist.
func WithRequestBody(enabled bool) Option {
	return optionFunc(func(c *Config) { c.HTTP.CaptureRequestBody = enabled })
}

// WithResponseBody enables response body capture. Default false.
// When true, response bodies are buffered (up to MaxBodyBytes) and logged
// if the Content-Type is in the ContentTypes allowlist.
func WithResponseBody(enabled bool) Option {
	return optionFunc(func(c *Config) { c.HTTP.CaptureResponseBody = enabled })
}

// WithMaxBodyBytes sets the maximum size of captured request/response bodies.
// Default 65536 (64 KiB). Minimum 1024, maximum 1 MiB; out-of-range values
// are rejected by Build.
func WithMaxBodyBytes(n int) Option {
	return optionFunc(func(c *Config) { c.HTTP.MaxBodyBytes = n })
}

// WithContentTypes sets the list of MIME types eligible for body capture.
// Default is [application/json, application/x-www-form-urlencoded, text/plain, …].
// This replaces (not appends to) the default list. Use to restrict capture to
// specific content types.
func WithContentTypes(ct ...string) Option {
	return optionFunc(func(c *Config) { c.HTTP.ContentTypes = ct })
}

// WithHeaderDenylist appends headers to the logging denylist. The default denylist
// includes Authorization, Cookie, Set-Cookie, Proxy-Authorization, X-Api-Key variants.
// Provided headers are appended to these defaults unless HeaderAllowlist is set,
// in which case the denylist is ignored entirely.
func WithHeaderDenylist(h ...string) Option {
	return optionFunc(func(c *Config) { c.HTTP.HeaderDenylist = append(c.HTTP.HeaderDenylist, h...) })
}

// WithHeaderAllowlist sets an allowlist of headers to log, overriding the default
// denylist. If set, only these headers are logged; all others are omitted.
// Non-empty allowlist takes precedence over HeaderDenylist.
func WithHeaderAllowlist(h ...string) Option {
	return optionFunc(func(c *Config) { c.HTTP.HeaderAllowlist = h })
}

// WithSensitiveQueryParams appends query parameter names to redact from url.query logs.
// Default includes "token", "access_token", "api_key", "key", "signature".
func WithSensitiveQueryParams(q ...string) Option {
	return optionFunc(func(c *Config) { c.HTTP.SensitiveQueryParams = append(c.HTTP.SensitiveQueryParams, q...) })
}

// WithRequestIDHeader sets the header name to check for (and propagate) a request ID.
// Default "X-Request-ID". If the header is present inbound, it is echoed outbound
// and attached to the log record. If absent and GenerateRequestID is true, a UUIDv4
// is generated and used.
func WithRequestIDHeader(name string) Option {
	return optionFunc(func(c *Config) { c.HTTP.RequestIDHeader = name })
}

// WithGenerateRequestID controls whether a UUIDv4 request ID is synthesized if none
// is present in the RequestIDHeader inbound. Default true.
func WithGenerateRequestID(enabled bool) Option {
	return optionFunc(func(c *Config) { c.HTTP.GenerateRequestID = enabled })
}

// WithSkipPaths appends request paths to skip logging entirely. Exact-match only in v1.
// Use for routes like /healthz or /metrics that generate high-volume, low-value logs.
func WithSkipPaths(paths ...string) Option {
	return optionFunc(func(c *Config) { c.HTTP.SkipPaths = append(c.HTTP.SkipPaths, paths...) })
}
