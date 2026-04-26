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

// HTTPConfig is a stub placeholder for M3. M4 fills in all request/response
// body and header configuration options.
type HTTPConfig struct {
	// TODO(M4): add CaptureRequestBody, CaptureResponseBody, MaxBodyBytes,
	// ContentTypes, HeaderDenylist, HeaderAllowlist, SensitiveQueryParams,
	// RequestIDHeader, GenerateRequestID, SkipPaths.
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
