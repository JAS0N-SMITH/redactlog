package redactlog

import "github.com/JAS0N-SMITH/redactlog/redact"

// New creates a new Handler with the given options. It is a general-purpose
// constructor that requires WithLogger to be set (via opts). Paths and
// detectors are opt-in.
//
// Use NewPCI for the PCI-DSS compliance preset (adds PAN detection and
// common payment field redaction paths).
func New(opts ...Option) (*Handler, error) {
	cfg := &Config{
		Censor: "",
		Clock:  nil,
	}
	for _, opt := range opts {
		opt.apply(cfg)
	}
	return cfg.Build()
}

// NewPCI creates a Handler preconfigured for PCI-DSS compliance. It merges
// the following defaults before applying caller-supplied opts:
//
//   - [redact.PANDetector] — content-based PAN detection (Luhn+regex, per ADR-007).
//   - PCI redaction paths — common payment field names (cvv, pan, track data, etc.).
//   - Header denylist additions — authorization, cookie, set-cookie.
//
// Caller-supplied opts are applied after the defaults, so they can extend or
// override them (e.g., WithRedactPaths appends extra paths).
//
// WithLogger is still required; NewPCI returns ErrNoLogger if not provided.
func NewPCI(opts ...Option) (*Handler, error) {
	defaults := make([]Option, 0, 3+len(opts))
	defaults = append(defaults,
		WithDetectors(redact.PANDetector()),
		WithRedactPaths(pciRedactPaths...),
		WithHeaderDenylist(pciHeaderDenylist...),
	)
	return New(append(defaults, opts...)...)
}
