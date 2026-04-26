package redactlog

// New creates a new Handler with the given options. It is a general-purpose
// constructor that requires WithLogger to be set (via opts). Paths and
// detectors are opt-in.
//
// Use NewPCI for the PCI compliance preset (adds PAN detection).
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

// NewPCI creates a new Handler preconfigured for PCI compliance. It includes
// the PAN detector and default redaction paths for common payment field names.
// The PCI preset is a stub in M3 (no paths or detectors); M6 wires the full
// PCI ruleset and detector.
//
// M3 stub: NewPCI behaves identically to New(opts...). The full PCI preset
// is wired in M6.
func NewPCI(opts ...Option) (*Handler, error) {
	// M3 stub: defer full PCI paths and detector to M6.
	// For now, NewPCI is identical to New.
	return New(opts...)
}
