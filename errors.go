package redactlog

import "errors"

// Sentinel errors returned by Config.Build and New/NewPCI.
var (
	// ErrNoLogger is returned when Config.Logger is nil.
	ErrNoLogger = errors.New("redactlog: Config.Logger is required")

	// ErrInvalidPath is returned when any DSL path fails to parse. The wrapped
	// error includes the offending path and column for diagnostics.
	ErrInvalidPath = errors.New("redactlog: invalid redaction path")

	// ErrBadCensor is returned when Config.Censor is set to an empty string.
	ErrBadCensor = errors.New("redactlog: censor must be non-empty")
)
