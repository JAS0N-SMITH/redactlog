package redact

import (
	"testing"
)

func FuzzDSLParse(f *testing.F) {
	// Seed corpus - examples that should always work or always fail consistently


}

func FuzzRedactValue(f *testing.F) {
	// Seed with slog.Value shapes
}

func FuzzLuhn(f *testing.F) {
	// Seed with valid and invalid credit card numbers
}

