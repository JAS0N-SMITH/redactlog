package redact

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/JAS0N-SMITH/redactlog/internal/luhn"
)

func FuzzDSLParse(f *testing.F) {
	// Seed corpus - examples that should always work or always fail consistently
	seeds := []string{
		"a.b.c",
		"a[*]",
		"a.*.b",
		`a["x-api-key"]`,
		"*.password",
		"req.body.card[*].cvv",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Parse any random string; should not panic
		_, err := parsePath(input)
		// Don't assert on err - invalid paths are expected;
		// The invariant: no panics
		if err != nil && err.Error() == "" {
			t.Fatalf("empty error message for input %q", input)
		}
	})
}

func FuzzRedactValue(f *testing.F) {
	// Seed with slog.Value shapes
	f.Add(`{"password":"secret"}`)
	f.Add(`[1, 2, 3]`)
	f.Add(`{"nested": {"key": "value"}}`)

	engine, _ := New([]string{"*.password", "nested.key"}, Options{Censor: "***"})

	f.Fuzz(func(t *testing.T, jsonBytes []byte) {
		var v any
		// Parse JSON; if it fails, skip
		_ = json.Unmarshal(jsonBytes, &v)
		if v == nil {
			return
		}

		// The invariant: Redact(Redact(x)) == Redact(x) - idempotent
		redacted1 := engine.Redact(v)
		redacted2 := engine.Redact(redacted1)

		// Serialize both and compare
		b1, _ := json.Marshal(redacted1)
		b2, _ := json.Marshal(redacted2)

		if !bytes.Equal(b1, b2) {
			t.Fatalf("redaction not idempotent:\nfirst: %s\nsecond: %s", b1, b2)
		}
	})
}

func FuzzLuhn(f *testing.F) {
	// Seed with valid and invalid credit card numbers
	f.Add("4111111111111111") // valid test card
	f.Add("4242424242424242") // valid test card
	f.Add("1234567890123456") // invalid card
	f.Add("")                 // empty string

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic on any input
		_ = luhn.Valid(input)
	})
}
