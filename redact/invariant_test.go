package redact

import (
	"bytes"
	"encoding/json"
	"testing"

	"pgregory.net/rapid"
)

// TestInvariant_Idempotent verifies Redact(Redact(x)) == Redact(x)
func TestInvariant_Idempotent(t *testing.T) {
	engine, _ := New([]string{"*.password", "user.*.token"}, Options{})

	rapid.Check(t, func(t *rapid.T) {
		// Generate random nested structures
		input := genRandomValue(t)
		redacted1 := engine.Redact(input)
		redacted2 := engine.Redact(redacted1)

		// Compare serializations
		b1, _ := json.Marshal(redacted1)
		b2, _ := json.Marshal(redacted2)
		if !bytes.Equal(b1, b2) {
			t.Fatalf("not idempotent for input %v", input)
		}
	})
}

// TestInvariant_NoGrowth checks that Redaction never expands the tree
func TestInvariant_NoGrowth(t *testing.T) {
	engine, _ := New([]string{"*"}, Options{})

	rapid.Check(t, func(t *rapid.T) {
		input := genRandomValue(t)
		redacted := engine.Redact(input)

		// Count attrs before and after
		before := countAttrs(input)
		after := countAttrs(redacted)
		if after > before {
			t.Fatalf("redaction grew the tree: before %d, after %d", before, after)
		}
	})
}

// TestInvariant_SecretNeverLeaks checks that a seed string never appears unredacted
func TestInvariant_SecretNeverLeaks(t *testing.T) {
	engine, _ := New([]string{"*.password"}, Options{})

	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.StringMatching(`[a-zA-Z0-9]{20,}`).Draw(t, "secret")
		input := map[string]any{"user": map[string]any{"password": secret}}
		redacted := engine.Redact(input)
		out, _ := json.Marshal(redacted)
		if bytes.Contains(out, []byte(secret)) {
			t.Fatalf("secret leaked in output: %s in %s", secret, out)
		}
	})
}

// Use rapid to generate random nested maps/slices/strings
func genRandomValue(t *rapid.T) any {
	// Pseudo-code; implement based on your value shapes
	return rapid.MapOf(
		rapid.StringMatching(`[a-z]{5,10}`),
		rapid.Just(map[string]any{"value": "data"}),).Draw(t, "randomValue")
}

// Recursively count the number of attributes in a nested structure
func countAttrs(v any) int {
	count := 0
	switch val := v.(type) {
	case map[string]any:
		for _, item := range val {
			count += 1 + countAttrs(item)
		}
	case []any:
		for _, item := range val {
			count += countAttrs(item)
		}
	}
	return count
}
