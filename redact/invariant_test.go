package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

// TestInvariant_Idempotent verifies Redact(Redact(x)) == Redact(x).
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

// TestInvariant_NoGrowth checks that Redaction never expands the tree.
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

// TestInvariant_SecretNeverLeaks checks that a seed string never appears in plain text.
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

func genRandomValue(t *rapid.T) any {
	depth := rapid.IntRange(0, 3).Draw(t, "depth")
	return genValue(t, depth, "v")
}

// genValue recursively builds maps, slices, and scalar leaves up to depth levels deep.
func genValue(t *rapid.T, depth int, label string) any {
	if depth == 0 {
		switch rapid.IntRange(0, 2).Draw(t, label+"_leafKind") {
		case 0:
			return rapid.StringMatching(`[a-zA-Z0-9]{1,20}`).Draw(t, label+"_str")
		case 1:
			return rapid.Int().Draw(t, label+"_int")
		default:
			return rapid.Bool().Draw(t, label+"_bool")
		}
	}
	switch rapid.IntRange(0, 2).Draw(t, label+"_kind") {
	case 0: // map
		n := rapid.IntRange(0, 4).Draw(t, label+"_n")
		m := make(map[string]any, n)
		for i := range n {
			k := rapid.StringMatching(`[a-z]{3,8}`).Draw(t, fmt.Sprintf("%s_k%d", label, i))
			m[k] = genValue(t, depth-1, fmt.Sprintf("%s_%d", label, i))
		}
		return m
	case 1: // slice
		n := rapid.IntRange(0, 3).Draw(t, label+"_n")
		s := make([]any, n)
		for i := range s {
			s[i] = genValue(t, depth-1, fmt.Sprintf("%s_%d", label, i))
		}
		return s
	default: // scalar leaf
		return rapid.StringMatching(`[a-zA-Z0-9]{1,20}`).Draw(t, label+"_str")
	}
}

// Recursively count the number of attributes in a nested structure.
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
