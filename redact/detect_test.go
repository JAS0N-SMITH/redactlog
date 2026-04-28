package redact_test

import (
	"testing"

	"github.com/JAS0N-SMITH/redactlog/redact"
)

func TestPANDetector(t *testing.T) {
	det := redact.PANDetector()

	tests := []struct {
		name    string
		input   string
		want    string
		matched bool
	}{
		// Valid PANs — must be masked.
		{
			name:    "visa16_plain",
			input:   "4111111111111111",
			want:    "411111******1111",
			matched: true,
		},
		{
			name:    "visa16_stripe",
			input:   "4242424242424242",
			want:    "424242******4242",
			matched: true,
		},
		{
			name:    "mastercard16",
			input:   "5500005555555559",
			want:    "550000******5559",
			matched: true,
		},
		{
			name:    "discover16",
			input:   "6011111111111117",
			want:    "601111******1117",
			matched: true,
		},
		{
			name:    "amex15",
			input:   "378282246310005",
			want:    "378282*****0005",
			matched: true,
		},
		{
			name:    "visa16_dashes",
			input:   "4111-1111-1111-1111",
			want:    "411111******1111",
			matched: true,
		},
		{
			name:    "visa16_spaces",
			input:   "4111 1111 1111 1111",
			want:    "411111******1111",
			matched: true,
		},
		{
			name:    "pan_in_text",
			input:   "Card 4111111111111111 was charged",
			want:    "Card 411111******1111 was charged",
			matched: true,
		},
		{
			name:    "two_pans_in_text",
			input:   "primary 4111111111111111 backup 5500005555555559",
			want:    "primary 411111******1111 backup 550000******5559",
			matched: true,
		},
		{
			name:    "visa_alternate_4444",
			input:   "4444333322221111",
			want:    "444433******1111",
			matched: true,
		},

		// Luhn-failing — must NOT be masked.
		{
			name:    "luhn_fail_sequential16",
			input:   "1234567890123456",
			matched: false,
		},
		{
			name:    "luhn_fail_allones",
			input:   "1111111111111111",
			matched: false,
		},
		{
			name:    "luhn_fail_allnines",
			input:   "9999999999999999",
			matched: false,
		},
		{
			name:    "luhn_fail_last_digit_off",
			input:   "4111111111111112",
			matched: false,
		},

		// Too short — must NOT be masked.
		{
			name:    "too_short_12digits",
			input:   "411111111111",
			matched: false,
		},
		{
			name:    "phone_11digits",
			input:   "14155551234",
			matched: false,
		},
		{
			name:    "ssn_9digits",
			input:   "123-45-6789",
			matched: false,
		},

		// Letters break consecutive digit runs — must NOT match.
		{
			name:    "uuid_with_hyphens",
			input:   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			matched: false,
		},
		{
			name:    "sku_mixed",
			input:   "SKU-1234567890",
			matched: false,
		},
		{
			name:    "ip_address",
			input:   "192.168.1.100",
			matched: false,
		},
		{
			name:    "empty_string",
			input:   "",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched := det.Detect(tt.input)
			if matched != tt.matched {
				t.Errorf("Detect(%q): matched=%v, want %v", tt.input, matched, tt.matched)
			}
			if tt.matched && got != tt.want {
				t.Errorf("Detect(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPANDetectorName(t *testing.T) {
	if got := redact.PANDetector().Name(); got != "pan" {
		t.Errorf("Name() = %q, want %q", got, "pan")
	}
}

func TestAuthHeaderDetector(t *testing.T) {
	det := redact.AuthHeaderDetector()

	tests := []struct {
		name    string
		input   string
		want    string
		matched bool
	}{
		{
			name:    "bearer_token",
			input:   "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			want:    "Bearer ***",
			matched: true,
		},
		{
			name:    "bearer_case_insensitive",
			input:   "bearer mytoken123",
			want:    "bearer ***",
			matched: true,
		},
		{
			name:    "bearer_in_header_value",
			input:   "Bearer abc.def.ghi",
			want:    "Bearer ***",
			matched: true,
		},
		{
			name:    "no_bearer",
			input:   "Basic dXNlcjpwYXNz",
			matched: false,
		},
		{
			name:    "empty",
			input:   "",
			matched: false,
		},
		{
			name:    "plain_text",
			input:   "hello world",
			matched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, matched := det.Detect(tt.input)
			if matched != tt.matched {
				t.Errorf("Detect(%q): matched=%v, want %v", tt.input, matched, tt.matched)
			}
			if tt.matched && got != tt.want {
				t.Errorf("Detect(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAuthHeaderDetectorName(t *testing.T) {
	if got := redact.AuthHeaderDetector().Name(); got != "auth_header" {
		t.Errorf("Name() = %q, want %q", got, "auth_header")
	}
}

// TestEngineWithPANDetector verifies that the Engine applies PANDetector to
// string leaves via Engine.Redact (the map[string]any path used by HTTP
// middleware body capture).
func TestEngineWithPANDetector(t *testing.T) {
	engine, err := redact.New(nil, redact.Options{
		Detectors: []redact.Detector{redact.PANDetector()},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input any
		want  any
	}{
		{
			name:  "flat_string_pan",
			input: map[string]any{"card": "4111111111111111"},
			want:  map[string]any{"card": "411111******1111"},
		},
		{
			name: "nested_pan",
			input: map[string]any{
				"payment": map[string]any{"pan": "4242424242424242"},
			},
			want: map[string]any{
				"payment": map[string]any{"pan": "424242******4242"},
			},
		},
		{
			name:  "non_pan_string_untouched",
			input: map[string]any{"order_id": "ORD-001"},
			want:  map[string]any{"order_id": "ORD-001"},
		},
		{
			name:  "luhn_fail_untouched",
			input: map[string]any{"id": "1234567890123456"},
			want:  map[string]any{"id": "1234567890123456"},
		},
		{
			name:  "int_value_untouched",
			input: map[string]any{"amount": float64(100)},
			want:  map[string]any{"amount": float64(100)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.Redact(tt.input)
			if !deepEqual(got, tt.want) {
				t.Errorf("Redact(%v): got %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestEnginePathPlusPANDetector verifies that path redaction and content
// detection compose correctly: path-matched fields get "***"; non-path string
// fields with a PAN get the masked PAN.
//
// The path rule "*.cvv" matches <any_parent>.cvv, so cvv must be one level
// inside another object (e.g. payment.cvv), not at the root of the map.
func TestEnginePathPlusPANDetector(t *testing.T) {
	engine, err := redact.New(
		[]string{"*.cvv"},
		redact.Options{Detectors: []redact.Detector{redact.PANDetector()}},
	)
	if err != nil {
		t.Fatal(err)
	}

	// "*.cvv" matches payment.cvv (wildcard * = "payment").
	// "card_number" has no path rule so PANDetector masks the PAN.
	input := map[string]any{
		"card_number": "4111111111111111",
		"payment": map[string]any{
			"cvv":    "737",
			"amount": float64(1999),
		},
	}
	got := engine.Redact(input).(map[string]any)
	payment := got["payment"].(map[string]any)

	if got["card_number"] != "411111******1111" {
		t.Errorf("card_number: got %q, want %q", got["card_number"], "411111******1111")
	}
	if payment["cvv"] != "***" {
		t.Errorf("payment.cvv: got %q, want %q", payment["cvv"], "***")
	}
	if payment["amount"] != float64(1999) {
		t.Errorf("payment.amount: got %v, want %v", payment["amount"], float64(1999))
	}
}

// BenchmarkPANDetector_16digit measures the hot-path cost of running
// PANDetector.Detect on a 16-digit PAN string.
func BenchmarkPANDetector_16digit(b *testing.B) {
	det := redact.PANDetector()
	s := "4111111111111111"
	b.ReportAllocs()
	for b.Loop() {
		det.Detect(s)
	}
}

// BenchmarkPANDetector_NoMatch measures the cost when the input has no PAN.
func BenchmarkPANDetector_NoMatch(b *testing.B) {
	det := redact.PANDetector()
	s := "order-id-abc-12345"
	b.ReportAllocs()
	for b.Loop() {
		det.Detect(s)
	}
}

// deepEqual is a minimal recursive comparator for the types produced by
// Engine.Redact (map[string]any, []any, scalar). It avoids importing
// reflect in the test binary's production-path and keeps the test readable.
func deepEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, av2 := range av {
			if !deepEqual(av2, bv[k]) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !deepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}
