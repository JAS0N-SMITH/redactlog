package luhn_test

import (
	"testing"

	"github.com/JAS0N-SMITH/redactlog/internal/luhn"
)

func TestValid(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		valid bool
	}{
		// Known-valid PCI test card numbers.
		{"visa16", "4111111111111111", true},
		{"visa16_stripe", "4242424242424242", true},
		{"amex15", "378282246310005", true},
		{"mastercard16", "5500005555555559", true},
		{"discover16", "6011111111111117", true},

		// Dash/space separators are ignored.
		{"visa_dashes", "4111-1111-1111-1111", true},
		{"visa_spaces", "4111 1111 1111 1111", true},
		{"amex_spaces", "3782 822463 10005", true},

		// Luhn-failing sequences (same digit count, last digit off).
		{"visa_bad_last", "4111111111111112", false},
		{"sequential16", "1234567890123456", false},
		{"allones16", "1111111111111111", false},
		{"allnines16", "9999999999999999", false},

		// Too short: need at least 2 digits.
		{"one_digit", "7", false},
		{"empty", "", false},

		// Non-digit characters are skipped.
		{"letters_only", "abcdef", false},
		{"mixed_letters", "4111abc111111111", false}, // only 14 digits → still check Luhn on those

		// Edge: two-digit valid (18 passes: 1 doubled=2; 8 undoubled: sum=10).
		{"two_digit_valid", "18", true},
		{"two_digit_invalid", "19", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := luhn.Valid(tt.s); got != tt.valid {
				t.Errorf("Valid(%q) = %v, want %v", tt.s, got, tt.valid)
			}
		})
	}
}

func BenchmarkValid_16digit(b *testing.B) {
	s := "4111111111111111"
	b.ReportAllocs()
	for b.Loop() {
		luhn.Valid(s)
	}
}
