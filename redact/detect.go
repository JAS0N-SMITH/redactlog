package redact

import (
	"regexp"
	"strings"

	"github.com/JAS0N-SMITH/redactlog/internal/luhn"
)

// panRegex matches 13–19 consecutive decimal digits with optional single
// space or dash separators between digits (e.g., "4111-1111-1111-1111" or
// "4111 1111 1111 1111"). Separators are stripped before the Luhn check.
//
// Pattern: one digit, optionally followed by a separator, repeated 12–18
// times, then a final required digit — giving 13–19 total digits.
var panRegex = regexp.MustCompile(`(?:\d[ -]?){12,18}\d`)

// bearerRegex matches HTTP Bearer tokens (case-insensitive) in header values.
// The scheme keyword and one or more whitespace characters are preserved; only
// the token itself is replaced.
var bearerRegex = regexp.MustCompile(`(?i)(Bearer\s+)\S+`)

// panDetector is the concrete Detector for Primary Account Numbers.
type panDetector struct{}

// authHeaderDetector is the concrete Detector for Bearer authorization tokens.
type authHeaderDetector struct{}

// PANDetector returns a Detector that finds and masks Primary Account Numbers
// (credit/debit card numbers) in string values. Detection uses a regex to
// locate 13–19 digit sequences (with optional separators), followed by a Luhn
// checksum to reject false positives.
//
// Matched PANs are replaced with a masked form showing the first six digits
// (BIN) and the last four digits, per PCI DSS 4.0 §3.4.1:
//
//	"4111111111111111" → "411111******1111"
//	"378282246310005"  → "378282*****0005"
//
// Regex redaction is off by default (ADR-007); PANDetector is explicitly
// activated by the NewPCI preset.
func PANDetector() Detector { return panDetector{} }

// AuthHeaderDetector returns a Detector that redacts Bearer tokens from HTTP
// Authorization header values. The scheme name is preserved:
//
//	"Bearer eyJhbGci..." → "Bearer ***"
func AuthHeaderDetector() Detector { return authHeaderDetector{} }

// Name implements Detector.
func (panDetector) Name() string { return "pan" }

// Detect implements Detector. It finds every PAN-like sequence in s, verifies
// it with the Luhn algorithm, and replaces verified PANs with the first-6/
// last-4 masked form. It returns the processed string and matched=true when at
// least one PAN was found; otherwise it returns ("", false) so the caller
// leaves s unchanged.
func (panDetector) Detect(s string) (string, bool) {
	found := false
	result := panRegex.ReplaceAllStringFunc(s, func(match string) string {
		digits := extractDigits(match)
		n := len(digits)
		if n < 13 || n > 19 {
			return match
		}
		if !luhn.Valid(digits) {
			return match
		}
		found = true
		return maskPAN(digits)
	})
	if !found {
		return "", false
	}
	return result, true
}

// Name implements Detector.
func (authHeaderDetector) Name() string { return "auth_header" }

// Detect implements Detector. It replaces the token portion of any Bearer
// authorization value with "***", preserving the scheme name and whitespace.
func (authHeaderDetector) Detect(s string) (string, bool) {
	result := bearerRegex.ReplaceAllString(s, "${1}***")
	if result == s {
		return "", false
	}
	return result, true
}

// extractDigits returns only the decimal-digit characters from s.
func extractDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// maskPAN returns the PCI-DSS-compliant masked form of digits, a pure
// decimal-digit string of length 13–19. The first six digits (BIN) and the
// last four digits are visible; the middle is replaced with asterisks.
func maskPAN(digits string) string {
	n := len(digits)
	mid := strings.Repeat("*", n-10)
	return digits[:6] + mid + digits[n-4:]
}
