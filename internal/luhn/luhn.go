package luhn

// Valid reports whether s encodes a valid Luhn checksum. Only the decimal-digit
// characters in s are examined; all other characters are skipped, making this
// safe to call on dash- or space-separated card strings. The string must
// contain at least two digits for a meaningful result.
//
// HOT: called by the PAN detector on every string leaf. It is allocation-free
// and iterates over s once from right to left.
func Valid(s string) bool {
	nDigits := 0
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
		nDigits++
	}
	return nDigits >= 2 && sum%10 == 0
}
