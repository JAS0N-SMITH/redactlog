package redact

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// ident is a test helper that builds a literal-key segment.
func ident(name string) segment { return segment{kind: segIdent, name: name} }

var (
	wild  = segment{kind: segWild}
	arrWC = segment{kind: segArrayWild}
)

func TestParsePath_Valid(t *testing.T) {
	t.Parallel()

	// The first ten cases are the canonical example paths from
	// docs/architecture.md §6.1. Remaining cases cover boundary forms.
	tests := []struct {
		name string
		in   string
		want []segment
	}{
		{
			"§6.1 ex 1: exact leaf", "req.body.password",
			[]segment{ident("req"), ident("body"), ident("password")},
		},
		{
			"§6.1 ex 2: header authorization", "req.headers.authorization",
			[]segment{ident("req"), ident("headers"), ident("authorization")},
		},
		{
			"§6.1 ex 3: bracketed hyphen key", `req.headers["x-api-key"]`,
			[]segment{ident("req"), ident("headers"), ident("x-api-key")},
		},
		{
			"§6.1 ex 4: terminal wildcard", "req.body.user.*",
			[]segment{ident("req"), ident("body"), ident("user"), wild},
		},
		{
			"§6.1 ex 5: array wildcard + ident", "req.body.items[*].secret",
			[]segment{ident("req"), ident("body"), ident("items"), arrWC, ident("secret")},
		},
		{
			"§6.1 ex 6: terminal array wildcard", "res.body.accounts[*]",
			[]segment{ident("res"), ident("body"), ident("accounts"), arrWC},
		},
		{
			"§6.1 ex 7: leading wildcard", "*.ssn",
			[]segment{wild, ident("ssn")},
		},
		{
			"§6.1 ex 8: intermediate wildcard", "req.body.*.token",
			[]segment{ident("req"), ident("body"), wild, ident("token")},
		},
		{
			"§6.1 ex 9: scoped intermediate wildcard", "req.body.nested.*.credential",
			[]segment{ident("req"), ident("body"), ident("nested"), wild, ident("credential")},
		},
		{
			"§6.1 ex 10: terminal array wildcard", "req.body.config.keys[*]",
			[]segment{ident("req"), ident("body"), ident("config"), ident("keys"), arrWC},
		},

		{
			"single ident", "password",
			[]segment{ident("password")},
		},
		{
			"single wildcard", "*",
			[]segment{wild},
		},
		{
			"underscore identifier", "_private.field_one",
			[]segment{ident("_private"), ident("field_one")},
		},
		{
			"identifier with digits in middle/end", "ipv4.x1y",
			[]segment{ident("ipv4"), ident("x1y")},
		},
		{
			"top-level bracket-quoted key", `["odd.key"].x`,
			[]segment{ident("odd.key"), ident("x")},
		},
		{
			"quoted key containing bracket-irrelevant chars", `req.headers["X-Real-IP"]`,
			[]segment{ident("req"), ident("headers"), ident("X-Real-IP")},
		},
		{
			"chained array wildcards", "a[*][*]",
			[]segment{ident("a"), arrWC, arrWC},
		},
		{
			"wildcard then array wildcard", "a.*[*]",
			[]segment{ident("a"), wild, arrWC},
		},
		{
			"three consecutive wildcards via dots", "*.*.*",
			[]segment{wild, wild, wild},
		},
		{
			"quoted whitespace in key", `a["my key"]`,
			[]segment{ident("a"), ident("my key")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePath(tt.in)
			if err != nil {
				t.Fatalf("parsePath(%q) returned error: %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parsePath(%q):\n  got  %#v\n  want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParsePath_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		// Explicitly forbidden in architecture §6.1.
		{"recursive descent bare", "**"},
		{"recursive descent at end", "a.**"},
		{"recursive descent in middle", "a.**.b"},
		{"numeric index", "a[0]"},
		{"numeric index with field", "a[1].b"},
		{"multi-digit index", "a[42]"},
		{"negation prefix", "!a.b"},
		{"glob char-class via unquoted bracket", "a[pP]assword"},

		// General syntax errors.
		{"empty path", ""},
		{"bare dot", "."},
		{"trailing dot", "a."},
		{"double dot", "a..b"},
		{"leading dot", ".a"},
		{"unterminated bracket", "a[*"},
		{"unterminated quoted", `a["foo`},
		{"unterminated quoted no close bracket", `a["foo"`},
		{"empty bracket", "a[]"},
		{"empty quoted", `a[""]`},
		{"escape inside quoted", `a["a\nb"]`},
		{"missing separator after array", "a[*]b"},
		{"missing separator after quoted", `a["x"]b`},
		{"identifier starting with digit", "0a.b"},
		{"whitespace at start", " a.b"},
		{"whitespace inside path", "a .b"},
		{"hyphen in unquoted ident", "a-b"},
		{"unexpected char at start", "@a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePath(tt.in)
			if err == nil {
				t.Fatalf("parsePath(%q) = %#v, want error", tt.in, got)
			}
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("parsePath(%q) error %v does not wrap ErrInvalidPath", tt.in, err)
			}
		})
	}
}

// TestParsePath_ErrorIncludesPathAndColumn verifies the diagnostic shape so
// users can find offending paths in a stack of rules at construction time.
func TestParsePath_ErrorIncludesPathAndColumn(t *testing.T) {
	t.Parallel()

	_, err := parsePath("a..b")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{`"a..b"`, "col ", "redactlog: invalid redaction path"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}
