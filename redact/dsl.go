package redact

import (
	"errors"
	"fmt"
)

// ErrInvalidPath is returned when a DSL path string fails to parse. Callers
// should check membership with [errors.Is]; the wrapping error includes the
// offending path and a 1-based column for diagnostics.
//
// See docs/architecture.md §6.1 for the grammar and ADR-002 for the rationale.
var ErrInvalidPath = errors.New("redactlog: invalid redaction path")

// segKind identifies the kind of a parsed path segment.
type segKind uint8

const (
	// segIdent is a literal key segment (e.g. "password" in req.body.password).
	segIdent segKind = iota
	// segWild is the single-segment wildcard "*".
	segWild
	// segArrayWild is the array wildcard "[*]".
	segArrayWild
)

// segment is one node in a parsed DSL path.
type segment struct {
	kind segKind
	name string // populated for segIdent only
}

// parsePath lexes and parses a single DSL path string, returning its segments
// in left-to-right order. The empty string and any input that violates the
// grammar return an error wrapping [ErrInvalidPath].
//
// Grammar (see architecture.md §6.1):
//
//	path     := first ( '.' segment | '[' bracket ']' )*
//	first    := IDENT | '*' | '[' bracket ']'
//	segment  := IDENT | '*'
//	bracket  := '*' | '"' [^"]+ '"'
//	IDENT    := [A-Za-z_][A-Za-z0-9_]*
//
// "**" (recursive descent), numeric bracket indices, negation prefixes, and
// glob character classes are rejected per ADR-002.
func parsePath(p string) ([]segment, error) {
	if p == "" {
		return nil, wrapPathErr(p, 1, "empty path")
	}
	pp := pathParser{src: p}
	if pp.peek() == '!' {
		return nil, pp.errf("negated paths are not supported")
	}
	first, err := pp.parseFirst()
	if err != nil {
		return nil, err
	}
	out := []segment{first}
	for pp.pos < len(pp.src) {
		seg, err := pp.parseNext()
		if err != nil {
			return nil, err
		}
		out = append(out, seg)
	}
	return out, nil
}

type pathParser struct {
	src string
	pos int // byte offset into src; reported column = pos + 1
}

func (pp *pathParser) parseFirst() (segment, error) {
	c := pp.peek()
	switch {
	case c == '*':
		pp.pos++
		if pp.peek() == '*' {
			return segment{}, pp.errf("`**` recursive descent is not supported")
		}
		return segment{kind: segWild}, nil
	case c == '[':
		return pp.parseBracket()
	case isIdentStart(c):
		return segment{kind: segIdent, name: pp.consumeIdent()}, nil
	default:
		return segment{}, pp.errf("unexpected %s", showByte(c))
	}
}

func (pp *pathParser) parseNext() (segment, error) {
	c := pp.peek()
	switch c {
	case '.':
		pp.pos++
		c2 := pp.peek()
		switch {
		case c2 == '*':
			pp.pos++
			if pp.peek() == '*' {
				return segment{}, pp.errf("`**` recursive descent is not supported")
			}
			return segment{kind: segWild}, nil
		case isIdentStart(c2):
			return segment{kind: segIdent, name: pp.consumeIdent()}, nil
		default:
			return segment{}, pp.errf("expected identifier or `*` after `.`, got %s", showByte(c2))
		}
	case '[':
		return pp.parseBracket()
	default:
		return segment{}, pp.errf("expected `.` or `[`, got %s", showByte(c))
	}
}

// parseBracket parses a bracketed segment starting at '['. It accepts only
// `[*]` and `["..."]`; numeric indices and unquoted bracket bodies (which
// would permit glob char-classes) are rejected.
func (pp *pathParser) parseBracket() (segment, error) {
	pp.pos++ // consume '['
	c := pp.peek()
	switch {
	case c == '*':
		pp.pos++
		if pp.peek() != ']' {
			return segment{}, pp.errf("expected `]` after `[*`")
		}
		pp.pos++
		return segment{kind: segArrayWild}, nil
	case c == '"':
		return pp.parseQuoted()
	case c >= '0' && c <= '9':
		return segment{}, pp.errf("numeric bracket indices are not supported")
	case c == ']':
		return segment{}, pp.errf("empty `[]` is not allowed")
	default:
		return segment{}, pp.errf("bracket content must be `*` or a quoted string, got %s", showByte(c))
	}
}

// parseQuoted parses a `"..."` body inside brackets. The opening `"` is the
// current peek byte; on success the closing `]` is also consumed.
func (pp *pathParser) parseQuoted() (segment, error) {
	pp.pos++ // consume opening '"'
	start := pp.pos
	for pp.pos < len(pp.src) && pp.src[pp.pos] != '"' {
		if pp.src[pp.pos] == '\\' {
			return segment{}, pp.errf("escape sequences are not supported in quoted segment")
		}
		pp.pos++
	}
	if pp.pos >= len(pp.src) {
		return segment{}, pp.errf("unterminated quoted segment")
	}
	name := pp.src[start:pp.pos]
	if name == "" {
		return segment{}, pp.errf("empty quoted segment")
	}
	pp.pos++ // consume closing '"'
	if pp.peek() != ']' {
		return segment{}, pp.errf("expected `]` after quoted segment")
	}
	pp.pos++
	return segment{kind: segIdent, name: name}, nil
}

func (pp *pathParser) peek() byte {
	if pp.pos >= len(pp.src) {
		return 0
	}
	return pp.src[pp.pos]
}

func (pp *pathParser) consumeIdent() string {
	start := pp.pos
	for pp.pos < len(pp.src) && isIdentCont(pp.src[pp.pos]) {
		pp.pos++
	}
	return pp.src[start:pp.pos]
}

func (pp *pathParser) errf(format string, args ...any) error {
	return wrapPathErr(pp.src, pp.pos+1, fmt.Sprintf(format, args...))
}

func wrapPathErr(path string, col int, detail string) error {
	return fmt.Errorf("%w: %q (col %d): %s", ErrInvalidPath, path, col, detail)
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func showByte(c byte) string {
	if c == 0 {
		return "end of input"
	}
	return fmt.Sprintf("%q", c)
}
