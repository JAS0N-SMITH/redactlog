package redact

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

func TestCompile_Empty(t *testing.T) {
	t.Parallel()

	p, err := compile(nil, "***")
	if err != nil {
		t.Fatalf("compile(nil) returned error: %v", err)
	}
	if p == nil || p.root == nil {
		t.Fatalf("expected non-nil Program with non-nil root, got %+v", p)
	}
	if p.root.leaf {
		t.Errorf("root should not be a leaf for empty input")
	}
	if len(p.root.children) != 0 {
		t.Errorf("expected 0 children, got %d", len(p.root.children))
	}
	if p.root.wildChild != nil {
		t.Errorf("expected nil wildChild, got %+v", p.root.wildChild)
	}
	if p.numRules != 0 {
		t.Errorf("numRules = %d, want 0", p.numRules)
	}
}

func TestCompile_SingleExactPath(t *testing.T) {
	t.Parallel()

	p, err := compile([]string{"a.b.c"}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	a := mustChild(t, p.root, "a")
	requireNotLeaf(t, a)
	b := mustChild(t, a, "b")
	requireNotLeaf(t, b)
	c := mustChild(t, b, "c")
	requireLeaf(t, c)
	if len(c.children) != 0 || c.wildChild != nil {
		t.Errorf("terminal node should have no children, got %+v", c)
	}
}

func TestCompile_PrefixSharing(t *testing.T) {
	t.Parallel()

	p, err := compile([]string{"a.b", "a.c", "a.d.e"}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	a := mustChild(t, p.root, "a")
	requireNotLeaf(t, a)

	// a.b and a.c are leaves; a.d is an intermediate.
	b := mustChild(t, a, "b")
	requireLeaf(t, b)
	c := mustChild(t, a, "c")
	requireLeaf(t, c)
	d := mustChild(t, a, "d")
	requireNotLeaf(t, d)
	e := mustChild(t, d, "e")
	requireLeaf(t, e)

	if got := len(a.children); got != 3 {
		t.Errorf("a has %d children (%v), want 3", got, sortedKeys(a.children))
	}
}

func TestCompile_LeafAtIntermediate(t *testing.T) {
	t.Parallel()

	// a.b is a leaf; a.b.c is also a leaf — both must coexist.
	p, err := compile([]string{"a.b", "a.b.c"}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	b := mustChild(t, mustChild(t, p.root, "a"), "b")
	requireLeaf(t, b)
	c := mustChild(t, b, "c")
	requireLeaf(t, c)
}

func TestCompile_WildcardInsertion(t *testing.T) {
	t.Parallel()

	p, err := compile([]string{"a.*"}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	a := mustChild(t, p.root, "a")
	if a.wildChild == nil {
		t.Fatal("expected wildChild on a")
	}
	requireLeaf(t, a.wildChild)
}

func TestCompile_ArrayAndObjectWildcardsShareSlot(t *testing.T) {
	t.Parallel()

	// Per architecture §6.4 / ADR-002, `.*` and `[*]` collapse to the same
	// wildChild. Inserting both should not allocate two distinct child nodes.
	p, err := compile([]string{"a.*.x", "a[*].y"}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	a := mustChild(t, p.root, "a")
	if a.wildChild == nil {
		t.Fatal("expected wildChild on a")
	}

	// Both x and y must end up under the same wildChild.
	wc := a.wildChild
	x := mustChild(t, wc, "x")
	requireLeaf(t, x)
	y := mustChild(t, wc, "y")
	requireLeaf(t, y)
	if got := len(wc.children); got != 2 {
		t.Errorf("wildChild has %d children (%v), want 2 (x, y)", got, sortedKeys(wc.children))
	}
}

func TestCompile_QuotedKeyIsLiteral(t *testing.T) {
	t.Parallel()

	p, err := compile([]string{`req.headers["x-api-key"]`}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	headers := mustChild(t, mustChild(t, p.root, "req"), "headers")
	leaf := mustChild(t, headers, "x-api-key")
	requireLeaf(t, leaf)
}

func TestCompile_DuplicatePathsMergeButCountAll(t *testing.T) {
	t.Parallel()

	p, err := compile([]string{"a.b", "a.b", "a.c"}, "***")
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	a := mustChild(t, p.root, "a")
	if got := len(a.children); got != 2 {
		t.Errorf("a has %d children, want 2 (b, c) — duplicate a.b should merge", got)
	}
	if p.numRules != 3 {
		t.Errorf("numRules = %d, want 3 (each input counted)", p.numRules)
	}
}

func TestCompile_InvalidPathPropagates(t *testing.T) {
	t.Parallel()

	_, err := compile([]string{"a.b", "a.**", "c"}, "***")
	if err == nil {
		t.Fatal("expected error from invalid path")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("error %v does not wrap ErrInvalidPath", err)
	}
	if !strings.Contains(err.Error(), "a.**") {
		t.Errorf("error %q should reference offending path %q", err.Error(), "a.**")
	}
}

func TestProgram_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    *Program
		want string
	}{
		{
			name: "nil program",
			p:    nil,
			want: "redact.Program(nil)",
		},
		{
			name: "empty rules",
			p:    mustCompile(t, nil, "***"),
			want: `redact.Program{rules=0, censor="***"}`,
		},
		{
			name: "with rules and custom censor",
			p:    mustCompile(t, []string{"a.b", "c.*"}, "[REDACTED]"),
			want: `redact.Program{rules=2, censor="[REDACTED]"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- helpers ---

func mustCompile(t *testing.T, paths []string, censor string) *Program {
	t.Helper()
	p, err := compile(paths, censor)
	if err != nil {
		t.Fatalf("compile(%v) failed: %v", paths, err)
	}
	return p
}

func mustChild(t *testing.T, n *trieNode, key string) *trieNode {
	t.Helper()
	if n == nil {
		t.Fatalf("mustChild(%q): node is nil", key)
	}
	c, ok := n.children[key]
	if !ok {
		t.Fatalf("expected child %q, got keys %v", key, sortedKeys(n.children))
	}
	return c
}

func requireLeaf(t *testing.T, n *trieNode) {
	t.Helper()
	if !n.leaf {
		t.Errorf("expected node to be a leaf")
	}
}

func requireNotLeaf(t *testing.T, n *trieNode) {
	t.Helper()
	if n.leaf {
		t.Errorf("expected node not to be a leaf")
	}
}

func sortedKeys(m map[string]*trieNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
