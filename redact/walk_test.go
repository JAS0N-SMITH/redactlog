package redact

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// fmtAttr renders an attr in a stable, dependency-free form so tests can
// compare expected vs actual output via plain string equality.
func fmtAttr(a slog.Attr) string { return a.Key + "=" + fmtValue(a.Value) }

func fmtValue(v slog.Value) string {
	if v.Kind() == slog.KindGroup {
		attrs := v.Group()
		parts := make([]string, len(attrs))
		for i, a := range attrs {
			parts[i] = fmtAttr(a)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return v.String()
}

func TestRedactAttr_NilOrEmptyProgram(t *testing.T) {
	t.Parallel()

	a := slog.String("password", "secret")
	want := fmtAttr(a)

	// nil program is a no-op.
	var pNil *Program
	if got := fmtAttr(pNil.redactAttr(a)); got != want {
		t.Errorf("nil program: got %q, want %q", got, want)
	}

	// Empty program (no rules) is also a no-op.
	pEmpty := mustCompile(t, nil, "***")
	if got := fmtAttr(pEmpty.redactAttr(a)); got != want {
		t.Errorf("empty program: got %q, want %q", got, want)
	}
}

func TestRedactAttr_TopLevelExactMatch(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"password"}, "***")
	got := fmtAttr(p.redactAttr(slog.String("password", "hunter2")))
	if got != "password=***" {
		t.Errorf("got %q, want %q", got, "password=***")
	}

	// A non-matching sibling key is untouched.
	other := fmtAttr(p.redactAttr(slog.String("greeting", "hi")))
	if other != "greeting=hi" {
		t.Errorf("got %q, want %q", other, "greeting=hi")
	}
}

func TestRedactAttr_NestedExactMatch(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"req.body.password"}, "***")
	body := slog.GroupValue(
		slog.String("password", "hunter2"),
		slog.String("username", "alice"),
	)
	req := slog.Attr{Key: "req", Value: slog.GroupValue(slog.Attr{Key: "body", Value: body})}

	got := fmtAttr(p.redactAttr(req))
	want := "req={body={password=***,username=alice}}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRedactAttr_WildcardMatch(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"req.*.token"}, "***")
	v := slog.Attr{Key: "req", Value: slog.GroupValue(
		slog.Attr{Key: "user", Value: slog.GroupValue(
			slog.String("token", "abc"),
			slog.String("name", "alice"),
		)},
		slog.Attr{Key: "session", Value: slog.GroupValue(
			slog.String("token", "xyz"),
		)},
	)}
	got := fmtAttr(p.redactAttr(v))
	want := "req={user={token=***,name=alice},session={token=***}}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRedactAttr_TerminalWildcardRedactsAllChildren(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"secrets.*"}, "***")
	v := slog.Attr{Key: "secrets", Value: slog.GroupValue(
		slog.String("api_key", "k1"),
		slog.String("db_pass", "k2"),
		slog.Int("rotation_days", 30),
	)}
	got := fmtAttr(p.redactAttr(v))
	want := "secrets={api_key=***,db_pass=***,rotation_days=***}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRedactAttr_GroupKeyMatchesLeaf_RedactsWholeGroup(t *testing.T) {
	t.Parallel()

	// Rule names a key whose value is a group — entire group becomes censor.
	p := mustCompile(t, []string{"req.body"}, "***")
	v := slog.Attr{Key: "req", Value: slog.GroupValue(
		slog.Attr{Key: "body", Value: slog.GroupValue(
			slog.String("user", "alice"),
			slog.String("password", "hunter2"),
		)},
	)}
	got := fmtAttr(p.redactAttr(v))
	want := "req={body=***}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// secretString is a test LogValuer that always resolves to "***", verifying
// LogValuer resolution composes correctly with the path walker (architecture
// §6.5).
type secretString string

func (s secretString) LogValue() slog.Value { return slog.StringValue("***") }

func TestRedactAttr_LogValuerResolvedBeforeMatch(t *testing.T) {
	t.Parallel()

	// No path rules; the LogValuer alone must redact the value.
	p := mustCompile(t, nil, "REDACTED")
	a := slog.Any("token", secretString("real-secret-bytes"))
	got := fmtAttr(p.redactAttr(a))
	if got != "token=***" {
		t.Errorf("got %q, want %q", got, "token=***")
	}

	// And path rules still work on top: leaf match takes precedence over the
	// resolved string. (We use a custom censor to distinguish the two paths.)
	p2 := mustCompile(t, []string{"token"}, "PATH")
	got2 := fmtAttr(p2.redactAttr(slog.Any("token", secretString("x"))))
	if got2 != "token=PATH" {
		t.Errorf("got %q, want %q", got2, "token=PATH")
	}
}

// TestRedactAttr_MultiStateOverlap is the correctness test for multi-state
// walking. With rules `a.b.password` and `a.*.token`, the value `a.b.token`
// is matched only via the wildcard branch — single-state walking that picks
// `child` over `wild` would miss it and leak. CLAUDE.md §10 fail-closed.
func TestRedactAttr_MultiStateOverlap(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"a.b.password", "a.*.token"}, "***")
	v := slog.Attr{Key: "a", Value: slog.GroupValue(
		slog.Attr{Key: "b", Value: slog.GroupValue(
			slog.String("password", "p1"),
			slog.String("token", "t1"), // must redact via a.*.token
			slog.String("other", "ok"),
		)},
	)}
	got := fmtAttr(p.redactAttr(v))
	want := "a={b={password=***,token=***,other=ok}}"
	if got != want {
		t.Errorf("multi-state walker missed overlap case:\n got %q\nwant %q", got, want)
	}
}

func TestRedactAttr_BracketQuotedKey(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{`req.headers["x-api-key"]`}, "***")
	v := slog.Attr{Key: "req", Value: slog.GroupValue(
		slog.Attr{Key: "headers", Value: slog.GroupValue(
			slog.String("x-api-key", "supersecret"),
			slog.String("user-agent", "go-test"),
		)},
	)}
	got := fmtAttr(p.redactAttr(v))
	want := "req={headers={x-api-key=***,user-agent=go-test}}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRedactAttr_PassThroughNonStringScalars(t *testing.T) {
	t.Parallel()

	// No rules — int/bool/time/duration round-trip unchanged.
	p := mustCompile(t, nil, "***")
	cases := []slog.Attr{
		slog.Int("count", 42),
		slog.Bool("ok", true),
		slog.Float64("ratio", 0.75),
		slog.Time("at", time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)),
		slog.Duration("elapsed", 2*time.Second),
	}
	for _, a := range cases {
		want := fmtAttr(a)
		got := fmtAttr(p.redactAttr(a))
		if got != want {
			t.Errorf("scalar %s: got %q, want %q", a.Key, got, want)
		}
	}
}

func TestWalkAttr_DepthBoundFailsClosed(t *testing.T) {
	t.Parallel()

	// Rule `a.b.c.d.e` forces descent through five levels of non-leaf
	// transitions. With maxDepth=2, the walker must bail before reaching the
	// secret leaf and replace the offending node with the censor token.
	p := mustCompile(t, []string{"a.b.c.d.e"}, "***")
	v := slog.Attr{Key: "a", Value: slog.GroupValue(
		slog.Attr{Key: "b", Value: slog.GroupValue(
			slog.Attr{Key: "c", Value: slog.GroupValue(
				slog.Attr{Key: "d", Value: slog.GroupValue(
					slog.String("e", "leak-me"),
				)},
			)},
		)},
	)}
	st := &walkState{maxNodes: 1000, maxDepth: 2}
	got := fmtAttr(p.walkAttr(v, []*trieNode{p.root}, 0, st))
	// Top-level walkAttr starts at depth=0; depth>maxDepth triggers at the
	// fourth recursive call (a@0→b@1→c@2→d@3). "d" becomes censor and the
	// leaf below is never visited.
	if !strings.Contains(got, "d=***") {
		t.Errorf("expected `d=***` (fail-closed at depth bound), got %q", got)
	}
	if strings.Contains(got, "leak-me") {
		t.Errorf("secret leaked past depth bound: %q", got)
	}
}

func TestWalkAttr_NodeCountBoundFailsClosed(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"top.*"}, "***")
	// 50 children; node budget = 5 → the bulk should be censored.
	children := make([]slog.Attr, 50)
	for i := range children {
		children[i] = slog.String("k", "v") // identical keys are fine for this test
	}
	v := slog.Attr{Key: "top", Value: slog.GroupValue(children...)}
	st := &walkState{maxNodes: 5, maxDepth: 100}

	got := fmtAttr(p.walkAttr(v, []*trieNode{p.root}, 0, st))
	if !strings.Contains(got, "k=***") {
		t.Errorf("expected censoring, got %q", got)
	}
}

func TestRedactValue_NilOrEmptyProgram(t *testing.T) {
	t.Parallel()

	v := slog.GroupValue(slog.String("password", "secret"))
	want := fmtValue(v)

	var pNil *Program
	if got := fmtValue(pNil.redactValue(v)); got != want {
		t.Errorf("nil program: got %q, want %q", got, want)
	}
	pEmpty := mustCompile(t, nil, "***")
	if got := fmtValue(pEmpty.redactValue(v)); got != want {
		t.Errorf("empty program: got %q, want %q", got, want)
	}
}

func TestRedactValue_NonGroupPassThrough(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"password"}, "***")
	// A scalar value at the top level has no key context — pass through.
	got := fmtValue(p.redactValue(slog.StringValue("hello")))
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestWalkValue_DepthBoundFailsClosed(t *testing.T) {
	t.Parallel()

	// walkValue is the no-key entry; it has its own depth/node guards. With
	// maxDepth=0 the very first call exceeds the bound and must return the
	// censor scalar in place of the group.
	p := mustCompile(t, nil, "***")
	v := slog.GroupValue(slog.String("k", "v"))
	st := &walkState{maxNodes: 100, maxDepth: -1}
	got := fmtValue(p.walkValue(v, []*trieNode{p.root}, 0, st))
	if got != "***" {
		t.Errorf("expected censor scalar, got %q", got)
	}
}

func TestRedactValue_GroupWalksChildren(t *testing.T) {
	t.Parallel()

	p := mustCompile(t, []string{"password"}, "***")
	v := slog.GroupValue(
		slog.String("password", "hunter2"),
		slog.String("user", "alice"),
	)
	got := fmtValue(p.redactValue(v))
	want := "{password=***,user=alice}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRedactAttr_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	// Build an input then snapshot its rendering. After walking, the input
	// must render identically — the walker may not share backing storage in
	// a way that lets the output's mutations leak back.
	p := mustCompile(t, []string{"req.body.password"}, "***")
	in := slog.Attr{Key: "req", Value: slog.GroupValue(
		slog.Attr{Key: "body", Value: slog.GroupValue(
			slog.String("password", "hunter2"),
			slog.String("user", "alice"),
		)},
	)}
	snapshot := fmtAttr(in)
	_ = p.redactAttr(in)
	if got := fmtAttr(in); got != snapshot {
		t.Errorf("walker mutated input:\n before %q\n after  %q", snapshot, got)
	}
}

// --- benchmarks ---

func BenchmarkWalkAttr_NoMatch(b *testing.B) {
	// One group, five string attrs, no rule fires. Architecture §6.8 target:
	// < 150 ns/op, 0 allocs/op.
	p := mustCompileB(b, []string{"req.body.password"}, "***")
	a := slog.Attr{Key: "other", Value: slog.GroupValue(
		slog.String("k1", "v1"),
		slog.String("k2", "v2"),
		slog.String("k3", "v3"),
		slog.String("k4", "v4"),
		slog.String("k5", "v5"),
	)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.redactAttr(a)
	}
}

func BenchmarkWalkAttr_LeafMatch(b *testing.B) {
	// One leaf rewrite at the top level. Architecture §6.8 target:
	// < 400 ns/op, ≤ 1 alloc.
	p := mustCompileB(b, []string{"password"}, "***")
	a := slog.String("password", "hunter2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.redactAttr(a)
	}
}

func BenchmarkWalkAttr_NestedMatch(b *testing.B) {
	// 3-deep nested group with one leaf rewrite. Architecture §6.8 target:
	// < 900 ns/op, ≤ 2 allocs.
	p := mustCompileB(b, []string{"req.body.password"}, "***")
	a := slog.Attr{Key: "req", Value: slog.GroupValue(
		slog.Attr{Key: "body", Value: slog.GroupValue(
			slog.String("password", "hunter2"),
			slog.String("user", "alice"),
		)},
	)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.redactAttr(a)
	}
}

// mustCompileB is the benchmark-side mirror of mustCompile (testing.TB-typed
// helpers exist but the *testing.T helpers in compile_test.go take t.Helper(),
// and *testing.B doesn't satisfy that wider signature comfortably).
func mustCompileB(b *testing.B, paths []string, censor string) *Program {
	b.Helper()
	p, err := compile(paths, censor)
	if err != nil {
		b.Fatalf("compile failed: %v", err)
	}
	return p
}
