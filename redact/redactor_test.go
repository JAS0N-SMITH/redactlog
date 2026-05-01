package redact

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"
)

func TestNew_DefaultCensor(t *testing.T) {
	t.Parallel()

	e, err := New([]string{"password"}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := fmtAttr(e.RedactValue(slog.GroupValue(slog.String("password", "secret"))).Group()[0])
	if got != "password=***" {
		t.Errorf("default censor: got %q, want %q", got, "password=***")
	}
}

func TestNew_CustomCensor(t *testing.T) {
	t.Parallel()

	e, err := New([]string{"password"}, Options{Censor: "[REDACTED]"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := fmtAttr(e.RedactValue(slog.GroupValue(slog.String("password", "secret"))).Group()[0])
	if got != "password=[REDACTED]" {
		t.Errorf("custom censor: got %q, want %q", got, "password=[REDACTED]")
	}
}

func TestNew_InvalidPathReturnsError(t *testing.T) {
	t.Parallel()

	_, err := New([]string{"a.b", "a.**"}, Options{})
	if err == nil {
		t.Fatal("expected error from invalid path")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Errorf("error %v does not wrap ErrInvalidPath", err)
	}
}

func TestNew_EmptyPathsValid(t *testing.T) {
	t.Parallel()

	e, err := New(nil, Options{})
	if err != nil {
		t.Fatalf("New(nil) failed: %v", err)
	}
	if e == nil || e.prog == nil {
		t.Fatal("expected non-nil Engine and Program")
	}
	// With no rules, Redact and RedactValue pass through.
	in := slog.String("password", "secret")
	if got := fmtAttr(e.RedactValue(slog.GroupValue(in)).Group()[0]); got != "password=secret" {
		t.Errorf("empty-rules RedactValue should pass through: %q", got)
	}
}

// stubDetector is a Detector used to verify the interface compiles and is
// stored by New. It does not implement actual detection logic — the walker
// does not yet dispatch to detectors (that lands in M6).
type stubDetector struct{ name string }

func (s stubDetector) Name() string                 { return s.name }
func (s stubDetector) Detect(string) (string, bool) { return "", false }

func TestNew_DetectorsCopied(t *testing.T) {
	t.Parallel()

	dets := []Detector{stubDetector{name: "first"}, stubDetector{name: "second"}}
	e, err := New(nil, Options{Detectors: dets})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(e.detectors) != 2 {
		t.Fatalf("expected 2 detectors stored, got %d", len(e.detectors))
	}

	// Mutating the caller's slice must not affect the engine.
	dets[0] = stubDetector{name: "mutated"}
	if e.detectors[0].Name() != "first" {
		t.Errorf("Engine detectors not isolated from caller mutation: %q", e.detectors[0].Name())
	}
}

func TestEngine_NilSafety(t *testing.T) {
	t.Parallel()

	var e *Engine
	if got := e.Program(); got != nil {
		t.Errorf("nil Engine.Program() = %v, want nil", got)
	}
	v := slog.StringValue("hello")
	if got := e.RedactValue(v); got.String() != "hello" {
		t.Errorf("nil Engine.RedactValue mutated input: %v", got)
	}
	in := map[string]any{"k": "v"}
	if got := e.Redact(in); !reflect.DeepEqual(got, in) {
		t.Errorf("nil Engine.Redact: got %v, want %v", got, in)
	}
}

func TestEngine_Program_ReturnsCompiledTrie(t *testing.T) {
	t.Parallel()

	e, err := New([]string{"a.b", "a.c"}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := e.Program()
	if p == nil {
		t.Fatal("Program() returned nil")
	}
	if p.numRules != 2 {
		t.Errorf("numRules = %d, want 2", p.numRules)
	}
}

func TestEngine_RedactValue_NestedMatch(t *testing.T) {
	t.Parallel()

	e, _ := New([]string{"req.body.password"}, Options{})
	v := slog.GroupValue(slog.Attr{Key: "req", Value: slog.GroupValue(
		slog.Attr{Key: "body", Value: slog.GroupValue(
			slog.String("password", "hunter2"),
			slog.String("user", "alice"),
		)},
	)})
	got := fmtValue(e.RedactValue(v))
	want := "{req={body={password=***,user=alice}}}"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestEngine_Redact_MapPath(t *testing.T) {
	t.Parallel()

	e, _ := New([]string{"password"}, Options{})
	in := map[string]any{
		"password": "hunter2",
		"user":     "alice",
	}
	out := e.Redact(in).(map[string]any)
	if out["password"] != "***" {
		t.Errorf("password not redacted: %v", out["password"])
	}
	if out["user"] != "alice" {
		t.Errorf("user mutated: %v", out["user"])
	}
}

func TestEngine_Redact_NestedMap(t *testing.T) {
	t.Parallel()

	e, _ := New([]string{"req.body.password"}, Options{})
	in := map[string]any{
		"req": map[string]any{
			"body": map[string]any{
				"password": "hunter2",
				"user":     "alice",
			},
			"method": "POST",
		},
	}
	out := e.Redact(in).(map[string]any)
	body := out["req"].(map[string]any)["body"].(map[string]any)
	if body["password"] != "***" {
		t.Errorf("nested password not redacted: %v", body["password"])
	}
	if body["user"] != "alice" {
		t.Errorf("user mutated: %v", body["user"])
	}
	if out["req"].(map[string]any)["method"] != "POST" {
		t.Errorf("non-matching key mutated")
	}
}

func TestEngine_Redact_ArrayWildcardElementField(t *testing.T) {
	t.Parallel()

	// Rule users[*].password: redact `password` on every array element.
	e, _ := New([]string{"users[*].password"}, Options{})
	in := map[string]any{
		"users": []any{
			map[string]any{"id": 1, "password": "p1"},
			map[string]any{"id": 2, "password": "p2"},
		},
	}
	out := e.Redact(in).(map[string]any)
	users := out["users"].([]any)
	for i, u := range users {
		m := u.(map[string]any)
		if m["password"] != "***" {
			t.Errorf("users[%d].password not redacted: %v", i, m["password"])
		}
		if m["id"] != i+1 {
			t.Errorf("users[%d].id mutated: %v", i, m["id"])
		}
	}
}

func TestEngine_Redact_TerminalArrayWildcard(t *testing.T) {
	t.Parallel()

	// Rule cards[*]: redact every element of cards.
	e, _ := New([]string{"cards[*]"}, Options{})
	in := map[string]any{
		"cards": []any{"4111111111111111", "5555555555554444"},
	}
	out := e.Redact(in).(map[string]any)
	cards := out["cards"].([]any)
	for i, c := range cards {
		if c != "***" {
			t.Errorf("cards[%d] not redacted: %v", i, c)
		}
	}
}

func TestEngine_Redact_KeyMatchesLeaf_RedactsWholeValue(t *testing.T) {
	t.Parallel()

	// Rule "secrets" matches the key whose value is a map; the entire map
	// becomes the censor scalar.
	e, _ := New([]string{"secrets"}, Options{})
	in := map[string]any{
		"secrets": map[string]any{"a": 1, "b": 2},
		"name":    "alice",
	}
	out := e.Redact(in).(map[string]any)
	if out["secrets"] != "***" {
		t.Errorf("secrets not redacted to scalar: %v", out["secrets"])
	}
	if out["name"] != "alice" {
		t.Errorf("name mutated: %v", out["name"])
	}
}

func TestEngine_Redact_ScalarPassThrough(t *testing.T) {
	t.Parallel()

	e, _ := New([]string{"password"}, Options{})
	cases := []any{42, true, 3.14, "hello", nil, []byte{1, 2, 3}}
	for _, c := range cases {
		out := e.Redact(c)
		if !reflect.DeepEqual(out, c) {
			t.Errorf("scalar %v (%T) mutated: %v", c, c, out)
		}
	}
}

func TestEngine_Redact_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	e, _ := New([]string{"req.body.password", "users[*].token"}, Options{})
	in := map[string]any{
		"req": map[string]any{
			"body": map[string]any{"password": "secret-1"},
		},
		"users": []any{
			map[string]any{"token": "tok-1"},
			map[string]any{"token": "tok-2"},
		},
	}
	_ = e.Redact(in)

	// Verify originals unchanged.
	if in["req"].(map[string]any)["body"].(map[string]any)["password"] != "secret-1" {
		t.Error("input password mutated")
	}
	if in["users"].([]any)[0].(map[string]any)["token"] != "tok-1" {
		t.Error("input users[0].token mutated")
	}
}

func TestEngine_Redact_DepthBoundFailsClosed(t *testing.T) {
	t.Parallel()

	e, _ := New([]string{"a.b.c.d.e"}, Options{})
	in := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": map[string]any{
					"d": map[string]any{
						"e": "leak-me",
					},
				},
			},
		},
	}
	// Force fail-closed: maxDepth too small to reach the leaf.
	st := &walkState{maxNodes: 1000, maxDepth: 2}
	got := e.redactAny(in, []*trieNode{e.prog.root}, 0, st).(map[string]any)
	// Walk down until we hit the censor scalar.
	cur := any(got)
	for _, k := range []string{"a", "b", "c"} {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("expected map at %q, got %T", k, cur)
		}
		cur = m[k]
	}
	if cur != "***" {
		t.Errorf("expected censor scalar at depth bound, got %v", cur)
	}
	// Verify the original value was never copied through.
	if reflect.DeepEqual(cur, "leak-me") {
		t.Error("secret leaked past depth bound")
	}
}

func TestEngine_Redact_WildcardBranches(t *testing.T) {
	t.Parallel()

	// Rule `*.password` exercises advanceForKey's wildChild-non-leaf branch
	// (descend through wildcard) and the subsequent leaf match. The slice
	// under "list" has no wildcard rule reaching into it — that exercises
	// advanceForArray's wildChild==nil branch (pass slice through).
	e, _ := New([]string{"*.password"}, Options{})
	in := map[string]any{
		"user": map[string]any{"password": "x", "name": "alice"},
		"list": []any{1, 2, 3},
	}
	out := e.Redact(in).(map[string]any)
	user := out["user"].(map[string]any)
	if user["password"] != "***" {
		t.Errorf("password not redacted via wildcard: %v", user["password"])
	}
	if user["name"] != "alice" {
		t.Errorf("name mutated: %v", user["name"])
	}
	if !reflect.DeepEqual(out["list"], []any{1, 2, 3}) {
		t.Errorf("slice with no applicable wildcard should pass through: %v", out["list"])
	}

	// Top-level `*` puts the wildChild leaf flag at the root, exercising
	// advanceForKey's wildChild-leaf branch.
	e2, _ := New([]string{"*"}, Options{})
	in2 := map[string]any{"a": 1, "b": 2}
	out2 := e2.Redact(in2).(map[string]any)
	if out2["a"] != "***" || out2["b"] != "***" {
		t.Errorf("top-level `*` should redact every key: %v", out2)
	}
}

// --- benchmarks (per v1roadmap §M2) ---

// BenchmarkRedact_Flat10 redacts one of ten flat string attrs — the
// "log line with a single PII field" workload.
func BenchmarkRedact_Flat10(b *testing.B) {
	e, err := New([]string{"password"}, Options{})
	if err != nil {
		b.Fatal(err)
	}
	v := slog.GroupValue(
		slog.String("k0", "v0"),
		slog.String("k1", "v1"),
		slog.String("k2", "v2"),
		slog.String("k3", "v3"),
		slog.String("k4", "v4"),
		slog.String("password", "hunter2"),
		slog.String("k6", "v6"),
		slog.String("k7", "v7"),
		slog.String("k8", "v8"),
		slog.String("k9", "v9"),
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.RedactValue(v)
	}
}

// BenchmarkRedact_Nested5x5 redacts one leaf in a 5-deep × 5-wide group
// tree. v1roadmap §M2 definition-of-done target: ≤ 1.5 µs/op.
func BenchmarkRedact_Nested5x5(b *testing.B) {
	e, err := New([]string{"a.a.a.a.a"}, Options{})
	if err != nil {
		b.Fatal(err)
	}
	v := buildNested5x5()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.RedactValue(v)
	}
}

// BenchmarkRedact_1KBJSON redacts a roughly-1KB JSON-decoded payload via
// Engine.Redact(any) — the body-capture entry path the M4 middleware will
// drive.
func BenchmarkRedact_1KBJSON(b *testing.B) {
	e, err := New([]string{
		"user.password",
		"user.ssn",
		"users[*].token",
		"creditcard.*",
	}, Options{})
	if err != nil {
		b.Fatal(err)
	}
	payload := build1KBJSON()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Redact(payload)
	}
}

// buildNested5x5 returns a 5-level nested group where each level holds five
// attrs named a–e. The "a" branch chains all the way down; siblings b–e are
// scalars at every level so the walker exercises both descent and
// pass-through on every step.
func buildNested5x5() slog.Value {
	v := slog.GroupValue(
		slog.String("a", "secret"),
		slog.String("b", "v"),
		slog.String("c", "v"),
		slog.String("d", "v"),
		slog.String("e", "v"),
	)
	for d := 0; d < 4; d++ {
		v = slog.GroupValue(
			slog.Attr{Key: "a", Value: v},
			slog.String("b", "v"),
			slog.String("c", "v"),
			slog.String("d", "v"),
			slog.String("e", "v"),
		)
	}
	return v
}

// build1KBJSON returns a map[string]any whose JSON encoding is on the order
// of 1 KB, shaped like a typical fintech HTTP request body (user record +
// credit card + array of nested users + metadata).
func build1KBJSON() map[string]any {
	return map[string]any{
		"user": map[string]any{
			"id":       12345,
			"name":     "Alice Smith",
			"email":    "alice@example.test",
			"password": "hunter2-very-secret",
			"ssn":      "000-00-0000",
			"address": map[string]any{
				"street": "123 Main St",
				"city":   "Springfield",
				"zip":    "12345",
			},
		},
		"creditcard": map[string]any{
			"number":    "4111111111111111",
			"cvv":       "123",
			"exp_month": 12,
			"exp_year":  2030,
			"holder":    "Alice Smith",
		},
		"users": []any{
			map[string]any{"id": 1, "token": "tok-abcdef", "role": "admin"},
			map[string]any{"id": 2, "token": "tok-ghijkl", "role": "viewer"},
			map[string]any{"id": 3, "token": "tok-mnopqr", "role": "editor"},
		},
		"metadata": map[string]any{
			"request_id": "req-12345abcdef",
			"timestamp":  "2026-04-25T12:00:00Z",
			"user_agent": "go-test/1.0",
		},
	}
}

func ExampleNew() {
	e, err := New([]string{"user.password"}, Options{})
	if err != nil {
		panic(err)
	}
	v := slog.GroupValue(
		slog.Attr{Key: "user", Value: slog.GroupValue(
			slog.String("name", "alice"),
			slog.String("password", "hunter2"),
		)},
	)
	_ = e.RedactValue(v)
	// The redacted value's "password" attr now holds "***" instead of
	// "hunter2"; non-matching attrs round-trip unchanged.
}

// ExampleEngine_Redact demonstrates the Engine.Redact method on a map[string]any,
// which is the body-capture pipeline used by the HTTP middleware.
// It shows how path-based redaction and content-based detectors (like Luhn PAN detection)
// work together on unstructured JSON data.
func ExampleEngine_Redact() {
	// Construct an Engine with PCI paths and the PAN detector.
	e, err := New(
		[]string{"payment.cvv", "payment.pin"},
		Options{
			Censor:    DefaultCensor,
			Detectors: []Detector{PANDetector()},
		},
	)
	if err != nil {
		panic(err)
	}

	// Simulate a payment request body (as map[string]any from json.Unmarshal).
	body := map[string]interface{}{
		"payment": map[string]interface{}{
			"pan": "4111111111111111", // Matches via PAN detector (Luhn)
			"cvv": "123",              // Matches via path "payment.cvv"
			"pin": "5678",             // Matches via path "payment.pin"
		},
		"user": map[string]interface{}{
			"name": "alice", // Does not match any path or detector
		},
	}

	// Redact the body in-place.
	redacted := e.Redact(body)

	// After redaction:
	// - payment.pan → "411111******1111" (Luhn detection + masking)
	// - payment.cvv → "***" (path match)
	// - payment.pin → "***" (path match)
	// - user.name → "alice" (unchanged)
	_ = redacted
}
