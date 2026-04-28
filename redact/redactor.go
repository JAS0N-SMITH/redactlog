package redact

import "log/slog"

// DefaultCensor is the replacement token used when [Options.Censor] is empty.
// It matches Pino's de-facto convention for terse, visually obvious redaction
// (architecture §6.6 / ADR-008).
const DefaultCensor = "***"

// Engine is a compiled, immutable redactor produced by [New]. A single Engine
// is safe for concurrent use by any number of callers; share one across the
// lifetime of your service rather than constructing per request.
type Engine struct {
	prog      *Program
	detectors []Detector
}

// Options configure an [Engine] at construction time. Zero values are safe
// defaults: empty Censor falls back to [DefaultCensor]; a nil Detectors slice
// runs no detectors.
type Options struct {
	// Censor is the replacement token written in place of redacted values.
	// Empty value falls back to [DefaultCensor]. Non-empty values are stored
	// verbatim — callers are responsible for choosing a token that does not
	// collide with legitimate field values.
	Censor string

	// Detectors run after path matching on string leaves that survived path
	// redaction. v1 ships no detectors by default; the PCI preset (M6)
	// supplies the PAN detector. The slice is copied at construction so
	// post-construction mutation has no effect.
	Detectors []Detector
}

// Redactor is the minimal interface for redacting a [slog.Value]. The concrete
// [Engine] satisfies it; tests and callers that only need the slog hot path
// can depend on this interface to substitute mocks or alternate
// implementations.
type Redactor interface {
	RedactValue(v slog.Value) slog.Value
}

// Detector runs content-based redaction on string leaves that survive path
// matching. v1 ships no built-in detectors by default; the PCI preset
// supplies the PAN detector.
type Detector interface {
	// Name identifies the detector in diagnostic output (e.g., "pan", "email").
	// It must never appear in redacted log lines.
	Name() string
	// Detect inspects s and returns (replacement, matched). When matched is
	// false the caller must pass s through unchanged. Implementations must
	// not panic on malformed input — the redaction path is safety-critical
	// per CLAUDE.md §10.
	Detect(s string) (replacement string, matched bool)
}

// Compile-time assertion that *Engine satisfies the Redactor interface so a
// breaking signature change is caught by `go vet` rather than at first use.
var _ Redactor = (*Engine)(nil)

// New compiles paths into an [Engine]. The returned Engine is immutable and
// safe for concurrent use. Errors wrap [ErrInvalidPath] for any path that
// fails to parse; the wrapping message includes the offending path and column
// for diagnostics.
//
// An empty paths slice is legal and produces an Engine that performs only
// detector-based redaction (or pass-through, if no detectors are configured).
//
// Options.Censor defaults to [DefaultCensor] when empty. Options.Detectors is
// copied; modifying the caller's slice after New returns has no effect on
// the Engine.
func New(paths []string, opts Options) (*Engine, error) {
	censor := opts.Censor
	if censor == "" {
		censor = DefaultCensor
	}
	prog, err := compile(paths, censor)
	if err != nil {
		return nil, err
	}
	var detectors []Detector
	if len(opts.Detectors) > 0 {
		detectors = make([]Detector, len(opts.Detectors))
		copy(detectors, opts.Detectors)
	}
	prog.detectors = detectors
	return &Engine{prog: prog, detectors: detectors}, nil
}

// Program returns the compiled rule trie. The returned value is opaque except
// for its [Program.String] method, which produces a short summary suitable
// for pprof labels. A nil Engine returns nil.
func (e *Engine) Program() *Program {
	if e == nil {
		return nil
	}
	return e.prog
}

// RedactValue returns a redacted copy of v. It is the hot-path entry used by
// the slog handler wrapper and is safe to call on a nil Engine (returns v
// unchanged).
//
// HOT: called once per [slog.Record] by the handler.
func (e *Engine) RedactValue(v slog.Value) slog.Value {
	if e == nil || e.prog == nil {
		return v
	}
	return e.prog.redactValue(v)
}

// Redact returns a redacted copy of v without mutating the input. It walks
// the structural shapes a JSON decode produces:
//
//   - map[string]any — recursed; keys form trie path segments.
//   - []any          — recursed; the array wildcard `[*]` matches every element.
//   - any other type — returned unchanged. There is no runtime reflection
//     (CLAUDE.md §2): callers needing other shapes should restructure as
//     map[string]any, implement [slog.LogValuer], or use [Engine.RedactValue]
//     with [slog.Value] inputs.
//
// Redact is the entry point used by the HTTP middleware's body-capture
// pipeline (M4). A nil Engine is a safe no-op.
func (e *Engine) Redact(v any) any {
	if e == nil || e.prog == nil || e.prog.root == nil {
		return v
	}
	st := walkState{maxNodes: defaultMaxNodes, maxDepth: defaultMaxDepth}
	return e.redactAny(v, []*trieNode{e.prog.root}, 0, &st)
}

// RedactAttrInGroups redacts a single [slog.Attr] as if it were nested under
// the given group path segments. Used by the slog [Handler] wrapper to honor
// DSL paths that begin with a group prefix accumulated via [Handler.WithGroup].
//
// For example, a DSL path `req.body.password` is matched by first advancing
// the trie through group names ["req", "body"] and then walking the attribute
// key against the resulting trie positions.
//
// A nil Engine returns the attribute unchanged.
func (e *Engine) RedactAttrInGroups(a slog.Attr, groups []string) slog.Attr {
	if e == nil || e.prog == nil || e.prog.root == nil {
		return a
	}
	st := walkState{maxNodes: defaultMaxNodes, maxDepth: defaultMaxDepth}
	states := []*trieNode{e.prog.root}
	for _, g := range groups {
		next, leaf := advanceForKey(states, g)
		if leaf {
			// The entire group is a redact target — replace the whole attribute value.
			return slog.String(a.Key, e.prog.censor)
		}
		if len(next) == 0 {
			// No rule can match under this group prefix; pass through.
			return a
		}
		states = next
	}
	return e.prog.walkAttr(a, states, 0, &st)
}

// applyDetectorsToString passes s through each detector in sequence, updating
// s when a detector fires. It is used by [Engine.Redact] for string values
// that survive path matching.
func (e *Engine) applyDetectorsToString(s string) string {
	for _, d := range e.detectors {
		if rep, ok := d.Detect(s); ok {
			s = rep
		}
	}
	return s
}

// redactAny is the recursive walker behind [Engine.Redact]. The multi-state
// design mirrors [Program.walkAttr]; see walk.go for the rationale.
//
// When states is nil (or empty), no path rules apply for this subtree. The
// walk still recurses into nested containers so that detectors can reach all
// string leaves. This is the "detector-only" mode entered whenever the trie
// has no matching transition for a given key or array element.
func (e *Engine) redactAny(v any, states []*trieNode, depth int, st *walkState) any {
	st.nodes++
	if st.nodes > st.maxNodes || depth > st.maxDepth {
		return e.prog.censor
	}
	switch x := v.(type) {
	case map[string]any:
		return e.redactMap(x, states, depth, st)
	case []any:
		return e.redactSlice(x, states, depth, st)
	default:
		if s, ok := v.(string); ok && len(e.detectors) > 0 {
			return e.applyDetectorsToString(s)
		}
		return v
	}
}

// redactMap walks a map[string]any against the active trie states.
func (e *Engine) redactMap(x map[string]any, states []*trieNode, depth int, st *walkState) any {
	out := make(map[string]any, len(x))
	for k, sub := range x {
		if len(states) == 0 {
			out[k] = e.redactAny(sub, nil, depth+1, st)
			continue
		}
		next, leaf := advanceForKey(states, k)
		switch {
		case leaf:
			out[k] = e.prog.censor
		case len(next) == 0:
			// Trie has no further match; switch to detector-only for this subtree.
			out[k] = e.redactAny(sub, nil, depth+1, st)
		default:
			out[k] = e.redactAny(sub, next, depth+1, st)
		}
	}
	return out
}

// redactSlice walks a []any against the active trie states.
func (e *Engine) redactSlice(x []any, states []*trieNode, depth int, st *walkState) any {
	if len(states) == 0 {
		out := make([]any, len(x))
		for i, sub := range x {
			out[i] = e.redactAny(sub, nil, depth+1, st)
		}
		return out
	}
	next, leaf := advanceForArray(states)
	out := make([]any, len(x))
	switch {
	case leaf:
		for i := range out {
			out[i] = e.prog.censor
		}
	case len(next) == 0:
		// No array-wildcard rule; switch to detector-only for each element.
		for i, sub := range x {
			out[i] = e.redactAny(sub, nil, depth+1, st)
		}
	default:
		for i, sub := range x {
			out[i] = e.redactAny(sub, next, depth+1, st)
		}
	}
	return out
}

// advanceForKey advances active trie states by one named segment. Used by
// [Engine.Redact] for map[string]any keys; the slog hot path inlines the
// equivalent logic in walkAttr to preserve its zero-alloc no-match
// guarantee.
func advanceForKey(states []*trieNode, key string) (next []*trieNode, leaf bool) {
	for _, n := range states {
		if c := n.children[key]; c != nil {
			if c.leaf {
				return nil, true
			}
			next = append(next, c)
		}
		if n.wildChild != nil {
			if n.wildChild.leaf {
				return nil, true
			}
			next = append(next, n.wildChild)
		}
	}
	return next, false
}

// advanceForArray advances active trie states by following each wildChild
// (the `.*` / `[*]` slot collapsed at compile time per architecture §6.4).
// Used by [Engine.Redact] for []any elements.
func advanceForArray(states []*trieNode) (next []*trieNode, leaf bool) {
	for _, n := range states {
		if n.wildChild == nil {
			continue
		}
		if n.wildChild.leaf {
			return nil, true
		}
		next = append(next, n.wildChild)
	}
	return next, false
}
