package redact

import "log/slog"

// Default walk limits. They cap per-call work to prevent runaway recursion or
// memory blowups on adversarial input. Both apply as hard caps; on excess the
// walker fails closed (replaces the offending attribute with the censor token)
// per architecture §12.1.
const (
	defaultMaxDepth = 32
	defaultMaxNodes = 10000
)

// walkState carries per-call counters across the recursive walk. A fresh
// state is allocated for each top-level redaction call so concurrent walks
// do not share counters.
type walkState struct {
	nodes    int
	maxNodes int
	maxDepth int
}

// redactAttr is the walker's entry point for a single attribute. It returns a
// (possibly redacted) attribute and never mutates the input.
//
// A nil program (or one with no rules) is treated as a no-op — the input is
// returned unchanged after a [slog.Value.Resolve] of any [slog.LogValuer].
func (p *Program) redactAttr(a slog.Attr) slog.Attr {
	if p == nil || p.root == nil {
		return a
	}
	st := walkState{maxNodes: defaultMaxNodes, maxDepth: defaultMaxDepth}
	return p.walkAttr(a, []*trieNode{p.root}, 0, &st)
}

// redactValue is the walker's entry point for a [slog.Value]. Non-group
// values have no key context to match against and are returned unchanged
// (after [slog.Value.Resolve]). Group values have each child walked against
// the trie root.
func (p *Program) redactValue(v slog.Value) slog.Value {
	if p == nil || p.root == nil {
		return v
	}
	st := walkState{maxNodes: defaultMaxNodes, maxDepth: defaultMaxDepth}
	return p.walkValue(v, []*trieNode{p.root}, 0, &st)
}

// walkAttr applies the trie at the active states to attr a.
//
// Multi-state design: when both an exact-key transition and a wildcard
// transition could apply concurrently, single-state walking under-redacts
// overlap cases (e.g. rules `a.b.password` and `a.*.token` both apply to
// `a.b.token`). CLAUDE.md §10 requires fail-closed behavior on ambiguity,
// so we track the set of active trie positions and consult all of them at
// each step.
//
// HOT: walkAttr is called once per top-level attribute by the slog handler
// and recursively for every nested group attribute. The no-match path is
// allocation-free.
func (p *Program) walkAttr(a slog.Attr, states []*trieNode, depth int, st *walkState) slog.Attr {
	st.nodes++
	if st.nodes > st.maxNodes || depth > st.maxDepth {
		return slog.String(a.Key, p.censor)
	}

	a.Value = a.Value.Resolve()

	var next []*trieNode
	for _, n := range states {
		if c := n.children[a.Key]; c != nil {
			if c.leaf {
				return slog.String(a.Key, p.censor)
			}
			next = append(next, c)
		}
		if n.wildChild != nil {
			if n.wildChild.leaf {
				return slog.String(a.Key, p.censor)
			}
			next = append(next, n.wildChild)
		}
	}

	if len(next) == 0 || a.Value.Kind() != slog.KindGroup {
		return a
	}

	attrs := a.Value.Group()
	out := make([]slog.Attr, len(attrs))
	for i, sub := range attrs {
		out[i] = p.walkAttr(sub, next, depth+1, st)
	}
	return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
}

// walkValue handles the no-key entry case used by [Engine.RedactValue]. For
// non-group values there is nothing to match against; for groups, each child
// attribute is walked against the supplied trie states.
func (p *Program) walkValue(v slog.Value, states []*trieNode, depth int, st *walkState) slog.Value {
	st.nodes++
	if st.nodes > st.maxNodes || depth > st.maxDepth {
		return slog.StringValue(p.censor)
	}
	v = v.Resolve()
	if v.Kind() != slog.KindGroup {
		return v
	}
	attrs := v.Group()
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = p.walkAttr(a, states, depth+1, st)
	}
	return slog.GroupValue(out...)
}
