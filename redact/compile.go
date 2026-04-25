package redact

import "fmt"

// Program is the immutable compiled output of [New] for a set of DSL paths.
// Once produced it is safe for concurrent use by any number of redaction
// calls; the walker reads the trie without locking.
//
// Program is exposed by [Engine.Program] for debugging and pprof labels;
// callers should treat it as opaque. Only [Program.String] is part of the
// stable API.
type Program struct {
	root     *trieNode
	censor   string
	numRules int
}

// String returns a short, fixed-format summary suitable for pprof labels.
func (p *Program) String() string {
	if p == nil {
		return "redact.Program(nil)"
	}
	return fmt.Sprintf("redact.Program{rules=%d, censor=%q}", p.numRules, p.censor)
}

// trieNode is one node in the compiled rule trie. It is allocated only by
// [compile] and never mutated after compile returns.
type trieNode struct {
	// children holds exact-key transitions (including bracket-quoted keys).
	// nil when no exact-key rules pass through this node.
	children map[string]*trieNode

	// wildChild is the transition shared by both `.*` and `[*]` segments.
	// Architecture §6.4 notes that under slog, arrays are KindAny holding a
	// slice — indistinguishable from object children at walk time — so
	// collapsing both wildcard forms into one slot avoids a false dichotomy.
	wildChild *trieNode

	// leaf is true when at least one DSL path terminates exactly at this
	// node. The walker, after consuming an attribute key, redacts when the
	// landing node has leaf == true.
	leaf bool
}

// compile parses each DSL path and folds the resulting segments into a trie.
// It returns the first parse error encountered (subsequent paths are not
// parsed) so configuration bugs surface at construction time per CLAUDE.md §5.
//
// An empty paths slice produces a Program whose trie has no transitions and
// no leaves; the walker treats it as a no-op. Duplicate paths are silently
// merged at the trie level but counted individually in numRules so debug
// output reflects what the caller wrote.
//
// The censor string is stored verbatim. Validation (non-empty etc.) is the
// caller's responsibility — the future Engine constructor enforces it.
func compile(paths []string, censor string) (*Program, error) {
	root := &trieNode{}
	for _, p := range paths {
		segs, err := parsePath(p)
		if err != nil {
			return nil, err
		}
		insert(root, segs)
	}
	return &Program{
		root:     root,
		censor:   censor,
		numRules: len(paths),
	}, nil
}

// insert folds one parsed path into the trie rooted at root, reusing existing
// prefix nodes and allocating only on novel tail segments. The terminal node
// is marked as a leaf.
func insert(root *trieNode, segs []segment) {
	n := root
	for _, s := range segs {
		switch s.kind {
		case segIdent:
			if n.children == nil {
				n.children = make(map[string]*trieNode)
			}
			child, ok := n.children[s.name]
			if !ok {
				child = &trieNode{}
				n.children[s.name] = child
			}
			n = child
		case segWild, segArrayWild:
			if n.wildChild == nil {
				n.wildChild = &trieNode{}
			}
			n = n.wildChild
		}
	}
	n.leaf = true
}
