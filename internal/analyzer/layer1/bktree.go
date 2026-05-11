package layer1

// Burkhardt-Keller tree for sub-linear edit-distance search against a fixed
// reference set (here: the top-N popular npm package names). Replaces the
// O(N) linear scan in TyposquatChecker.Check so we can lift the reference set
// from 10k to 100k without blowing the Layer 1 budget.
//
// Metric choice: the tree is built on plain Levenshtein distance, NOT
// Damerau-Levenshtein. Levenshtein satisfies the triangle inequality (a true
// metric), which BK-tree pruning needs to be correct. Damerau-Levenshtein
// with adjacent transposition (OSA) violates it on pathological cases, and a
// BK-tree built on OSA can silently miss valid matches.
//
// The cost: a transposition (e.g. "raect" vs "react") is Levenshtein-2, not
// DL-1. So we search with the looser warnDistance tolerance on Levenshtein,
// then for every returned candidate compute the true Damerau-Levenshtein in
// the caller to find the closest match. The candidate set is small (typically
// a handful of names) so the refinement is cheap.

type bkNode struct {
	word     string
	children map[int]*bkNode
}

// newBKTree builds a tree containing every word. Returns nil for an empty
// input so callers can treat "no reference set" as "no signals".
func newBKTree(words []string) *bkNode {
	if len(words) == 0 {
		return nil
	}
	root := &bkNode{word: words[0], children: map[int]*bkNode{}}
	for _, w := range words[1:] {
		root.insert(w)
	}
	return root
}

// insert places word under the node whose Levenshtein distance to it matches
// an existing edge; otherwise it creates a new edge. Duplicates (d=0) are a
// no-op.
func (n *bkNode) insert(word string) {
	d := levenshtein(n.word, word)
	if d == 0 {
		return
	}
	if c, ok := n.children[d]; ok {
		c.insert(word)
		return
	}
	n.children[d] = &bkNode{word: word, children: map[int]*bkNode{}}
}

// search collects every word in the tree whose Levenshtein distance to query
// is at most tol. Triangle-inequality pruning: at a node with distance d, a
// matching descendant must lie in children at edge-distance [d-tol, d+tol].
// Order of returned candidates is tree-traversal order, not sorted by
// distance.
func (n *bkNode) search(query string, tol int) []string {
	if n == nil {
		return nil
	}
	var out []string
	n.searchRec(query, tol, &out)
	return out
}

func (n *bkNode) searchRec(query string, tol int, out *[]string) {
	d := levenshtein(n.word, query)
	if d <= tol {
		*out = append(*out, n.word)
	}
	lo := d - tol
	if lo < 1 {
		lo = 1 // child edges are always > 0; d=0 children don't exist
	}
	hi := d + tol
	for childDist, child := range n.children {
		if childDist >= lo && childDist <= hi {
			child.searchRec(query, tol, out)
		}
	}
}

// levenshtein returns the plain Levenshtein distance (insert/delete/substitute,
// no transposition) between a and b. This is a true metric — needed for
// correct BK-tree pruning. For final ranking the caller applies
// damerauLevenshtein on a small candidate set.
func levenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la := len(ra)
	lb := len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Two-row DP — full matrix is unnecessary for distance-only output and
	// names rarely exceed 40 characters anyway.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = minInt3(
				curr[j-1]+1,    // insertion
				prev[j]+1,      // deletion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
