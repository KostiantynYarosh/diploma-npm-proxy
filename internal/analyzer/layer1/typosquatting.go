package layer1

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/yourusername/npm-proxy/internal/signal"
)

// asciiHomoglyphs maps ASCII look-alikes (digits, symbols) to their letter equivalent.
// A match here alone is not a veto: names like "react0" may be legitimate, so the
// signal is weighted via policy engine instead of blocking outright.
//
// Non-ASCII confusables (Cyrillic/Greek) are deliberately out of scope: the npm
// registry's validate-npm-package-name rejects non-ASCII at publish time, so
// proxy traffic for such names returns 404 from upstream and never reaches this
// detector in the first place.
var asciiHomoglyphs = map[rune]rune{
	'0': 'o', 'O': 'o',
	'1': 'l', 'I': 'l',
	'5': 's',
	'3': 'e',
	'@': 'a',
	'$': 's',
}

// minPopularScopeOccurrences is the cut-off for considering a scope "popular"
// enough to be a typosquat target. Derived from the top-N reference list at
// load time, not configurable: anything < this is just one company's vanity
// scope, not an attractive impersonation target.
const minPopularScopeOccurrences = 3

// TyposquatOptions bundles every score/threshold knob the checker reads. An
// option struct beats a long positional argument list — six fields was already
// awkward, and combosquat + scope-typosquat would push it to eleven.
type TyposquatOptions struct {
	CloseDistance       int
	CloseScore          float64
	WarnDistance        int
	WarnScore           float64
	ASCIIHomoglyphScore float64
	CombosquatScore     float64
	CombosquatMinSegLen int // 0 → 4 (skips noise from "js"/"lib"/"npm")
	ScopeCloseScore     float64
	ScopeWarnScore      float64
}

type TyposquatChecker struct {
	// BK-tree over the unscoped popular names. Built on plain Levenshtein so
	// the metric pruning is correct; refinement uses Damerau-Levenshtein.
	tree *bkNode

	// knownSet holds the bare (post-scope-strip) popular names for two O(1)
	// lookups Check() performs many times: exact-popular short-circuit and
	// combosquat segment matching.
	knownSet map[string]struct{}

	// popularScopes is the small set of scopes (e.g. "@types", "@babel") that
	// appear at least minPopularScopeOccurrences times in the reference list.
	// Tiny set ─ linear scan is fine.
	popularScopes    []string
	popularScopesSet map[string]struct{}

	closeDistance       int
	closeScore          float64
	warnDistance        int
	warnScore           float64
	asciiHomoglyphScore float64
	combosquatScore     float64
	combosquatMinSegLen int
	scopeCloseScore     float64
	scopeWarnScore      float64
}

func NewTyposquatChecker(top10kPath string, opts TyposquatOptions) (*TyposquatChecker, error) {
	rawNames, err := loadLines(top10kPath)
	if err != nil {
		return nil, err
	}

	bareSet := make(map[string]struct{}, len(rawNames))
	bareNames := make([]string, 0, len(rawNames))
	scopeCount := map[string]int{}
	for _, raw := range rawNames {
		full := strings.ToLower(norm.NFKC.String(strings.TrimSpace(raw)))
		if full == "" {
			continue
		}
		// Track scope occurrences before stripping so we can derive popular
		// scopes for the scope-typosquat check.
		if strings.HasPrefix(full, "@") {
			if idx := strings.Index(full, "/"); idx > 0 {
				scopeCount[full[:idx]]++
			}
		}
		bare := stripScope(full)
		if bare == "" {
			continue
		}
		if _, seen := bareSet[bare]; seen {
			continue
		}
		bareSet[bare] = struct{}{}
		bareNames = append(bareNames, bare)
	}

	popularScopes := make([]string, 0)
	popularScopesSet := map[string]struct{}{}
	for sc, n := range scopeCount {
		if n >= minPopularScopeOccurrences {
			popularScopes = append(popularScopes, sc)
			popularScopesSet[sc] = struct{}{}
		}
	}

	minSegLen := opts.CombosquatMinSegLen
	if minSegLen <= 0 {
		minSegLen = 4
	}

	return &TyposquatChecker{
		tree:                newBKTree(bareNames),
		knownSet:            bareSet,
		popularScopes:       popularScopes,
		popularScopesSet:    popularScopesSet,
		closeDistance:       opts.CloseDistance,
		closeScore:          opts.CloseScore,
		warnDistance:        opts.WarnDistance,
		warnScore:           opts.WarnScore,
		asciiHomoglyphScore: opts.ASCIIHomoglyphScore,
		combosquatScore:     opts.CombosquatScore,
		combosquatMinSegLen: minSegLen,
		scopeCloseScore:     opts.ScopeCloseScore,
		scopeWarnScore:      opts.ScopeWarnScore,
	}, nil
}

// Check applies, in order: scope typosquat (works on the original scoped
// name), exact-popular short-circuit, ASCII homoglyph match, combosquat
// detection, and Damerau-Levenshtein nearest-neighbour via the BK-tree.
// Multiple signals can fire for one package (e.g. scope typosquat + name
// typosquat), reflecting independent attack vectors that the policy engine
// then weighs.
func (t *TyposquatChecker) Check(_ context.Context, name string) []signal.Signal {
	lowered := strings.ToLower(norm.NFKC.String(name))
	var sigs []signal.Signal

	// Scope typosquat is checked first because it works on the *original*
	// scoped name — stripping the scope below would erase the evidence.
	if scopeSig := t.checkScope(lowered); scopeSig != nil {
		sigs = append(sigs, *scopeSig)
	}

	bare := stripScope(lowered)
	if bare == "" {
		return sigs
	}

	// Exact match: a known popular package. Scope check above already fired
	// if relevant; nothing else applies.
	if _, ok := t.knownSet[bare]; ok {
		return sigs
	}

	// ASCII homoglyph: high-weight match on de-glyphed bare name. We still
	// keep going to combosquat/distance below — a name can be both a glyph
	// substitution AND structurally similar to another popular name.
	if deglyphed, changed := deHomoglyph(bare, asciiHomoglyphs); changed {
		if _, ok := t.knownSet[deglyphed]; ok {
			sigs = append(sigs, signal.Signal{
				Rule:           "typosquat_ascii_homoglyph",
				Score:          t.asciiHomoglyphScore,
				MatchedPackage: deglyphed,
				Detail:         "ascii digit/symbol substitution matches popular package",
			})
			return sigs
		}
	}

	// Combosquat: edit-distance is blind to "react-fake" because the suffix
	// adds 5+ characters in one chunk. Splitting on common separators and
	// checking whether any segment is itself a popular package catches this
	// class without distance arithmetic.
	if t.combosquatScore > 0 {
		if seg := t.combosquatMatch(bare); seg != "" {
			sigs = append(sigs, signal.Signal{
				Rule:           "typosquat_combosquat",
				Score:          t.combosquatScore,
				MatchedPackage: seg,
				Detail:         "segment_match=" + seg,
			})
		}
	}

	// Edit-distance nearest neighbour via BK-tree (Levenshtein) + DL refine.
	// We over-fetch on Levenshtein with warnDistance tolerance, then pick the
	// best by Damerau-Levenshtein so a single transposition still counts as
	// distance 1 rather than the Levenshtein 2.
	if t.tree != nil {
		bestDist := -1
		var bestMatch string
		for _, c := range t.tree.search(bare, t.warnDistance) {
			d := damerauLevenshtein(bare, c)
			if d == 0 {
				continue
			}
			if d <= t.warnDistance && (bestDist == -1 || d < bestDist) {
				bestDist = d
				bestMatch = c
			}
		}
		if bestDist != -1 {
			rule := "typosquat_warn"
			score := t.warnScore
			if bestDist <= t.closeDistance {
				rule = "typosquat_close"
				score = t.closeScore
			}
			sigs = append(sigs, signal.Signal{
				Rule:           rule,
				Score:          score,
				MatchedPackage: bestMatch,
				Detail:         "edit_distance=" + itoa(bestDist),
			})
		}
	}

	return sigs
}

// checkScope returns a scope-typosquat signal when the input is scoped and
// its scope is edit-distance ≤ warnDistance from a popular scope without
// being an exact popular scope itself. Returns nil for non-scoped names,
// scopes < 3 chars (false-positive prone), or when no calibrated score is
// configured for the relevant tier.
func (t *TyposquatChecker) checkScope(loweredFull string) *signal.Signal {
	if !strings.HasPrefix(loweredFull, "@") {
		return nil
	}
	idx := strings.Index(loweredFull, "/")
	if idx <= 0 {
		return nil
	}
	scope := loweredFull[:idx]
	if len(scope) < 3 {
		return nil
	}
	if _, ok := t.popularScopesSet[scope]; ok {
		return nil
	}

	bestDist := -1
	var bestMatch string
	for _, known := range t.popularScopes {
		if absInt(len(scope)-len(known)) > t.warnDistance {
			continue
		}
		d := damerauLevenshtein(scope, known)
		if d == 0 {
			continue
		}
		if d <= t.warnDistance && (bestDist == -1 || d < bestDist) {
			bestDist = d
			bestMatch = known
		}
	}
	if bestDist == -1 {
		return nil
	}

	rule := "typosquat_scope_warn"
	score := t.scopeWarnScore
	if bestDist <= t.closeDistance {
		rule = "typosquat_scope_close"
		score = t.scopeCloseScore
	}
	if score == 0 {
		// Calibrated out — skip rather than emit a zero-weight signal.
		return nil
	}
	return &signal.Signal{
		Rule:           rule,
		Score:          score,
		MatchedPackage: bestMatch,
		Detail:         "edit_distance=" + itoa(bestDist),
	}
}

// combosquatMatch returns the first popular-package segment found inside a
// multi-segment bare name, or "" if nothing matches. Segments are split on
// hyphens, underscores, and dots; min-segment-length filtering rejects noise
// from common short fragments ("js", "lib", "npm") that legitimately appear
// inside many package names.
func (t *TyposquatChecker) combosquatMatch(bare string) string {
	parts := strings.FieldsFunc(bare, isCompoundSep)
	if len(parts) < 2 {
		return ""
	}
	for _, seg := range parts {
		if len(seg) < t.combosquatMinSegLen {
			continue
		}
		if _, ok := t.knownSet[seg]; ok {
			return seg
		}
	}
	return ""
}

func isCompoundSep(r rune) bool {
	return r == '-' || r == '_' || r == '.'
}

// stripScope removes a leading "@scope/" prefix; returns the input unchanged
// for non-scoped names.
func stripScope(s string) string {
	if !strings.HasPrefix(s, "@") {
		return s
	}
	idx := strings.Index(s, "/")
	if idx <= 0 {
		return s
	}
	return s[idx+1:]
}

// deHomoglyph returns the de-substituted string and a flag indicating whether
// any character was replaced.
func deHomoglyph(s string, table map[rune]rune) (string, bool) {
	changed := false
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if mapped, ok := table[r]; ok {
			b.WriteRune(mapped)
			changed = true
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), changed
}

// damerauLevenshtein returns the Damerau-Levenshtein distance (edit distance
// with adjacent-transposition as a single operation) between a and b. Used
// for final ranking of BK-tree candidates and for scope comparisons (where
// the reference set is tiny so a direct scan is fine).
func damerauLevenshtein(a, b string) int {
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

	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = minInt3(
				d[i-1][j]+1,
				d[i][j-1]+1,
				d[i-1][j-1]+cost,
			)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := d[i-2][j-2] + 1; t < d[i][j] {
					d[i][j] = t
				}
			}
		}
	}
	return d[la][lb]
}

func minInt3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}
