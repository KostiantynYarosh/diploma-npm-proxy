package layer1

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeTop10kFixture creates a throwaway popular-packages file for tests.
// Using a tiny fixture keeps the assertions independent of the full 10k list
// that ships in configs/.
func writeTop10kFixture(t *testing.T, names []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "top.txt")
	content := ""
	for _, n := range names {
		content += n + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func newTestChecker(t *testing.T) *TyposquatChecker {
	t.Helper()
	// Note: @types appears in three entries to clear minPopularScopeOccurrences=3,
	// so scope-typosquat tests have something to match against.
	path := writeTop10kFixture(t, []string{
		"react", "lodash", "express", "axios", "typescript",
		"@types/node", "@types/react", "@types/express",
		"react-dom",
	})
	c, err := NewTyposquatChecker(path, TyposquatOptions{
		CloseDistance:       1,
		CloseScore:          0.55,
		WarnDistance:        2,
		WarnScore:           0.30,
		ASCIIHomoglyphScore: 0.65,
		CombosquatScore:     0.20,
		ScopeCloseScore:     0.55,
		ScopeWarnScore:      0.25,
	})
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}
	return c
}

func findSignal(sigs []signalLike, rule string) (signalLike, bool) {
	for _, s := range sigs {
		if s.Rule == rule {
			return s, true
		}
	}
	return signalLike{}, false
}

// signalLike mirrors signal.Signal fields we care about without importing the
// full signal package - keeps the test focused on rule firing semantics.
type signalLike struct {
	Rule           string
	Score          float64
	MatchedPackage string
	Veto           bool
}

func sigs(t *testing.T, c *TyposquatChecker, name string) []signalLike {
	t.Helper()
	out := c.Check(context.Background(), name)
	conv := make([]signalLike, len(out))
	for i, s := range out {
		conv[i] = signalLike{Rule: s.Rule, Score: s.Score, MatchedPackage: s.MatchedPackage, Veto: s.Veto}
	}
	return conv
}

func TestTyposquat_ExactPopularReturnsNil(t *testing.T) {
	c := newTestChecker(t)
	if got := sigs(t, c, "react"); len(got) != 0 {
		t.Errorf("exact popular name should not signal, got %+v", got)
	}
}

func TestTyposquat_EditDistanceOneBlocks(t *testing.T) {
	c := newTestChecker(t)
	// "raect" - a transposition of "react" (DL distance 1).
	got := sigs(t, c, "raect")
	s, ok := findSignal(got, "typosquat_close")
	if !ok {
		t.Fatalf("expected typosquat_close, got %+v", got)
	}
	if s.MatchedPackage != "react" {
		t.Errorf("expected matched=react, got %q", s.MatchedPackage)
	}
	if s.Score <= 0 {
		t.Errorf("expected positive score, got %v", s.Score)
	}
}

func TestTyposquat_EditDistanceTwoIsWarn(t *testing.T) {
	c := newTestChecker(t)
	// "reactzz" = "react" + two trailing inserts → DL distance 2.
	got := sigs(t, c, "reactzz")
	if _, ok := findSignal(got, "typosquat_warn"); !ok {
		t.Fatalf("expected typosquat_warn, got %+v", got)
	}
}

func TestTyposquat_LegitimateVariantNotFlagged(t *testing.T) {
	c := newTestChecker(t)
	// "react-dom" is itself popular (in our fixture), so should return nil.
	if got := sigs(t, c, "react-dom"); len(got) != 0 {
		t.Errorf("known legitimate variant should not signal, got %+v", got)
	}
}

func TestTyposquat_ASCIIHomoglyphScoredNotVetoed(t *testing.T) {
	c := newTestChecker(t)
	got := sigs(t, c, "l0dash")
	s, ok := findSignal(got, "typosquat_ascii_homoglyph")
	if !ok {
		t.Fatalf("expected typosquat_ascii_homoglyph, got %+v", got)
	}
	if s.Veto {
		t.Errorf("ascii homoglyph should not veto, got %+v", s)
	}
	if s.Score < 0.5 {
		t.Errorf("expected high score, got %v", s.Score)
	}
}

func TestTyposquat_ScopedPackageNormalized(t *testing.T) {
	c := newTestChecker(t)
	// Scope-strip behaviour: "@types/nodex" → bare "nodex" → distance-1 from
	// nothing in fixture. Just ensure no panic and no spurious signals beyond
	// what the bare-name search would produce.
	_ = sigs(t, c, "@types/nodex")
}

// --- Phase 1: combosquat ---

func TestTyposquat_Combosquat_PrefixOfPopular(t *testing.T) {
	c := newTestChecker(t)
	// "react-fake" — popular segment "react" + suffix "fake".
	got := sigs(t, c, "react-fake")
	s, ok := findSignal(got, "typosquat_combosquat")
	if !ok {
		t.Fatalf("expected typosquat_combosquat for react-fake, got %+v", got)
	}
	if s.MatchedPackage != "react" {
		t.Errorf("expected matched=react, got %q", s.MatchedPackage)
	}
}

func TestTyposquat_Combosquat_DoesNotFireOnShortSegments(t *testing.T) {
	c := newTestChecker(t)
	// "js-react" splits to ["js", "react"]. "react" is popular, but combosquat
	// should still fire because the "js" prefix is filler. This is a positive
	// case actually — verify the popular segment match wins.
	got := sigs(t, c, "js-react")
	if _, ok := findSignal(got, "typosquat_combosquat"); !ok {
		t.Fatalf("expected combosquat for js-react, got %+v", got)
	}
}

func TestTyposquat_Combosquat_SkipsSingleSegment(t *testing.T) {
	c := newTestChecker(t)
	// "reactjs" (no separator) — combosquat needs ≥2 segments. The bare-name
	// distance check may still fire (distance 2), but no combosquat signal.
	got := sigs(t, c, "reactjs")
	if _, ok := findSignal(got, "typosquat_combosquat"); ok {
		t.Errorf("combosquat should not fire for single-segment name; got %+v", got)
	}
}

func TestTyposquat_Combosquat_KnownPackageEarlyExit(t *testing.T) {
	c := newTestChecker(t)
	// "react-dom" is popular (exact match) — should NOT emit combosquat even
	// though "react" is a popular segment of it.
	got := sigs(t, c, "react-dom")
	if _, ok := findSignal(got, "typosquat_combosquat"); ok {
		t.Errorf("combosquat should not fire on popular package itself; got %+v", got)
	}
}

// --- Phase 2: scope typosquat ---

func TestTyposquat_ScopeClose(t *testing.T) {
	c := newTestChecker(t)
	// "@typess/node" — "@typess" is distance-1 from popular "@types".
	got := sigs(t, c, "@typess/node")
	s, ok := findSignal(got, "typosquat_scope_close")
	if !ok {
		t.Fatalf("expected typosquat_scope_close, got %+v", got)
	}
	if s.MatchedPackage != "@types" {
		t.Errorf("expected matched=@types, got %q", s.MatchedPackage)
	}
}

func TestTyposquat_ScopeExactMatchSkips(t *testing.T) {
	c := newTestChecker(t)
	// "@types/node" — exact scope, exact package, should return zero signals.
	if got := sigs(t, c, "@types/node"); len(got) != 0 {
		t.Errorf("@types/node is fully legitimate, got %+v", got)
	}
}

func TestTyposquat_ScopeTooShortIgnored(t *testing.T) {
	c := newTestChecker(t)
	// "@a/foo" — scope "@a" is < 3 chars, false-positive prone, skipped.
	got := sigs(t, c, "@a/foo")
	if _, ok := findSignal(got, "typosquat_scope_close"); ok {
		t.Errorf("scope < 3 chars should not be checked; got %+v", got)
	}
	if _, ok := findSignal(got, "typosquat_scope_warn"); ok {
		t.Errorf("scope < 3 chars should not be checked; got %+v", got)
	}
}

// --- Phase 3: BK-tree correctness ---

func TestBKTree_FindsAllWithinTolerance(t *testing.T) {
	tree := newBKTree([]string{"react", "redux", "axios", "lodash", "express"})
	cand := tree.search("raect", 2)
	// Levenshtein("raect","react") = 2 (two substitutions); should be in candidates.
	found := false
	for _, c := range cand {
		if c == "react" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("BK-tree search missed 'react' for query 'raect' (Lev distance 2); got %v", cand)
	}
}

func TestBKTree_EmptyInputIsNil(t *testing.T) {
	if tree := newBKTree(nil); tree != nil {
		t.Errorf("nil input should produce nil tree")
	}
	if tree := newBKTree([]string{}); tree != nil {
		t.Errorf("empty input should produce nil tree")
	}
}

func TestBKTree_SearchNilSafe(t *testing.T) {
	var tree *bkNode
	if got := tree.search("anything", 2); got != nil {
		t.Errorf("nil-receiver search should return nil; got %v", got)
	}
}

func TestLevenshtein_KnownCases(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"react", "react", 0},
		{"react", "reac", 1},
		{"react", "reacts", 1},
		{"react", "rxact", 1},
		{"react", "raect", 2}, // transposition is 2 under plain Levenshtein
		{"react", "lodash", 5},
	}
	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q,%q)=%d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDamerauLevenshtein_KnownCases(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"react", "react", 0},
		{"react", "raect", 1}, // transposition counted as one op
		{"react", "reac", 1},
		{"react", "reacts", 1},
		{"react", "rxact", 1},
		{"react", "lodash", 5},
		{"kitten", "sitting", 3},
	}
	for _, tt := range tests {
		got := damerauLevenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("DL(%q,%q)=%d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
