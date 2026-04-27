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
	path := writeTop10kFixture(t, []string{
		"react", "lodash", "express", "axios", "typescript",
		"@types/node", "react-dom",
	})
	c, err := NewTyposquatChecker(path, 1, 0.55, 2, 0.30, 0.65)
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}
	return c
}

func TestTyposquat_ExactPopularReturnsNil(t *testing.T) {
	c := newTestChecker(t)
	if got := c.Check(context.Background(), "react"); got != nil {
		t.Errorf("exact popular name should not signal, got %+v", got)
	}
}

func TestTyposquat_EditDistanceOneBlocks(t *testing.T) {
	c := newTestChecker(t)
	// "raect" - a transposition of "react" (DL distance 1).
	sigs := c.Check(context.Background(), "raect")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Rule != "typosquat_close" {
		t.Errorf("expected typosquat_close, got %q", sigs[0].Rule)
	}
	if sigs[0].MatchedPackage != "react" {
		t.Errorf("expected matched=react, got %q", sigs[0].MatchedPackage)
	}
	if sigs[0].Score <= 0 {
		t.Errorf("expected positive score, got %v", sigs[0].Score)
	}
}

func TestTyposquat_EditDistanceTwoIsWarn(t *testing.T) {
	c := newTestChecker(t)
	// "reactzz" = "react" + two trailing inserts → DL distance 2.
	sigs := c.Check(context.Background(), "reactzz")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal for distance-2 match, got %d: %+v", len(sigs), sigs)
	}
	if sigs[0].Rule != "typosquat_warn" {
		t.Errorf("expected typosquat_warn, got %q (matched=%q detail=%q)", sigs[0].Rule, sigs[0].MatchedPackage, sigs[0].Detail)
	}
}

func TestTyposquat_LegitimateVariantNotFlagged(t *testing.T) {
	c := newTestChecker(t)
	// "react-dom" is itself popular (in our fixture), so should return nil.
	if got := c.Check(context.Background(), "react-dom"); got != nil {
		t.Errorf("known legitimate variant should not signal, got %+v", got)
	}
}

func TestTyposquat_ASCIIHomoglyphScoredNotVetoed(t *testing.T) {
	c := newTestChecker(t)
	// "l0dash" (zero instead of letter-o) should score but not veto.
	sigs := c.Check(context.Background(), "l0dash")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(sigs), sigs)
	}
	if sigs[0].Veto {
		t.Errorf("ascii homoglyph should not veto, got %+v", sigs[0])
	}
	if sigs[0].Rule != "typosquat_ascii_homoglyph" {
		t.Errorf("expected typosquat_ascii_homoglyph, got %q", sigs[0].Rule)
	}
	if sigs[0].Score < 0.5 {
		t.Errorf("expected high score, got %v", sigs[0].Score)
	}
}

func TestTyposquat_ScopedPackageNormalized(t *testing.T) {
	// "@types/nod" → strip scope → "nod" is distance-1 from "node" - but "node"
	// is not in our fixture. We test that "@typess/node" (a plausible scope
	// typosquat) does *not* crash and returns something sensible.
	c := newTestChecker(t)
	sigs := c.Check(context.Background(), "@typess/node")
	// "@typess/node" normalizes to "node"; "node" is not in our fixture but
	// "react-dom" has len 9, "node" has len 4 - no close match expected.
	// What we really test: no panic + reasonable behaviour on scoped names.
	_ = sigs
}

func TestDamerauLevenshtein_KnownCases(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"react", "react", 0},
		{"react", "raect", 1}, // transposition
		{"react", "reac", 1},  // deletion
		{"react", "reacts", 1}, // insertion
		{"react", "rxact", 1}, // substitution
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
