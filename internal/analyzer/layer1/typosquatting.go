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

type TyposquatChecker struct {
	top10k             []string
	closeDistance      int     // edit distance that triggers the high-score signal (default 1)
	closeScore         float64 // score added for distance == closeDistance
	warnDistance       int     // edit distance that triggers the lower-score signal (default 2)
	warnScore          float64 // score added for distance == warnDistance
	asciiHomoglyphScore float64 // score for ASCII-confusable match; not a veto
}

func NewTyposquatChecker(top10kPath string, closeDistance int, closeScore float64, warnDistance int, warnScore float64, asciiHomoglyphScore float64) (*TyposquatChecker, error) {
	names, err := loadLines(top10kPath)
	if err != nil {
		return nil, err
	}
	// Pre-normalize known names once at load time to avoid repeating per request.
	normalized := make([]string, len(names))
	for i, n := range names {
		normalized[i] = normalize(n)
	}
	return &TyposquatChecker{
		top10k:              normalized,
		closeDistance:       closeDistance,
		closeScore:          closeScore,
		warnDistance:        warnDistance,
		warnScore:           warnScore,
		asciiHomoglyphScore: asciiHomoglyphScore,
	}, nil
}

func (t *TyposquatChecker) Check(_ context.Context, name string) []signal.Signal {
	normalized := normalize(name)

	// Exact match against a top-N name - a known package, skip.
	for _, known := range t.top10k {
		if known == normalized {
			return nil
		}
	}

	// ASCII homoglyph check: high weight but not veto - may be a legitimate name.
	if deglyphed, changed := deHomoglyph(normalized, asciiHomoglyphs); changed {
		for _, known := range t.top10k {
			if deglyphed == known {
				return []signal.Signal{{
					Rule:           "typosquat_ascii_homoglyph",
					Score:          t.asciiHomoglyphScore,
					MatchedPackage: known,
					Detail:         "ascii digit/symbol substitution matches popular package",
				}}
			}
		}
	}

	// Edit-distance scan. Early-exit on the closest match.
	bestDist := -1
	var bestMatch string
	for _, known := range t.top10k {
		// Length-based pruning: abs(len(a)-len(b)) is a lower bound on edit distance.
		if absInt(len(normalized)-len(known)) > t.warnDistance {
			continue
		}
		d := damerauLevenshtein(normalized, known)
		if d == 0 {
			continue
		}
		if bestDist == -1 || d < bestDist {
			bestDist = d
			bestMatch = known
			if d <= t.closeDistance {
				break // can't get closer while still being a typosquat
			}
		}
	}

	if bestDist == -1 || bestDist > t.warnDistance {
		return nil
	}

	if bestDist <= t.closeDistance {
		return []signal.Signal{{
			Rule:           "typosquat_close",
			Score:          t.closeScore,
			MatchedPackage: bestMatch,
			Detail:         "edit_distance=" + itoa(bestDist),
		}}
	}
	return []signal.Signal{{
		Rule:           "typosquat_warn",
		Score:          t.warnScore,
		MatchedPackage: bestMatch,
		Detail:         "edit_distance=" + itoa(bestDist),
	}}
}

// normalize applies NFKC Unicode normalization, lowercases, and strips @scope/ prefix
// so that "@TypeS/Node" is compared on "node" against the known-names index.
func normalize(s string) string {
	s = norm.NFKC.String(s)
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "@") {
		if idx := strings.Index(s, "/"); idx > 0 {
			s = s[idx+1:]
		}
	}
	return s
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

// damerauLevenshtein returns the Damerau-Levenshtein distance (edit distance with
// adjacent-transposition as a single operation) between a and b.
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

	// Full O(la*lb) matrix - fine for package-name lengths (rarely > 40 chars).
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
				d[i-1][j]+1,      // deletion
				d[i][j-1]+1,      // insertion
				d[i-1][j-1]+cost, // substitution
			)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := d[i-2][j-2] + 1; t < d[i][j] {
					d[i][j] = t // transposition
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
