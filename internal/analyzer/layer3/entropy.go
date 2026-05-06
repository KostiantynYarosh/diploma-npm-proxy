package layer3

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/yourusername/npm-proxy/internal/signal"
	"github.com/yourusername/npm-proxy/internal/extractor"
)

// EntropyOptions exposes the analyzer's tunable thresholds. Pre-compiled regexes
// for the string-literal and hex-run scans are built from MinStringLen / HexMinLen
// so operators can broaden or tighten the corpus without recompilation.
type EntropyOptions struct {
	Threshold      float64
	RatioThreshold float64
	MinStringLen   int
	HexMinLen      int
}

type EntropyAnalyzer struct {
	threshold        float64
	ratioThreshold   float64
	minStringLen     int
	reStringLiteral  *regexp.Regexp
	reHexString      *regexp.Regexp
}

func NewEntropyAnalyzer(opts EntropyOptions) *EntropyAnalyzer {
	if opts.MinStringLen <= 0 {
		opts.MinStringLen = 20
	}
	if opts.HexMinLen <= 0 {
		opts.HexMinLen = 64
	}
	return &EntropyAnalyzer{
		threshold:       opts.Threshold,
		ratioThreshold:  opts.RatioThreshold,
		minStringLen:    opts.MinStringLen,
		reStringLiteral: regexp.MustCompile(fmt.Sprintf(`(?:'([^'\\]{%d,})'|"([^"\\]{%d,})")`, opts.MinStringLen, opts.MinStringLen)),
		reHexString:     regexp.MustCompile(fmt.Sprintf(`[0-9a-fA-F]{%d,}`, opts.HexMinLen)),
	}
}

// Analyze scans all JS files for obfuscation signals.
// Returns signals and a bool indicating whether obfuscation was detected.
//
// Pre-built bundles in dist/, build/, lib/, and *.min.js / *.bundle.js are
// excluded from the entropy scan: minification legitimately produces high
// Shannon entropy (collapsed whitespace, mangled identifiers) that is
// indistinguishable from obfuscation by this signal alone. Other detectors
// (sinks, capabilities, install_script) still scan those files - this skip
// only quiets the entropy heuristic, not the rest of the pipeline.
func (e *EntropyAnalyzer) Analyze(_ context.Context, tree extractor.FileTree) ([]signal.Signal, bool) {
	var totalStrings, highEntropyCount int

	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		if isLikelyBundle(path) {
			continue
		}
		src := string(content)
		ts, hc := e.scanFileEntropy(src)
		totalStrings += ts
		highEntropyCount += hc
	}

	if totalStrings == 0 {
		return nil, false
	}

	ratio := float64(highEntropyCount) / float64(totalStrings)
	if ratio >= e.ratioThreshold {
		return []signal.Signal{{
			Rule:  "obfuscation_high_entropy",
			Score: math.Min(ratio, 1.0) * 0.3,
		}}, true
	}

	return nil, false
}

func (e *EntropyAnalyzer) scanFileEntropy(src string) (total, high int) {
	matches := e.reStringLiteral.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		if len(s) < e.minStringLen {
			continue
		}
		total++
		if shannonEntropy(s) >= e.threshold {
			high++
		}
	}

	// Also count base64-decodable strings.
	for _, m := range matches {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		if len(s) < e.minStringLen {
			continue
		}
		if isBase64(s, e.minStringLen) {
			total++
			high++ // base64 strings always count as high-entropy for our purposes
		}
	}

	// Count long hex strings.
	hexMatches := e.reHexString.FindAllString(src, -1)
	for _, hm := range hexMatches {
		_ = hm
		total++
		high++
	}

	return total, high
}

// isLikelyBundle reports whether a path is a pre-built distribution artefact
// (minified or otherwise transformed) that legitimately exhibits high
// entropy. The list is npm-flavoured: dist/, build/, out/, lib/ are the
// canonical "shipped output" directories; the suffixes cover the common
// minified/UMD/ESM/CJS bundle naming conventions. We deliberately don't skip
// node_modules/ because npm tarballs never ship that.
func isLikelyBundle(path string) bool {
	lower := strings.ToLower(path)
	for _, prefix := range []string{
		"package/dist/", "package/build/", "package/out/", "package/lib/",
		"dist/", "build/", "out/", "lib/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, suffix := range []string{
		".min.js", ".bundle.js", ".prod.js",
		".umd.js", ".cjs.js", ".esm.js", ".iife.js",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isBase64(s string, minLen int) bool {
	s = strings.TrimRight(s, "=")
	if len(s) < minLen {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s + strings.Repeat("=", (4-len(s)%4)%4))
	return err == nil
}
