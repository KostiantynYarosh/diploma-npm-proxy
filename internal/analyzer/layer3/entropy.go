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
func (e *EntropyAnalyzer) Analyze(_ context.Context, tree extractor.FileTree) ([]signal.Signal, bool) {
	var totalStrings, highEntropyCount int

	for path, content := range tree {
		if !isJSFile(path) {
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
