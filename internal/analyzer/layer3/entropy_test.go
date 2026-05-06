package layer3

import (
	"context"
	"strings"
	"testing"

	"github.com/yourusername/npm-proxy/internal/extractor"
)

func TestEntropy_HighEntropyStringDetected(t *testing.T) {
	e := NewEntropyAnalyzer(EntropyOptions{Threshold: 4.5, RatioThreshold: 0.20, MinStringLen: 64, HexMinLen: 64})
	// Long pseudo-random string (high Shannon entropy) >= minStringLen.
	payload := strings.Repeat("aB3xZ9qW", 10)
	tree := extractor.FileTree{
		"package/x.js": []byte(`const k = "` + payload + `";`),
	}
	_, obfuscated := e.Analyze(context.Background(), tree)
	if !obfuscated {
		t.Errorf("expected high-entropy payload to trigger obfuscation flag")
	}
}

func TestEntropy_CleanFileNotFlagged(t *testing.T) {
	e := NewEntropyAnalyzer(EntropyOptions{Threshold: 4.5, RatioThreshold: 0.20, MinStringLen: 64, HexMinLen: 64})
	tree := extractor.FileTree{
		"package/x.js": []byte(`const greeting = "hello world, this is a perfectly normal string with readable english text";`),
	}
	_, obfuscated := e.Analyze(context.Background(), tree)
	if obfuscated {
		t.Errorf("natural-language string should not be flagged as obfuscated")
	}
}

// Minified bundles legitimately exhibit high entropy (collapsed whitespace,
// mangled identifiers). The path-aware skip must keep them out of the
// obfuscation count even when the same payload would flag at the source path.
func TestEntropy_BundleSkipped(t *testing.T) {
	e := NewEntropyAnalyzer(EntropyOptions{Threshold: 4.5, RatioThreshold: 0.20, MinStringLen: 64, HexMinLen: 64})
	payload := strings.Repeat("aB3xZ9qW", 10)
	for _, path := range []string{
		"package/dist/index.js",
		"package/build/main.min.js",
		"package/lib/foo.bundle.js",
		"package/foo.umd.js",
	} {
		tree := extractor.FileTree{path: []byte(`var k="` + payload + `";`)}
		_, obfuscated := e.Analyze(context.Background(), tree)
		if obfuscated {
			t.Errorf("%s: bundle path must not contribute to entropy ratio", path)
		}
	}
}

func TestEntropy_NonBundlePathStillFlagged(t *testing.T) {
	// Sanity check: the same payload outside a bundle path still flags.
	e := NewEntropyAnalyzer(EntropyOptions{Threshold: 4.5, RatioThreshold: 0.20, MinStringLen: 64, HexMinLen: 64})
	payload := strings.Repeat("aB3xZ9qW", 10)
	tree := extractor.FileTree{"package/index.js": []byte(`var k="` + payload + `";`)}
	_, obfuscated := e.Analyze(context.Background(), tree)
	if !obfuscated {
		t.Errorf("non-bundle path must still trigger obfuscation flag")
	}
}
