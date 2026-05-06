package layer3

import (
	"context"
	"testing"

	"github.com/yourusername/npm-proxy/internal/extractor"
)

func TestSinks_EvalAloneScored(t *testing.T) {
	s := NewSinkAnalyzer(0.2, 0.55)
	tree := extractor.FileTree{
		"package/index.js": []byte(`eval("console.log('hi')");`),
	}
	sigs := s.Analyze(context.Background(), tree, false)
	if len(sigs) != 1 || sigs[0].Veto || sigs[0].Rule != "sink_eval" {
		t.Errorf("expected single non-veto sink_eval signal, got %+v", sigs)
	}
}

func TestSinks_EvalWithObfuscationScoredHeavily(t *testing.T) {
	// Sink + obfuscation used to be a hard veto; it is now a heavy scored
	// signal so minified popular bundles aren't auto-blocked. Verify the
	// rule name collapses to "sink_with_obfuscation" with the heavier weight
	// and no veto flag.
	s := NewSinkAnalyzer(0.2, 0.55)
	tree := extractor.FileTree{
		"package/index.js": []byte(`eval("console.log('hi')");`),
	}
	sigs := s.Analyze(context.Background(), tree, true)
	if len(sigs) != 1 {
		t.Fatalf("expected single signal, got %+v", sigs)
	}
	if sigs[0].Veto {
		t.Errorf("sink+obfuscation must not veto, got %+v", sigs[0])
	}
	if sigs[0].Rule != "sink_with_obfuscation" {
		t.Errorf("rule should collapse to sink_with_obfuscation, got %q", sigs[0].Rule)
	}
	if sigs[0].Score != 0.55 {
		t.Errorf("expected obfuscation score 0.55, got %v", sigs[0].Score)
	}
}

func TestSinks_NoSinkNoSignal(t *testing.T) {
	s := NewSinkAnalyzer(0.2, 0.55)
	tree := extractor.FileTree{
		"package/index.js": []byte(`module.exports = function(){};`),
	}
	if sigs := s.Analyze(context.Background(), tree, false); len(sigs) != 0 {
		t.Errorf("expected no signals for clean file, got %+v", sigs)
	}
}
