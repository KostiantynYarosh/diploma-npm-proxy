package layer3

import (
	"context"
	"testing"

	"github.com/yourusername/npm-proxy/internal/extractor"
)

func TestSinks_EvalAloneScored(t *testing.T) {
	s := NewSinkAnalyzer(0.2)
	tree := extractor.FileTree{
		"package/index.js": []byte(`eval("console.log('hi')");`),
	}
	sigs := s.Analyze(context.Background(), tree, false)
	if len(sigs) != 1 || sigs[0].Veto {
		t.Errorf("expected single non-veto eval signal, got %+v", sigs)
	}
}

func TestSinks_EvalWithObfuscationVetos(t *testing.T) {
	s := NewSinkAnalyzer(0.2)
	tree := extractor.FileTree{
		"package/index.js": []byte(`eval("console.log('hi')");`),
	}
	sigs := s.Analyze(context.Background(), tree, true)
	if len(sigs) != 1 || !sigs[0].Veto {
		t.Errorf("expected veto for eval+obfuscation, got %+v", sigs)
	}
}

func TestSinks_NoSinkNoSignal(t *testing.T) {
	s := NewSinkAnalyzer(0.2)
	tree := extractor.FileTree{
		"package/index.js": []byte(`module.exports = function(){};`),
	}
	if sigs := s.Analyze(context.Background(), tree, false); len(sigs) != 0 {
		t.Errorf("expected no signals for clean file, got %+v", sigs)
	}
}
