package layer3

import (
	"context"
	"testing"

	"github.com/yourusername/npm-proxy/internal/extractor"
)

func TestCapabilities_ExecDetected(t *testing.T) {
	a := NewCapabilityAnalyzer(0.15, 0.30, 0.25, 0.20, 0.10)
	tree := extractor.FileTree{
		"package/index.js": []byte(`const cp = require('child_process'); cp.exec('ls');`),
	}
	sigs, caps := a.Analyze(context.Background(), tree)
	found := false
	for _, c := range caps {
		if c == CapExec {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CapExec, got caps=%v sigs=%+v", caps, sigs)
	}
}

func TestCapabilities_NetDetected(t *testing.T) {
	a := NewCapabilityAnalyzer(0.15, 0.30, 0.25, 0.20, 0.10)
	tree := extractor.FileTree{
		"package/index.js": []byte(`const https = require('https'); https.get('http://x');`),
	}
	_, caps := a.Analyze(context.Background(), tree)
	found := false
	for _, c := range caps {
		if c == CapNet {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CapNet, got %v", caps)
	}
}

func TestCapabilities_CleanFileNoSignal(t *testing.T) {
	a := NewCapabilityAnalyzer(0.15, 0.30, 0.25, 0.20, 0.10)
	tree := extractor.FileTree{
		"package/index.js": []byte(`module.exports = function add(a,b){return a+b};`),
	}
	sigs, _ := a.Analyze(context.Background(), tree)
	if len(sigs) != 0 {
		t.Errorf("expected no signals for clean file, got %+v", sigs)
	}
}
