package layer3

import (
	"testing"

	"github.com/yourusername/npm-proxy/internal/registry"
)

func TestVersionDiff_NewScriptInPatchFires(t *testing.T) {
	v := NewVersionDiffAnalyzer(VersionDiffOptions{
		ScriptAddedScore:   0.4,
		ScriptChangedScore: 0.25,
		CapExecScore:       0.35,
		CapNetScore:        0.25,
	})
	meta := &registry.PackageMeta{
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {Scripts: map[string]string{}},
			"1.0.1": {Scripts: map[string]string{"postinstall": "node setup.js"}},
		},
	}
	sigs, deep := v.ScriptDiff(meta, "1.0.0", "1.0.1")
	if !deep {
		t.Errorf("expected needsDeepCheck=true when script is added in patch")
	}
	if len(sigs) != 1 || sigs[0].Rule != "version_diff_new_script_postinstall" {
		t.Errorf("expected version_diff_new_script_postinstall, got %+v", sigs)
	}
}

func TestVersionDiff_NewDependencyInPatchFires(t *testing.T) {
	v := NewVersionDiffAnalyzer(VersionDiffOptions{
		NewDepScore: 0.10,
		NewDepCap:   0.35,
	})
	meta := &registry.PackageMeta{
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {Dependencies: map[string]string{"chalk": "^4"}},
			"1.0.1": {Dependencies: map[string]string{"chalk": "^4", "curl-shim": "^1", "tcp-wire": "^1"}},
		},
	}
	sigs := v.DependencyDiff(meta, "1.0.0", "1.0.1")
	if len(sigs) != 1 || sigs[0].Rule != "version_diff_new_dependency" {
		t.Fatalf("expected version_diff_new_dependency, got %+v", sigs)
	}
	if sigs[0].Score < 0.19 {
		t.Errorf("expected score ≈ 0.20 for two new deps, got %v", sigs[0].Score)
	}
}

func TestVersionDiff_NonPatchBumpNoSignal(t *testing.T) {
	v := NewVersionDiffAnalyzer(VersionDiffOptions{
		ScriptAddedScore: 0.4,
	})
	meta := &registry.PackageMeta{
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {Scripts: map[string]string{}},
			"2.0.0": {Scripts: map[string]string{"postinstall": "node setup.js"}},
		},
	}
	sigs, _ := v.ScriptDiff(meta, "1.0.0", "2.0.0")
	if len(sigs) != 0 {
		t.Errorf("major bump should not trigger version_diff, got %+v", sigs)
	}
}
