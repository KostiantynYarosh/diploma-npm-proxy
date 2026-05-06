package analyzer

import (
	"testing"

	"github.com/yourusername/npm-proxy/internal/signal"
)

func TestAddComboSignals(t *testing.T) {
	result := &signal.Result{}
	result.Add(signal.Signal{Rule: "typosquat_warn", Score: 0.1})
	result.Add(signal.Signal{Rule: "install_script_present", Score: 0.1})
	result.Add(signal.Signal{Rule: "capability_exec", Score: 0.1})
	result.Add(signal.Signal{Rule: "capability_net_access", Score: 0.1})
	result.Add(signal.Signal{Rule: "obfuscation_high_entropy", Score: 0.1})

	AddComboSignals(result, ComboScores{
		TyposquatWithInstallScript:   0.2,
		InstallScriptWithExec:        0.3,
		InstallScriptWithNetwork:     0.4,
		InstallScriptWithObfuscation: 0.5,
	})

	want := map[string]float64{
		"typosquat_with_install_script":   0.2,
		"install_script_with_exec":        0.3,
		"install_script_with_network":     0.4,
		"install_script_with_obfuscation": 0.5,
	}
	for _, s := range result.Signals {
		if score, ok := want[s.Rule]; ok {
			if s.Score != score {
				t.Fatalf("%s score=%v want %v", s.Rule, s.Score, score)
			}
			delete(want, s.Rule)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing combo signals: %v", want)
	}
}

func TestAddComboSignalsIsIdempotent(t *testing.T) {
	result := &signal.Result{}
	result.Add(signal.Signal{Rule: "install_script_child_process_preinstall", Score: 0.1})

	scores := ComboScores{InstallScriptWithExec: 0.3}
	AddComboSignals(result, scores)
	AddComboSignals(result, scores)

	count := 0
	for _, s := range result.Signals {
		if s.Rule == "install_script_with_exec" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("install_script_with_exec count=%d want 1", count)
	}
}
