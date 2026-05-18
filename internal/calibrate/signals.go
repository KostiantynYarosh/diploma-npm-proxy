package calibrate

import (
	"strings"

	"github.com/yourusername/npm-proxy/internal/policy"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// CachedSignal stores the rule identity and veto flag from a pipeline run,
// preserving the original Score as a fallback for non-tunable rules.
// CWE/Detail/MatchedPackage are preserved so reports stay informative.
type CachedSignal struct {
	Rule           string
	Score          float64
	Veto           bool
	CWE            string
	Detail         string
	MatchedPackage string
}

// PackageRun is the per-package payload that calibration trials replay.
// One Run is built once per dataset entry; all subsequent trials rewire its
// signals against fresh weights and thresholds without touching disk or
// re-extracting the tarball.
type PackageRun struct {
	Name     string
	Version  string
	SHA256   string
	Label    Label
	Category string // optional sub-classification preserved from the corpus
	Signals  []CachedSignal
}

// Weights maps a rule name to its score contribution. A rule absent from the
// map keeps its original score (which is 0 for non-scored signals like
// veto-only rules and capability lists).
type Weights map[string]float64

// MinCategories is the gating bar replayed by the calibrator so its verdicts
// match the production proxy. Kept as a package-level knob so the search loop
// stays parameter-light - in practice only the proxy reads it from config and
// the calibrator should follow whatever's configured there.
var MinCategories = 2

// Apply replays cached signals with the supplied weights and returns the
// engine's verdict. Veto signals always block irrespective of weight or
// gating. Multi-category gating uses the package-level MinCategories knob.
func Apply(run *PackageRun, weights Weights, allow, block float64) policy.Decision {
	return ApplyWithMinCategories(run, weights, allow, block, MinCategories)
}

// ApplyWithMinCategories is the explicit form used by calibration search when
// min_categories itself is part of the search space.
func ApplyWithMinCategories(run *PackageRun, weights Weights, allow, block float64, minCategories int) policy.Decision {
	result := &signal.Result{}
	for _, cs := range run.Signals {
		score := cs.Score
		if tuned, ok := weights[WeightKey(cs.Rule)]; ok {
			score = tuned
		}
		result.Add(signal.Signal{
			Rule:           cs.Rule,
			Score:          score,
			Veto:           cs.Veto,
			CWE:            cs.CWE,
			Detail:         cs.Detail,
			MatchedPackage: cs.MatchedPackage,
		})
	}
	return policy.NewEngine(allow, block, minCategories).Decide(result)
}

// WeightKey maps concrete detector rule names back to the canonical weight
// keys used by the search space and config writer. Several detectors emit
// per-hook or more descriptive rule names while sharing one config knob.
func WeightKey(rule string) string {
	switch rule {
	case "anomaly_version_spike":
		return "anomaly_release_burst"
	case "license_patch_change":
		return "license_changed_in_patch"
	case "capability_exec":
		return "cap_exec"
	case "capability_dynamic_eval":
		return "cap_dynamic_eval"
	case "capability_env_read":
		return "cap_env_read"
	case "obfuscation_high_entropy":
		return "entropy_obfuscation"
	case "sink_eval", "sink_new_function", "sink_vm_run_this_context",
		"sink_vm_run_new_context", "sink_dynamic_require":
		return "sink_alone"
	case "version_diff_new_dependency":
		return "version_diff_new_deps_in_patch"
	}

	switch {
	case strings.HasPrefix(rule, "install_script_base64_decode_"):
		return "install_script_base64"
	case strings.HasPrefix(rule, "install_script_child_process_"):
		return "install_script_child_process"
	case strings.HasPrefix(rule, "install_script_eval_"):
		return "install_script_eval"
	case strings.HasPrefix(rule, "install_script_node_eval_"):
		return "install_script_node_eval"
	case strings.HasPrefix(rule, "install_script_dynamic_require_"):
		return "install_script_dynamic_require"
	case strings.HasPrefix(rule, "install_script_external_url_"):
		return "install_script_external_url"
	case strings.HasPrefix(rule, "version_diff_new_script_"):
		return "version_diff_new_script_in_patch"
	case strings.HasPrefix(rule, "version_diff_changed_script_"):
		return "version_diff_script_changed_in_patch"
	default:
		return rule
	}
}
