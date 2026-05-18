package analyzer

import (
	"strings"

	"github.com/yourusername/npm-proxy/internal/config"
	"github.com/yourusername/npm-proxy/internal/signal"
)

type ComboScores struct {
	TyposquatWithInstallScript   float64
	InstallScriptWithExec        float64
	InstallScriptWithNetwork     float64
	InstallScriptWithObfuscation float64
}

func ComboScoresFromConfig(cfg *config.Config) ComboScores {
	return ComboScores{
		TyposquatWithInstallScript:   cfg.Combo.TyposquatWithInstallScriptScore,
		InstallScriptWithExec:        cfg.Combo.InstallScriptWithExecScore,
		InstallScriptWithNetwork:     cfg.Combo.InstallScriptWithNetworkScore,
		InstallScriptWithObfuscation: cfg.Combo.InstallScriptWithObfuscationScore,
	}
}

// AddComboSignals derives higher-order signals from already detected rules.
// It does not rescan package contents; it only captures combinations that are
// substantially stronger than either component alone.
func AddComboSignals(result *signal.Result, scores ComboScores) {
	if result == nil {
		return
	}

	existing := make(map[string]struct{}, len(result.Signals)+4)
	var hasTyposquat, hasInstallScript, hasExec, hasNetwork, hasObfuscation bool
	for _, s := range result.Signals {
		existing[s.Rule] = struct{}{}
		switch {
		case isTyposquatRule(s.Rule):
			hasTyposquat = true
		case isInstallScriptRule(s.Rule):
			hasInstallScript = true
		}
		if isExecRule(s.Rule) {
			hasExec = true
		}
		if isNetworkRule(s.Rule) {
			hasNetwork = true
		}
		if isObfuscationRule(s.Rule) {
			hasObfuscation = true
		}
	}

	add := func(rule string, score float64, detail string) {
		if score <= 0 {
			return
		}
		if _, ok := existing[rule]; ok {
			return
		}
		result.Add(signal.Signal{
			Rule:   rule,
			Score:  score,
			CWE:    "CWE-506",
			Detail: detail,
		})
		existing[rule] = struct{}{}
	}

	if hasTyposquat && hasInstallScript {
		add("typosquat_with_install_script", scores.TyposquatWithInstallScript, "typosquat+install_script")
	}
	if hasInstallScript && hasExec {
		add("install_script_with_exec", scores.InstallScriptWithExec, "install_script+exec")
	}
	if hasInstallScript && hasNetwork {
		add("install_script_with_network", scores.InstallScriptWithNetwork, "install_script+network")
	}
	if hasInstallScript && hasObfuscation {
		add("install_script_with_obfuscation", scores.InstallScriptWithObfuscation, "install_script+obfuscation")
	}
}

func isTyposquatRule(rule string) bool {
	return strings.HasPrefix(rule, "typosquat_")
}

func isInstallScriptRule(rule string) bool {
	return rule == "install_script_present" || strings.HasPrefix(rule, "install_script_")
}

func isExecRule(rule string) bool {
	return rule == "capability_exec" ||
		rule == "cap_exec" ||
		strings.HasPrefix(rule, "install_script_child_process_") ||
		strings.HasPrefix(rule, "install_script_node_eval_")
}

func isNetworkRule(rule string) bool {
	// capability_net_access was removed from the signal set (calibrator zeroed
	// its weight across every profile). The network-combo signal now triggers
	// solely on lifecycle-script-borne network indicators.
	return strings.HasPrefix(rule, "install_script_external_url_")
}

func isObfuscationRule(rule string) bool {
	return rule == "obfuscation_high_entropy" ||
		rule == "entropy_obfuscation" ||
		rule == "sink_with_obfuscation"
}
