package calibrate

import (
	"sort"

	"github.com/yourusername/npm-proxy/internal/config"
)

// TunableRules is the canonical, ordered list of every rule whose score is
// subject to calibration. The order is stable so reports and the coordinate
// descent loop iterate deterministically. Veto-only rules (curl|sh, OSV)
// are excluded - their score never matters because veto short-circuits the
// engine.
var TunableRules = []string{
	// Layer 1
	"typosquat_close",
	"typosquat_warn",
	"typosquat_ascii_homoglyph",
	"metadata_new_package",
	"metadata_young_maintainer",
	"metadata_low_downloads",
	"metadata_popular_but_stale",
	"anomaly_release_burst",
	"anomaly_maintainer_change",
	"anomaly_unusual_publish_hour",
	"anomaly_size_spike",
	"license_missing",
	"license_changed_in_patch",
	// Layer 2 (curl_sh / wget_sh are veto - excluded)
	"install_script_present",
	"install_script_base64",
	"install_script_child_process",
	"install_script_eval",
	"install_script_node_eval",
	"install_script_dynamic_require",
	"install_script_external_url",
	// Layer 3
	"cap_net",
	"cap_exec",
	"cap_fs_sensitive",
	"cap_dynamic_eval",
	"cap_env_read",
	"entropy_obfuscation",
	"sink_alone",
	"sink_with_obfuscation",
	"version_diff_new_script_in_patch",
	"version_diff_script_changed_in_patch",
	"version_diff_new_exec_in_patch",
	"version_diff_new_net_in_patch",
	"version_diff_new_deps_in_patch",
	// Cross-layer combinations
	"typosquat_with_install_script",
	"install_script_with_exec",
	"install_script_with_network",
	"install_script_with_obfuscation",
}

// DefaultWeights extracts the current weight vector from a loaded config so
// the search loop has a sensible warm start.
func DefaultWeights(cfg *config.Config) Weights {
	return Weights{
		"typosquat_close":           cfg.Layer1.TyposquatCloseScore,
		"typosquat_warn":            cfg.Layer1.TyposquatWarnScore,
		"typosquat_ascii_homoglyph": cfg.Layer1.TyposquatASCIIHomoglyphScore,

		"metadata_new_package":       cfg.Layer1.MetadataNewPackageScore,
		"metadata_young_maintainer":  cfg.Layer1.MetadataYoungMaintainerScore,
		"metadata_low_downloads":     cfg.Layer1.MetadataLowDownloadsScore,
		"metadata_popular_but_stale": cfg.Layer1.MetadataPopularStaleScore,

		"anomaly_release_burst":        cfg.Layer1.AnomalyVersionSpikeScore,
		"anomaly_maintainer_change":    cfg.Layer1.AnomalyMaintainerChangeScore,
		"anomaly_unusual_publish_hour": cfg.Layer1.AnomalyUnusualHoursScore,
		"anomaly_size_spike":           cfg.Layer1.AnomalySizeDeviationScore,

		"license_missing":          cfg.Layer1.LicenseMissingPopScore,
		"license_changed_in_patch": cfg.Layer1.LicensePatchChangeScore,

		"install_script_present":         cfg.Layer2.InstallScriptPresentScore,
		"install_script_base64":          cfg.Layer2.InstallScriptBase64Score,
		"install_script_child_process":   cfg.Layer2.InstallScriptChildProcessScore,
		"install_script_eval":            cfg.Layer2.InstallScriptEvalScore,
		"install_script_node_eval":       cfg.Layer2.InstallScriptNodeEvalScore,
		"install_script_dynamic_require": cfg.Layer2.InstallScriptDynamicRequireScore,
		"install_script_external_url":    cfg.Layer2.InstallScriptExternalURLScore,

		"cap_net":          cfg.Layer3.CapabilityNetScore,
		"cap_exec":         cfg.Layer3.CapabilityExecScore,
		"cap_fs_sensitive": cfg.Layer3.CapabilityFSSensScore,
		"cap_dynamic_eval": cfg.Layer3.CapabilityDynEvalScore,
		"cap_env_read":     cfg.Layer3.CapabilityEnvReadScore,

		"entropy_obfuscation":   0.30, // not in config; entropy emits a fixed-score signal
		"sink_alone":            cfg.Layer3.SinkAloneScore,
		"sink_with_obfuscation": cfg.Layer3.SinkObfuscationScore,

		"version_diff_new_script_in_patch":     cfg.Layer3.VersionDiffScriptAddedScore,
		"version_diff_script_changed_in_patch": cfg.Layer3.VersionDiffScriptChangedScore,
		"version_diff_new_exec_in_patch":       cfg.Layer3.VersionDiffCapExecScore,
		"version_diff_new_net_in_patch":        cfg.Layer3.VersionDiffCapNetScore,
		"version_diff_new_deps_in_patch":       cfg.Layer3.VersionDiffNewDepScore,

		"typosquat_with_install_script":   cfg.Combo.TyposquatWithInstallScriptScore,
		"install_script_with_exec":        cfg.Combo.InstallScriptWithExecScore,
		"install_script_with_network":     cfg.Combo.InstallScriptWithNetworkScore,
		"install_script_with_obfuscation": cfg.Combo.InstallScriptWithObfuscationScore,
	}
}

// Clone returns a deep copy so search trials can mutate freely.
func (w Weights) Clone() Weights {
	out := make(Weights, len(w))
	for k, v := range w {
		out[k] = v
	}
	return out
}

// SortedKeys returns rule names in TunableRules order, including any extra
// keys (sorted alphabetically) so reports never silently drop fields.
func (w Weights) SortedKeys() []string {
	seen := make(map[string]struct{}, len(TunableRules))
	out := make([]string, 0, len(w))
	for _, k := range TunableRules {
		if _, ok := w[k]; ok {
			out = append(out, k)
			seen[k] = struct{}{}
		}
	}
	extra := make([]string, 0)
	for k := range w {
		if _, ok := seen[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// ApplyToConfig mutates cfg in place so the calibrated weights can be written
// back out via YAML marshaling. Rules not present in w are left untouched.
// EntropyObfuscation has no config knob (the entropy detector emits a fixed
// 0.30 score) so its tuned weight is silently dropped. This is a known
// limitation - if entropy weight tuning becomes important, expose a config
// field for it.
func (w Weights) ApplyToConfig(cfg *config.Config) {
	set := func(key string, dst *float64) {
		if v, ok := w[key]; ok {
			*dst = v
		}
	}

	set("typosquat_close", &cfg.Layer1.TyposquatCloseScore)
	set("typosquat_warn", &cfg.Layer1.TyposquatWarnScore)
	set("typosquat_ascii_homoglyph", &cfg.Layer1.TyposquatASCIIHomoglyphScore)

	set("metadata_new_package", &cfg.Layer1.MetadataNewPackageScore)
	set("metadata_young_maintainer", &cfg.Layer1.MetadataYoungMaintainerScore)
	set("metadata_low_downloads", &cfg.Layer1.MetadataLowDownloadsScore)
	set("metadata_popular_but_stale", &cfg.Layer1.MetadataPopularStaleScore)

	set("anomaly_release_burst", &cfg.Layer1.AnomalyVersionSpikeScore)
	set("anomaly_maintainer_change", &cfg.Layer1.AnomalyMaintainerChangeScore)
	set("anomaly_unusual_publish_hour", &cfg.Layer1.AnomalyUnusualHoursScore)
	set("anomaly_size_spike", &cfg.Layer1.AnomalySizeDeviationScore)

	set("license_missing", &cfg.Layer1.LicenseMissingPopScore)
	set("license_changed_in_patch", &cfg.Layer1.LicensePatchChangeScore)

	set("install_script_present", &cfg.Layer2.InstallScriptPresentScore)
	set("install_script_base64", &cfg.Layer2.InstallScriptBase64Score)
	set("install_script_child_process", &cfg.Layer2.InstallScriptChildProcessScore)
	set("install_script_eval", &cfg.Layer2.InstallScriptEvalScore)
	set("install_script_node_eval", &cfg.Layer2.InstallScriptNodeEvalScore)
	set("install_script_dynamic_require", &cfg.Layer2.InstallScriptDynamicRequireScore)
	set("install_script_external_url", &cfg.Layer2.InstallScriptExternalURLScore)

	set("cap_net", &cfg.Layer3.CapabilityNetScore)
	set("cap_exec", &cfg.Layer3.CapabilityExecScore)
	set("cap_fs_sensitive", &cfg.Layer3.CapabilityFSSensScore)
	set("cap_dynamic_eval", &cfg.Layer3.CapabilityDynEvalScore)
	set("cap_env_read", &cfg.Layer3.CapabilityEnvReadScore)

	set("sink_alone", &cfg.Layer3.SinkAloneScore)
	set("sink_with_obfuscation", &cfg.Layer3.SinkObfuscationScore)

	set("version_diff_new_script_in_patch", &cfg.Layer3.VersionDiffScriptAddedScore)
	set("version_diff_script_changed_in_patch", &cfg.Layer3.VersionDiffScriptChangedScore)
	set("version_diff_new_exec_in_patch", &cfg.Layer3.VersionDiffCapExecScore)
	set("version_diff_new_net_in_patch", &cfg.Layer3.VersionDiffCapNetScore)
	set("version_diff_new_deps_in_patch", &cfg.Layer3.VersionDiffNewDepScore)

	set("typosquat_with_install_script", &cfg.Combo.TyposquatWithInstallScriptScore)
	set("install_script_with_exec", &cfg.Combo.InstallScriptWithExecScore)
	set("install_script_with_network", &cfg.Combo.InstallScriptWithNetworkScore)
	set("install_script_with_obfuscation", &cfg.Combo.InstallScriptWithObfuscationScore)
}
