package layer3

import (
	"fmt"
	"strings"

	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/semverutil"
	"github.com/yourusername/npm-proxy/internal/signal"
)

var diffHooks = []string{"preinstall", "install", "postinstall", "preuninstall", "prepare"}

type VersionDiffAnalyzer struct {
	scriptAddedScore   float64 // new hook appeared in a patch release
	scriptChangedScore float64 // existing hook body changed in a patch release
	capExecScore       float64 // exec capability new in a patch release (deep check)
	capNetScore        float64 // net capability new in a patch release (deep check)
	newDepScore        float64 // per-new-dependency score contribution in a patch release
	newDepCap          float64 // cap on the aggregate new-dependency score (one signal)
}

type VersionDiffOptions struct {
	ScriptAddedScore   float64
	ScriptChangedScore float64
	CapExecScore       float64
	CapNetScore        float64
	NewDepScore        float64
	NewDepCap          float64
}

func NewVersionDiffAnalyzer(opts VersionDiffOptions) *VersionDiffAnalyzer {
	return &VersionDiffAnalyzer{
		scriptAddedScore:   opts.ScriptAddedScore,
		scriptChangedScore: opts.ScriptChangedScore,
		capExecScore:       opts.CapExecScore,
		capNetScore:        opts.CapNetScore,
		newDepScore:        opts.NewDepScore,
		newDepCap:          opts.NewDepCap,
	}
}

// ScriptDiff compares lifecycle script fields between the current and previous version
// using already-fetched registry metadata - zero extra network cost.
// Returns signals and whether a deep capability check should be triggered.
func (v *VersionDiffAnalyzer) ScriptDiff(
	meta *registry.PackageMeta,
	prevVersion, currentVersion string,
) (signals []signal.Signal, needsDeepCheck bool) {
	if prevVersion == "" || !semverutil.IsPatchBump(prevVersion, currentVersion) {
		return nil, false
	}

	prevMeta, prevOK := meta.Versions[prevVersion]
	currMeta, currOK := meta.Versions[currentVersion]
	if !prevOK || !currOK {
		return nil, false
	}

	for _, hook := range diffHooks {
		prev := strings.TrimSpace(prevMeta.Scripts[hook])
		curr := strings.TrimSpace(currMeta.Scripts[hook])

		if prev == curr {
			continue
		}

		if prev == "" && curr != "" {
			signals = append(signals, signal.Signal{
				Rule:  "version_diff_new_script_" + hook,
				Score: v.scriptAddedScore,
				CWE:   "CWE-506",
			})
		} else if curr != "" {
			signals = append(signals, signal.Signal{
				Rule:  "version_diff_changed_script_" + hook,
				Score: v.scriptChangedScore,
			})
		}
		needsDeepCheck = true
	}

	return signals, needsDeepCheck
}

// CapabilityDiff compares two capability sets from on-demand tarball analysis.
// Only fires on patch bumps - minor and major bumps are expected to add capabilities.
func (v *VersionDiffAnalyzer) CapabilityDiff(
	prevCaps, currentCaps []string,
	prevVersion, currentVersion string,
) []signal.Signal {
	if !semverutil.IsPatchBump(prevVersion, currentVersion) {
		return nil
	}

	prevSet := toSet(prevCaps)
	var signals []signal.Signal

	for _, cap := range currentCaps {
		if prevSet[cap] {
			continue
		}
		switch cap {
		case CapExec:
			signals = append(signals, signal.Signal{
				Rule:  "version_diff_new_exec_in_patch",
				Score: v.capExecScore,
				CWE:   "CWE-78",
			})
		case CapNet:
			signals = append(signals, signal.Signal{
				Rule:  "version_diff_new_net_in_patch",
				Score: v.capNetScore,
				CWE:   "CWE-918",
			})
		}
	}

	return signals
}

// DependencyDiff compares the dependency sets of two versions and flags
// new runtime or dev dependencies introduced during a patch bump.
// Rationale: patch releases are, by semver contract, bug fixes - a newly
// added dependency is suspicious because it expands the supply-chain surface
// without a minor/major version signal.
func (v *VersionDiffAnalyzer) DependencyDiff(
	meta *registry.PackageMeta,
	prevVersion, currentVersion string,
) []signal.Signal {
	if prevVersion == "" || !semverutil.IsPatchBump(prevVersion, currentVersion) {
		return nil
	}
	prevMeta, prevOK := meta.Versions[prevVersion]
	currMeta, currOK := meta.Versions[currentVersion]
	if !prevOK || !currOK {
		return nil
	}

	var newDeps []string
	newDeps = appendNewKeys(newDeps, prevMeta.Dependencies, currMeta.Dependencies)
	newDeps = appendNewKeys(newDeps, prevMeta.DevDependencies, currMeta.DevDependencies)
	if len(newDeps) == 0 {
		return nil
	}

	score := v.newDepScore * float64(len(newDeps))
	if v.newDepCap > 0 && score > v.newDepCap {
		score = v.newDepCap
	}

	// Bound the detail string so we don't splash an arbitrarily long list
	// into the warning header.
	detail := "new_deps=" + joinLimited(newDeps, 5)

	return []signal.Signal{{
		Rule:   "version_diff_new_dependency",
		Score:  score,
		Detail: detail,
	}}
}

func appendNewKeys(out []string, prev, curr map[string]string) []string {
	for k := range curr {
		if _, existed := prev[k]; !existed {
			out = append(out, k)
		}
	}
	return out
}

func joinLimited(items []string, limit int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= limit {
		return strings.Join(items, ",")
	}
	return strings.Join(items[:limit], ",") + fmt.Sprintf(",(+%d more)", len(items)-limit)
}

func toSet(caps []string) map[string]bool {
	s := make(map[string]bool, len(caps))
	for _, c := range caps {
		s[c] = true
	}
	return s
}

