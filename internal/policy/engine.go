package policy

import (
	"fmt"
	"strings"

	"github.com/yourusername/npm-proxy/internal/siem"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// Verdict is the final decision for a package request.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictWarn
	VerdictBlock
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictWarn:
		return "warn"
	case VerdictBlock:
		return "block"
	}
	return "unknown"
}

func (v Verdict) SIEMVerdict() siem.Verdict {
	switch v {
	case VerdictAllow:
		return siem.VerdictAllow
	case VerdictWarn:
		return siem.VerdictWarn
	default:
		return siem.VerdictBlock
	}
}

// Decision is the output of the policy engine for one request.
type Decision struct {
	Verdict        Verdict
	Score          float64
	TriggeredRules []string
	CWEIDs         []string
	VetoRule       string
	HTTPStatus     int
	WarningHeader  string
}

// Engine applies policy rules to an aggregated analysis result.
//
// minCategories raises the bar for warnings: if the aggregate score crosses
// the warn threshold but not the block threshold, the verdict is downgraded to
// allow unless rules from at least minCategories distinct categories fired
// (metadata, capability, install, sink, etc.). This guards against alarm
// fatigue from a single noisy rule with moderate weight. Set to 0 or 1 to
// disable gating.
//
// Vetos and score-based blocks always block regardless of category count.
type Engine struct {
	allowThreshold float64
	blockThreshold float64
	minCategories  int
}

func NewEngine(allowThreshold, blockThreshold float64, minCategories int) *Engine {
	return &Engine{
		allowThreshold: allowThreshold,
		blockThreshold: blockThreshold,
		minCategories:  minCategories,
	}
}

// Decide evaluates the analysis result and returns a Decision.
func (e *Engine) Decide(result *signal.Result) Decision {
	for _, s := range result.Signals {
		if s.Veto {
			return Decision{
				Verdict:        VerdictBlock,
				Score:          1.0,
				TriggeredRules: result.TriggeredRules(),
				CWEIDs:         result.CWEIDs(),
				VetoRule:       s.Rule,
				HTTPStatus:     403,
			}
		}
	}

	score := result.TotalScore()
	rules := result.TriggeredRules()
	cwes := result.CWEIDs()

	if score >= e.blockThreshold {
		return Decision{
			Verdict:        VerdictBlock,
			Score:          score,
			TriggeredRules: rules,
			CWEIDs:         cwes,
			HTTPStatus:     403,
		}
	}

	if score < e.allowThreshold {
		return Decision{
			Verdict:        VerdictAllow,
			Score:          score,
			TriggeredRules: rules,
			CWEIDs:         cwes,
			HTTPStatus:     200,
		}
	}

	// Multi-category gating applies only to warnings. A single noisy category
	// should not create alert fatigue, but block-level scores are treated as
	// strong enough evidence to stop the install.
	if e.minCategories > 1 && countCategories(rules) < e.minCategories {
		return Decision{
			Verdict:        VerdictAllow,
			Score:          score,
			TriggeredRules: rules,
			CWEIDs:         cwes,
			HTTPStatus:     200,
		}
	}

	return Decision{
		Verdict:        VerdictWarn,
		Score:          score,
		TriggeredRules: rules,
		CWEIDs:         cwes,
		HTTPStatus:     200,
		WarningHeader:  buildWarningHeader(score, rules),
	}
}

// ruleCategory groups rules into independent classes so the gating check can
// require evidence from multiple detectors. The mapping is by rule-name
// prefix - any new rule is automatically categorised by its existing prefix
// convention. Unknown rules fall into "other".
//
// Sinks and entropy are deliberately separate categories even though they
// are often correlated: a compromised library typically fires both, and we
// want that to count as 2 categories (so it passes the gate). Rolling them
// into one would mean such packages need a third detector to surface, which
// kills compromised_lib catch rate (we measured 95% → 1.4% during testing).
func ruleCategory(rule string) string {
	switch {
	case rule == "typosquat_with_install_script" ||
		rule == "install_script_with_exec" ||
		rule == "install_script_with_network" ||
		rule == "install_script_with_obfuscation":
		return "combo"
	case strings.HasPrefix(rule, "typosquat_"):
		return "typosquat"
	case strings.HasPrefix(rule, "metadata_"), strings.HasPrefix(rule, "license_"):
		return "metadata"
	case strings.HasPrefix(rule, "anomaly_"):
		return "anomaly"
	case strings.HasPrefix(rule, "install_script_"):
		return "install"
	case strings.HasPrefix(rule, "cap_"), strings.HasPrefix(rule, "capability_"):
		return "capability"
	case strings.HasPrefix(rule, "sink_"):
		return "sink"
	case rule == "entropy_obfuscation":
		return "entropy"
	case strings.HasPrefix(rule, "version_diff_"):
		return "version_diff"
	default:
		return "other"
	}
}

func countCategories(rules []string) int {
	seen := make(map[string]struct{})
	for _, r := range rules {
		seen[ruleCategory(r)] = struct{}{}
	}
	return len(seen)
}

func buildWarningHeader(score float64, rules []string) string {
	if len(rules) == 0 {
		return fmt.Sprintf("score=%.2f", score)
	}
	return fmt.Sprintf("score=%.2f rules=%v", score, rules)
}
