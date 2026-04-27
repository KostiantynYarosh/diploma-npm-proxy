package policy

import (
	"fmt"

	"github.com/yourusername/npm-proxy/internal/signal"
	"github.com/yourusername/npm-proxy/internal/siem"
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
type Engine struct {
	allowThreshold float64
	blockThreshold float64
}

func NewEngine(allowThreshold, blockThreshold float64) *Engine {
	return &Engine{
		allowThreshold: allowThreshold,
		blockThreshold: blockThreshold,
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

	switch {
	case score >= e.blockThreshold:
		return Decision{
			Verdict:        VerdictBlock,
			Score:          score,
			TriggeredRules: rules,
			CWEIDs:         cwes,
			HTTPStatus:     403,
		}
	case score >= e.allowThreshold:
		return Decision{
			Verdict:        VerdictWarn,
			Score:          score,
			TriggeredRules: rules,
			CWEIDs:         cwes,
			HTTPStatus:     200,
			WarningHeader:  buildWarningHeader(score, rules),
		}
	default:
		return Decision{
			Verdict:        VerdictAllow,
			Score:          score,
			TriggeredRules: rules,
			CWEIDs:         cwes,
			HTTPStatus:     200,
		}
	}
}

func buildWarningHeader(score float64, rules []string) string {
	if len(rules) == 0 {
		return fmt.Sprintf("score=%.2f", score)
	}
	return fmt.Sprintf("score=%.2f rules=%v", score, rules)
}
