package calibrate

import (
	"fmt"
	"sort"

	"github.com/yourusername/npm-proxy/internal/policy"
)

// Label is the ground-truth class for a corpus entry.
type Label int

const (
	LabelBenign Label = iota
	LabelMalicious
)

func (l Label) String() string {
	if l == LabelMalicious {
		return "malicious"
	}
	return "benign"
}

// Metrics holds a 2x3 confusion matrix: ground-truth label × policy verdict.
// We don't collapse warn+block into a single "positive" class because the
// calibration objective treats them very differently:
//   - Block on benign  : hard error (install fails). Must approach zero.
//   - Warn on benign   : soft error (X-Security-Warning header). Tolerable.
//   - Block on malicious: ideal catch.
//   - Warn on malicious : soft catch (developer might still proceed).
//   - Allow on malicious: full miss.
type Metrics struct {
	BenignAllow, BenignWarn, BenignBlock          int
	MaliciousAllow, MaliciousWarn, MaliciousBlock int
}

// Totals.
func (m Metrics) Benign() int    { return m.BenignAllow + m.BenignWarn + m.BenignBlock }
func (m Metrics) Malicious() int { return m.MaliciousAllow + m.MaliciousWarn + m.MaliciousBlock }
func (m Metrics) Total() int     { return m.Benign() + m.Malicious() }

// HardFPRate is the fraction of benign packages that get hard-blocked. This
// is the developer-experience killer: every block here is a failed npm
// install on something legitimate. Production target: < 1%.
func (m Metrics) HardFPRate() float64 {
	if m.Benign() == 0 {
		return 0
	}
	return float64(m.BenignBlock) / float64(m.Benign())
}

// SoftFPRate is the fraction of benign packages that surface a warning. The
// install still succeeds, the developer sees a header. Production target:
// < 5% (anything higher and developers learn to ignore the channel).
func (m Metrics) SoftFPRate() float64 {
	if m.Benign() == 0 {
		return 0
	}
	return float64(m.BenignWarn) / float64(m.Benign())
}

// CatchRate is the fraction of malicious packages surfaced (warn OR block).
// "Caught" here just means the developer is no longer silently installing
// malware - they got at least a warning header.
func (m Metrics) CatchRate() float64 {
	if m.Malicious() == 0 {
		return 0
	}
	return float64(m.MaliciousWarn+m.MaliciousBlock) / float64(m.Malicious())
}

// BlockRate is the fraction of malicious packages hard-blocked. The actually
// stopped attacks; warned-but-installed packages don't count. Equivalent to
// recall for the block tier when reported alongside BlockPrecision.
func (m Metrics) BlockRate() float64 {
	if m.Malicious() == 0 {
		return 0
	}
	return float64(m.MaliciousBlock) / float64(m.Malicious())
}

// WarnRecall is the fraction of malicious packages surfaced *only* via the
// warn tier (excluding blocks). Reported separately from BlockRate so the
// dissertation can quote a strict block-tier recall and a permissive warn-tier
// recall as two distinct operating points instead of one aggregated catch.
func (m Metrics) WarnRecall() float64 {
	if m.Malicious() == 0 {
		return 0
	}
	return float64(m.MaliciousWarn) / float64(m.Malicious())
}

// BlockPrecision: when we issue a hard block, how often is that block
// justified? Anything below ~99% means our blocks are blocking real packages
// with non-trivial frequency.
func (m Metrics) BlockPrecision() float64 {
	d := float64(m.MaliciousBlock + m.BenignBlock)
	if d == 0 {
		return 0
	}
	return float64(m.MaliciousBlock) / d
}

// WarnPrecision: when we surface a warning, how often is it on a real
// malicious package? Drops near the malicious-class prior when warnings are
// noise (developers learn to ignore them). Above 0.95 means a warning header
// is genuinely worth reading.
func (m Metrics) WarnPrecision() float64 {
	d := float64(m.MaliciousWarn + m.BenignWarn)
	if d == 0 {
		return 0
	}
	return float64(m.MaliciousWarn) / d
}

// Score is the calibration objective. Two hard caps disqualify a config:
// HardFPRate above MaxHardFPRate (benign blocks) and SoftFPRate above
// MaxSoftFPRate (benign warnings - alarm fatigue). Within both caps we
// maximise CatchRate, with a small soft-FP penalty as a tiebreaker.
//
// Each infeasible region still ranks by catch as a small bonus so search can
// climb. Otherwise two configs sitting at the same FP "floor" tie and we
// never see catch improve through pure exploration.
func (m Metrics) Score(opts ScoreObjective) float64 {
	hard := m.HardFPRate()
	if hard > opts.MaxHardFPRate {
		return -1.0 - hard + 0.01*m.CatchRate()
	}
	soft := m.SoftFPRate()
	if opts.MaxSoftFPRate > 0 && soft > opts.MaxSoftFPRate {
		// Higher band than hard-cap violation: prefer "too many warns" over
		// "too many blocks", but still rank below any fully feasible config.
		return -0.5 - soft + 0.01*m.CatchRate()
	}
	// Feasible: maximise catch, lightly penalise soft FPs. Catch dominates -
	// FPs only matter as a tiebreaker between configs with equal catch.
	return m.CatchRate() - 0.1*soft
}

// ScoreObjective bundles the two hard caps the calibration objective honours.
// MaxHardFPRate stops the search from picking configs that hard-block benign
// packages (broken DX). MaxSoftFPRate stops it from choosing configs that
// warn on so many benign packages that the channel becomes noise (alarm
// fatigue). Catch is maximised under both caps.
type ScoreObjective struct {
	MaxHardFPRate float64 // typical: 0.01 - hard cap on benign blocks
	MaxSoftFPRate float64 // typical: 0.10 - hard cap on benign warnings; 0 disables
}

func (m Metrics) String() string {
	return fmt.Sprintf(
		"catch=%.3f block_recall=%.3f warn_recall=%.3f hard_fp=%.3f soft_fp=%.3f block_precision=%.3f warn_precision=%.3f "+
			"[B:allow=%d warn=%d block=%d | M:allow=%d warn=%d block=%d]",
		m.CatchRate(), m.BlockRate(), m.WarnRecall(), m.HardFPRate(), m.SoftFPRate(), m.BlockPrecision(), m.WarnPrecision(),
		m.BenignAllow, m.BenignWarn, m.BenignBlock,
		m.MaliciousAllow, m.MaliciousWarn, m.MaliciousBlock,
	)
}

// Tally accumulates a single (label, verdict) pair into the matrix.
func (m *Metrics) Tally(label Label, verdict policy.Verdict) {
	switch {
	case label == LabelBenign && verdict == policy.VerdictAllow:
		m.BenignAllow++
	case label == LabelBenign && verdict == policy.VerdictWarn:
		m.BenignWarn++
	case label == LabelBenign && verdict == policy.VerdictBlock:
		m.BenignBlock++
	case label == LabelMalicious && verdict == policy.VerdictAllow:
		m.MaliciousAllow++
	case label == LabelMalicious && verdict == policy.VerdictWarn:
		m.MaliciousWarn++
	case label == LabelMalicious && verdict == policy.VerdictBlock:
		m.MaliciousBlock++
	}
}

// PerCategory groups metrics by CorpusEntry.Category. Empty strings collect
// runs that had no category set.
func PerCategory(runs []*PackageRun, weights Weights, allow, block float64) map[string]Metrics {
	return PerCategoryWithMinCategories(runs, weights, allow, block, MinCategories)
}

func PerCategoryWithMinCategories(runs []*PackageRun, weights Weights, allow, block float64, minCategories int) map[string]Metrics {
	out := map[string]Metrics{}
	for _, r := range runs {
		key := r.Category
		if key == "" {
			key = "(uncategorised)"
		}
		d := ApplyWithMinCategories(r, weights, allow, block, minCategories)
		m := out[key]
		m.Tally(r.Label, d.Verdict)
		out[key] = m
	}
	return out
}

// Misclassification surfaces a single run for diagnostic reports. For benign
// runs, Verdict tells you whether it was warn (soft FP) or block (hard FP);
// for malicious runs, ClassNegative=allow means full miss, ClassPositive=warn
// means soft catch.
type Misclassification struct {
	Run     *PackageRun
	Score   float64
	Verdict policy.Verdict
	Rules   []string
}

// BenignBlocks lists benign runs that got hard-blocked - the prime offenders.
func BenignBlocks(runs []*PackageRun, weights Weights, allow, block float64) []Misclassification {
	return BenignBlocksWithMinCategories(runs, weights, allow, block, MinCategories)
}

func BenignBlocksWithMinCategories(runs []*PackageRun, weights Weights, allow, block float64, minCategories int) []Misclassification {
	return collect(runs, weights, allow, block, minCategories, func(r *PackageRun, v policy.Verdict) bool {
		return r.Label == LabelBenign && v == policy.VerdictBlock
	})
}

// BenignWarns lists benign runs that got warn verdicts - tolerable but worth
// reviewing if the soft FP rate creeps up.
func BenignWarns(runs []*PackageRun, weights Weights, allow, block float64) []Misclassification {
	return BenignWarnsWithMinCategories(runs, weights, allow, block, MinCategories)
}

func BenignWarnsWithMinCategories(runs []*PackageRun, weights Weights, allow, block float64, minCategories int) []Misclassification {
	return collect(runs, weights, allow, block, minCategories, func(r *PackageRun, v policy.Verdict) bool {
		return r.Label == LabelBenign && v == policy.VerdictWarn
	})
}

// MaliciousAllows lists malicious runs that got fully missed (allow verdict).
// These are the genuine misses - warned-but-installed malicious packages are
// excluded.
func MaliciousAllows(runs []*PackageRun, weights Weights, allow, block float64) []Misclassification {
	return MaliciousAllowsWithMinCategories(runs, weights, allow, block, MinCategories)
}

func MaliciousAllowsWithMinCategories(runs []*PackageRun, weights Weights, allow, block float64, minCategories int) []Misclassification {
	return collect(runs, weights, allow, block, minCategories, func(r *PackageRun, v policy.Verdict) bool {
		return r.Label == LabelMalicious && v == policy.VerdictAllow
	})
}

func collect(
	runs []*PackageRun,
	weights Weights,
	allow, block float64,
	minCategories int,
	keep func(*PackageRun, policy.Verdict) bool,
) []Misclassification {
	var out []Misclassification
	for _, r := range runs {
		d := ApplyWithMinCategories(r, weights, allow, block, minCategories)
		if !keep(r, d.Verdict) {
			continue
		}
		out = append(out, Misclassification{
			Run:     r,
			Score:   d.Score,
			Verdict: d.Verdict,
			Rules:   d.TriggeredRules,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
