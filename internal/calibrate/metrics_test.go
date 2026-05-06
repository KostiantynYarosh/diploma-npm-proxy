package calibrate

import (
	"math"
	"testing"

	"github.com/yourusername/npm-proxy/internal/policy"
)

func TestMetricsTally(t *testing.T) {
	var m Metrics
	cases := []struct {
		label   Label
		verdict policy.Verdict
	}{
		{LabelMalicious, policy.VerdictBlock}, // catch
		{LabelMalicious, policy.VerdictWarn},  // soft catch
		{LabelMalicious, policy.VerdictAllow}, // miss
		{LabelBenign, policy.VerdictBlock},    // hard FP
		{LabelBenign, policy.VerdictWarn},     // soft FP
		{LabelBenign, policy.VerdictAllow},    // ok
		{LabelBenign, policy.VerdictAllow},    // ok
	}
	for _, c := range cases {
		m.Tally(c.label, c.verdict)
	}
	if m.MaliciousBlock != 1 || m.MaliciousWarn != 1 || m.MaliciousAllow != 1 {
		t.Errorf("malicious row wrong: %+v", m)
	}
	if m.BenignBlock != 1 || m.BenignWarn != 1 || m.BenignAllow != 2 {
		t.Errorf("benign row wrong: %+v", m)
	}
	if math.Abs(m.CatchRate()-2.0/3.0) > 1e-9 {
		t.Errorf("catch rate: got %v want 0.667", m.CatchRate())
	}
	if math.Abs(m.HardFPRate()-1.0/4.0) > 1e-9 {
		t.Errorf("hard FP rate: got %v want 0.25", m.HardFPRate())
	}
}

func TestScoreHardCapDisqualifies(t *testing.T) {
	// One config has higher catch but violates the hard-FP cap; the other has
	// lower catch but clean FP. Cap-violator must rank below cap-respecter
	// regardless of catch.
	highCatchHighFP := Metrics{
		BenignAllow: 5, BenignBlock: 5, // hard FP rate 0.5
		MaliciousAllow: 1, MaliciousBlock: 9, // catch 0.9
	}
	lowerCatchCleanFP := Metrics{
		BenignAllow: 10, // hard FP rate 0
		MaliciousAllow: 4, MaliciousWarn: 6, // catch 0.6
	}
	obj := ScoreObjective{MaxHardFPRate: 0.01}
	if highCatchHighFP.Score(obj) >= lowerCatchCleanFP.Score(obj) {
		t.Errorf("hard-FP violator (%.3f) must rank below cap-respecter (%.3f)",
			highCatchHighFP.Score(obj), lowerCatchCleanFP.Score(obj))
	}
}

func TestScorePrefersHigherCatch(t *testing.T) {
	// Both clean on hard FP. The one with higher catch must win.
	highCatch := Metrics{
		BenignAllow:    10,
		MaliciousAllow: 1, MaliciousBlock: 9, // catch 0.9
	}
	lowCatch := Metrics{
		BenignAllow:    10,
		MaliciousAllow: 5, MaliciousWarn: 5, // catch 0.5
	}
	obj := ScoreObjective{MaxHardFPRate: 0.01}
	if highCatch.Score(obj) <= lowCatch.Score(obj) {
		t.Errorf("higher catch (%.3f) must win over lower catch (%.3f)",
			highCatch.Score(obj), lowCatch.Score(obj))
	}
}

func TestWarnPrecision(t *testing.T) {
	m := Metrics{
		BenignWarn: 2, MaliciousWarn: 8, // 8/10
	}
	if got := m.WarnPrecision(); math.Abs(got-0.8) > 1e-9 {
		t.Errorf("warn precision: got %v want 0.8", got)
	}
	empty := Metrics{}
	if empty.WarnPrecision() != 0 {
		t.Errorf("empty warn precision must be 0, got %v", empty.WarnPrecision())
	}
}

func TestSoftFPCapDisqualifies(t *testing.T) {
	noisy := Metrics{
		BenignAllow: 70, BenignWarn: 30, // soft fp 0.30
		MaliciousAllow: 1, MaliciousBlock: 9, // catch 0.9
	}
	cleanWarns := Metrics{
		BenignAllow: 99, BenignWarn: 1, // soft fp 0.01
		MaliciousAllow: 5, MaliciousWarn: 5, // catch 0.5
	}
	obj := ScoreObjective{MaxHardFPRate: 0.01, MaxSoftFPRate: 0.10}
	if noisy.Score(obj) >= cleanWarns.Score(obj) {
		t.Errorf("soft-FP violator (%.3f) must rank below cap-respecter (%.3f)",
			noisy.Score(obj), cleanWarns.Score(obj))
	}
}

func TestScorePrefersFewerSoftFPs(t *testing.T) {
	// Same catch and hard FP, but one warns more benign packages. The one
	// with fewer soft FPs must win as a tiebreaker.
	cleaner := Metrics{
		BenignAllow: 9, BenignWarn: 1,
		MaliciousAllow: 4, MaliciousBlock: 6,
	}
	noisier := Metrics{
		BenignAllow: 3, BenignWarn: 7,
		MaliciousAllow: 4, MaliciousBlock: 6,
	}
	obj := ScoreObjective{MaxHardFPRate: 0.01}
	if cleaner.Score(obj) <= noisier.Score(obj) {
		t.Errorf("cleaner soft-FP profile (%.3f) must outrank noisier (%.3f)",
			cleaner.Score(obj), noisier.Score(obj))
	}
}
