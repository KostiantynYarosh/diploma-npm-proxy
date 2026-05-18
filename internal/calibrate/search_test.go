package calibrate

import (
	"math"
	"testing"
)

func init() {
	// Disable multi-category gating in unit tests: the tiny synthetic corpora
	// here use single-rule packages where gating would always downgrade to
	// allow. End-to-end tests in pipeline_test.go cover gating explicitly.
	MinCategories = 0
}

// makeRun builds a synthetic PackageRun with a single rule firing. This lets
// us test Apply / Search without invoking the full pipeline.
func makeRun(name string, label Label, rules []string, veto bool) *PackageRun {
	sigs := make([]CachedSignal, 0, len(rules))
	for _, r := range rules {
		sigs = append(sigs, CachedSignal{Rule: r, Veto: veto})
	}
	return &PackageRun{Name: name, Version: "1.0.0", SHA256: name, Label: label, Signals: sigs}
}

func TestApplyRespectsVeto(t *testing.T) {
	r := makeRun("evil", LabelMalicious, []string{"osv_known_vulnerability"}, true)
	d := Apply(r, Weights{}, 0.30, 0.70)
	if d.Verdict.String() != "block" {
		t.Errorf("veto must block regardless of weights, got %s", d.Verdict)
	}
}

func TestApplyUsesWeights(t *testing.T) {
	r := makeRun("susp", LabelMalicious, []string{"cap_exec", "cap_net"}, false)
	low := Apply(r, Weights{"cap_exec": 0.10, "cap_net": 0.10}, 0.30, 0.70)
	high := Apply(r, Weights{"cap_exec": 0.50, "cap_net": 0.40}, 0.30, 0.70)
	if low.Verdict.String() != "allow" {
		t.Errorf("0.10+0.10=0.20 < allow=0.30 must allow, got %s", low.Verdict)
	}
	if high.Verdict.String() != "block" {
		t.Errorf("0.50+0.40=0.90 >= block=0.70 must block, got %s", high.Verdict)
	}
}

func TestApplyMapsConcreteDetectorRulesToTunableWeights(t *testing.T) {
	r := makeRun("susp", LabelMalicious, []string{
		"capability_exec",
		"obfuscation_high_entropy",
		"install_script_external_url_preinstall",
		"version_diff_new_script_postinstall",
		"sink_eval",
		"anomaly_version_spike",
		"license_patch_change",
	}, false)
	d := Apply(r, Weights{
		"cap_exec":                         0.05,
		"entropy_obfuscation":              0.05,
		"install_script_external_url":      0.05,
		"version_diff_new_script_in_patch": 0.05,
		"sink_alone":                       0.05,
		"anomaly_release_burst":            0.05,
		"license_changed_in_patch":         0.05,
	}, 0.30, 0.70)
	if math.Abs(d.Score-0.35) > 1e-9 {
		t.Fatalf("mapped score: got %.2f want 0.35", d.Score)
	}
	if d.Verdict.String() != "warn" {
		t.Fatalf("mapped score should cross warn threshold, got %s", d.Verdict)
	}
}

func TestApplyFallsBackToOriginalScoreForUntunedRules(t *testing.T) {
	r := &PackageRun{
		Name:    "fixed",
		Version: "1.0.0",
		SHA256:  "fixed",
		Label:   LabelMalicious,
		Signals: []CachedSignal{
			{Rule: "metadata_single_maintainer", Score: 0.05},
			{Rule: "unknown_fixed_signal", Score: 0.20},
		},
	}
	d := Apply(r, Weights{}, 0.20, 0.70)
	if math.Abs(d.Score-0.25) > 1e-9 {
		t.Fatalf("fallback score: got %.2f want 0.25", d.Score)
	}
	if d.Verdict.String() != "warn" {
		t.Fatalf("fallback score should cross warn threshold, got %s", d.Verdict)
	}
}

func TestEvaluateWithMinCategoriesGatesWarnsButNotBlocks(t *testing.T) {
	r := makeRun("install-only", LabelMalicious, []string{
		"install_script_child_process_preinstall",
		"install_script_node_eval_preinstall",
	}, false)
	w := Weights{
		"install_script_child_process": 0.50,
		"install_script_node_eval":     0.50,
	}
	ungated := EvaluateWithMinCategories([]*PackageRun{r}, w, 0.30, 0.70, 1)
	gated := EvaluateWithMinCategories([]*PackageRun{r}, w, 0.30, 0.70, 2)
	if ungated.BlockRate() != 1 {
		t.Fatalf("min_categories=1 should block install-only high score, got %s", ungated.String())
	}
	if gated.BlockRate() != 1 {
		t.Fatalf("min_categories=2 should not gate block-threshold evidence, got %s", gated.String())
	}

	warnOnly := EvaluateWithMinCategories([]*PackageRun{r}, w, 0.30, 1.20, 2)
	if warnOnly.CatchRate() != 0 {
		t.Fatalf("min_categories=2 should gate single-category warn evidence to allow, got %s", warnOnly.String())
	}
}

func TestSplitStratifies(t *testing.T) {
	runs := []*PackageRun{}
	for i := 0; i < 10; i++ {
		runs = append(runs, makeRun("m"+string(rune(i)), LabelMalicious, []string{"x"}, false))
		runs = append(runs, makeRun("b"+string(rune(i)), LabelBenign, []string{"x"}, false))
	}
	train, val := Split(runs, 0.20, 42)
	if len(val) == 0 || len(train) == 0 {
		t.Fatalf("split empty: train=%d val=%d", len(train), len(val))
	}
	countLabels := func(rs []*PackageRun) (int, int) {
		var m, b int
		for _, r := range rs {
			if r.Label == LabelMalicious {
				m++
			} else {
				b++
			}
		}
		return m, b
	}
	tm, tb := countLabels(train)
	vm, vb := countLabels(val)
	if tm == 0 || tb == 0 || vm == 0 || vb == 0 {
		t.Errorf("split is not stratified: train M=%d B=%d val M=%d B=%d", tm, tb, vm, vb)
	}
}

func TestSearchConvergesOnSeparableCorpus(t *testing.T) {
	// Tiny golden corpus: malicious always fires "evil_rule", benign always
	// fires "noise_rule". A working search must drive evil_rule weight high
	// and noise_rule low, hitting catch=1.0 with no benign blocks.
	var runs []*PackageRun
	for i := 0; i < 20; i++ {
		runs = append(runs, makeRun("m"+string(rune('a'+i)), LabelMalicious, []string{"evil_rule"}, false))
		runs = append(runs, makeRun("b"+string(rune('a'+i)), LabelBenign, []string{"noise_rule"}, false))
	}
	train, val := Split(runs, 0.30, 1)

	base := Weights{"evil_rule": 0.10, "noise_rule": 0.50}
	opts := DefaultSearchOptions()
	opts.Trials = 50
	opts.RefineSteps = 1
	opts.Objective = ScoreObjective{MaxHardFPRate: 0.10}
	opts.Seed = 1

	best, log := Search(train, val, base, opts)
	if len(log) < opts.Trials {
		t.Fatalf("search did not run all trials: got %d", len(log))
	}
	if best.ValMet.CatchRate() < 0.9 {
		t.Errorf("expected catch>=0.9 on a separable corpus, got %s", best.ValMet.String())
	}
	if best.ValMet.HardFPRate() > 0.10 {
		t.Errorf("expected hard FP rate <=0.10, got %s", best.ValMet.String())
	}
}

func TestSearchRefinesEachMinCategoryBranch(t *testing.T) {
	runs := []*PackageRun{
		makeRun("m", LabelMalicious, []string{"evil_rule"}, false),
		makeRun("b", LabelBenign, []string{"noise_rule"}, false),
	}
	base := Weights{"evil_rule": 0.10, "noise_rule": 0.10}
	opts := DefaultSearchOptions()
	opts.Trials = 1
	opts.RefineSteps = 1
	opts.StepSize = 0.50
	opts.MinCategories = []int{1, 2}
	opts.Seed = 1

	_, log := Search(runs, runs, base, opts)
	countByMin := map[int]int{}
	for _, t := range log {
		countByMin[t.MinCategories]++
	}
	for _, minCat := range opts.MinCategories {
		if countByMin[minCat] <= opts.Trials {
			t.Fatalf("min_categories=%d was not refined independently; counts=%v", minCat, countByMin)
		}
	}
}
