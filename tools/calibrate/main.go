package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/npm-proxy/internal/calibrate"
	"github.com/yourusername/npm-proxy/internal/config"
)

// Hardcoded paths and search hyperparameters. The CLI surface is intentionally
// small - only the flags that change behavior in a meaningful way are exposed.
// Override file locations by editing the constants if your project layout
// differs.
const (
	corpusDir           = "dataset"
	configPath          = "configs/proxy.yaml"
	outConfigPath       = "configs/proxy.calibrated.yaml"
	outCSVPath          = "calibration-report.csv"
	refineSteps         = 3
	valFraction         = 0.20
	seed          int64 = 1
)

func main() {
	var (
		trials    = flag.Int("trials", 700, "random-search trials per min_categories candidate (Phase A budget)")
		maxHardFP = flag.Float64("max-hard-fp", 0.01, "hard cap on benign-block rate; trials above this are disqualified")
		maxSoftFP = flag.Float64("max-soft-fp", 0.10, "hard cap on benign-warn rate (alarm fatigue); 0 disables")
		evalOnly  = flag.Bool("eval-only", false, "skip search; just score the baseline config against the corpus")
		stripOSV  = flag.Bool("strip-osv", false, "drop the OSV veto signal from cached runs to tune scored detectors without OSV dominating the loss")
		workers   = flag.Int("workers", runtime.NumCPU(), "parallel corpus-analysis workers; <=0 uses logical CPU count")
		minCats   = flag.String("min-categories", "1,2,3", "comma-separated policy.min_categories values to try; 0/1 disables gating")
	)
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	corpus, err := calibrate.LoadCorpus(corpusDir)
	if err != nil {
		log.Fatalf("load corpus: %v", err)
	}
	log.Printf("loaded %d corpus entries from %s", len(corpus), corpusDir)

	runner, err := calibrate.NewRunner(cfg)
	if err != nil {
		log.Fatalf("init runner: %v", err)
	}
	runner.StripOSV = *stripOSV
	if runner.StripOSV {
		log.Printf("strip-osv: OSV veto signals will be dropped from corpus runs")
	}
	calibrate.MinCategories = cfg.Policy.MinCategories

	start := time.Now()
	runs, dropped := runPipeline(context.Background(), runner, corpus, *workers, start)
	log.Printf("pipeline done: %d runs ready, %d dropped, %s elapsed", len(runs), dropped, time.Since(start).Truncate(time.Millisecond))

	base := calibrate.DefaultWeights(cfg)
	objective := calibrate.ScoreObjective{
		MaxHardFPRate: *maxHardFP,
		MaxSoftFPRate: *maxSoftFP,
	}
	minCategoryValues, err := parseMinCategories(*minCats)
	if err != nil {
		log.Fatalf("parse -min-categories: %v", err)
	}
	log.Printf("min_categories candidates: %v", minCategoryValues)

	if *evalOnly {
		m := calibrate.EvaluateWithMinCategories(runs, base, cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories)
		fmt.Printf("eval-only baseline on %d runs:\n  %s\n", len(runs), m.String())
		printPerCategory(runs, base, cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories)
		printBenignBlocks(runs, base, cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories, 20)
		printBenignWarns(runs, base, cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories, 10)
		printFinalStatistics("all runs", -1, 0, m, cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories, objective)
		return
	}

	train, val := calibrate.Split(runs, valFraction, seed)
	log.Printf("split: %d train, %d val", len(train), len(val))

	baseMet := calibrate.EvaluateWithMinCategories(val, base, cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories)
	log.Printf("baseline val: %s min_categories=%d", baseMet.String(), cfg.Policy.MinCategories)

	opts := calibrate.DefaultSearchOptions()
	opts.Trials = *trials
	opts.RefineSteps = refineSteps
	opts.Objective = objective
	opts.Seed = seed
	opts.MinCategories = minCategoryValues

	best, logTrials := calibrate.Search(train, val, base, opts)
	log.Printf("search complete: %d trials evaluated", len(logTrials))
	log.Printf("best val: %s allow=%.2f block=%.2f min_categories=%d", best.ValMet.String(), best.Allow, best.Block, best.MinCategories)

	if err := calibrate.WriteCSV(outCSVPath, logTrials, opts.Objective); err != nil {
		log.Fatalf("write CSV: %v", err)
	}
	log.Printf("wrote trial log: %s", outCSVPath)

	calibratedCfg := *cfg
	best.Weights.ApplyToConfig(&calibratedCfg)
	calibratedCfg.Policy.AllowThreshold = best.Allow
	calibratedCfg.Policy.BlockThreshold = best.Block
	calibratedCfg.Policy.MinCategories = best.MinCategories
	if err := calibrate.WriteCalibratedConfig(outConfigPath, &calibratedCfg); err != nil {
		log.Fatalf("write config: %v", err)
	}
	log.Printf("wrote calibrated config: %s", outConfigPath)

	// Headline improvement: did catch go up while staying within the FP caps?
	// Compare user-facing metrics directly so infeasible baselines do not look
	// better just because they catch more by warning/blocking benign packages.
	improvedCatch := best.ValMet.CatchRate() > baseMet.CatchRate()
	baseFeasible := respectsObjective(baseMet, opts.Objective)
	bestFeasible := respectsObjective(best.ValMet, opts.Objective)
	switch {
	case !bestFeasible:
		fmt.Fprintf(os.Stderr, "WARNING: best config still exceeds requested FP caps; inspect the FP tables below before using this config\n")
	case !improvedCatch && baseFeasible:
		fmt.Fprintf(os.Stderr, "WARNING: search did not improve catch rate over baseline; consider larger -trials or richer corpus\n")
	case !improvedCatch && !baseFeasible:
		fmt.Fprintf(os.Stderr, "NOTE: best config lowers catch versus the infeasible baseline while satisfying FP caps. "+
			"Treat this as a strict-DX profile; inspect the Pareto frontier and malicious misses below for recall trade-offs.\n")
	}

	printParetoFrontier(logTrials, opts.Objective, 12)
	printPerCategory(val, best.Weights, best.Allow, best.Block, best.MinCategories)
	printMaliciousMisses(val, best.Weights, best.Allow, best.Block, best.MinCategories, "malicious_intent", 20)
	printBenignBlocks(val, best.Weights, best.Allow, best.Block, best.MinCategories, 20)
	printBenignWarns(val, best.Weights, best.Allow, best.Block, best.MinCategories, 10)
	printFinalStatistics("selected best validation trial", best.Index, best.Score(opts.Objective), best.ValMet, best.Allow, best.Block, best.MinCategories, opts.Objective)
}

func respectsObjective(m calibrate.Metrics, obj calibrate.ScoreObjective) bool {
	if m.HardFPRate() > obj.MaxHardFPRate {
		return false
	}
	return obj.MaxSoftFPRate <= 0 || m.SoftFPRate() <= obj.MaxSoftFPRate
}

func parseMinCategories(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty list")
	}
	seen := map[int]struct{}{}
	values := make([]int, 0)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", part)
		}
		if v < 0 {
			return nil, fmt.Errorf("%q must be >= 0", part)
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	sort.Ints(values)
	return values, nil
}

type pipelineResult struct {
	index int
	run   *calibrate.PackageRun
	err   error
}

func runPipeline(
	ctx context.Context,
	runner *calibrate.Runner,
	corpus []calibrate.CorpusEntry,
	workers int,
	start time.Time,
) ([]*calibrate.PackageRun, int) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(corpus) && len(corpus) > 0 {
		workers = len(corpus)
	}
	log.Printf("analysis workers: %d", workers)

	jobs := make(chan int)
	results := make(chan pipelineResult)
	for w := 0; w < workers; w++ {
		go func() {
			for i := range jobs {
				r, err := runner.Run(ctx, corpus[i])
				results <- pipelineResult{index: i, run: r, err: err}
			}
		}()
	}

	go func() {
		for i := range corpus {
			jobs <- i
		}
		close(jobs)
	}()

	ordered := make([]*calibrate.PackageRun, len(corpus))
	dropped := 0
	completed := 0
	for completed < len(corpus) {
		res := <-results
		completed++
		if res.err != nil {
			e := corpus[res.index]
			log.Printf("skip %s@%s (%s): %v", e.Name, e.Version, e.Label, res.err)
			dropped++
		} else {
			ordered[res.index] = res.run
		}
		if completed%50 == 0 || completed == len(corpus) {
			log.Printf("analysed %d/%d (%.1f/s)", completed, len(corpus), float64(completed)/time.Since(start).Seconds())
		}
	}

	runs := make([]*calibrate.PackageRun, 0, len(corpus)-dropped)
	for _, r := range ordered {
		if r != nil {
			runs = append(runs, r)
		}
	}
	return runs, dropped
}

// printParetoFrontier shows non-dominated feasible trials by the three
// operator-facing axes: catch up, hard FP down, soft FP down. Block rate is
// printed as context, but not used for dominance so the table stays focused on
// the requested FP budgets.
func printParetoFrontier(trials []calibrate.Trial, obj calibrate.ScoreObjective, top int) {
	feasible := make([]calibrate.Trial, 0, len(trials))
	for _, t := range trials {
		if respectsObjective(t.ValMet, obj) {
			feasible = append(feasible, t)
		}
	}
	if len(feasible) == 0 {
		fmt.Println("pareto frontier: no feasible trials found under the requested FP caps")
		return
	}

	frontier := make([]calibrate.Trial, 0, len(feasible))
	for _, candidate := range feasible {
		dominated := false
		for _, other := range feasible {
			if other.Index == candidate.Index {
				continue
			}
			if dominatesTrial(other, candidate) {
				dominated = true
				break
			}
		}
		if !dominated {
			frontier = append(frontier, candidate)
		}
	}

	sort.Slice(frontier, func(i, j int) bool {
		mi, mj := frontier[i].ValMet, frontier[j].ValMet
		if mi.CatchRate() != mj.CatchRate() {
			return mi.CatchRate() > mj.CatchRate()
		}
		if mi.SoftFPRate() != mj.SoftFPRate() {
			return mi.SoftFPRate() < mj.SoftFPRate()
		}
		if mi.HardFPRate() != mj.HardFPRate() {
			return mi.HardFPRate() < mj.HardFPRate()
		}
		return mi.BlockRate() > mj.BlockRate()
	})
	frontier = uniqueFrontierPoints(frontier)

	fmt.Printf("pareto frontier (feasible trials=%d, frontier=%d, showing top %d by catch):\n",
		len(feasible), len(frontier), minInt(top, len(frontier)))
	for i, t := range frontier {
		if i >= top {
			break
		}
		m := t.ValMet
		fmt.Printf("  trial=%d score=%.4f allow=%.2f block=%.2f min_categories=%d catch=%.3f block_rate=%.3f hard_fp=%.3f soft_fp=%.3f warn_precision=%.3f\n",
			t.Index, t.Score(obj), t.Allow, t.Block, t.MinCategories,
			m.CatchRate(), m.BlockRate(), m.HardFPRate(), m.SoftFPRate(), m.WarnPrecision())
	}
}

func dominatesTrial(a, b calibrate.Trial) bool {
	am, bm := a.ValMet, b.ValMet
	beatsOrTies := am.CatchRate() >= bm.CatchRate() &&
		am.HardFPRate() <= bm.HardFPRate() &&
		am.SoftFPRate() <= bm.SoftFPRate()
	strictlyBetter := am.CatchRate() > bm.CatchRate() ||
		am.HardFPRate() < bm.HardFPRate() ||
		am.SoftFPRate() < bm.SoftFPRate()
	return beatsOrTies && strictlyBetter
}

func uniqueFrontierPoints(frontier []calibrate.Trial) []calibrate.Trial {
	seen := make(map[string]struct{}, len(frontier))
	unique := make([]calibrate.Trial, 0, len(frontier))
	for _, t := range frontier {
		key := frontierPointKey(t.ValMet)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, t)
	}
	return unique
}

func frontierPointKey(m calibrate.Metrics) string {
	return fmt.Sprintf("%d/%d/%d/%d/%d/%d",
		m.BenignAllow, m.BenignWarn, m.BenignBlock,
		m.MaliciousAllow, m.MaliciousWarn, m.MaliciousBlock)
}

// printMaliciousMisses lists malicious packages that stayed below the allow
// threshold. Sorting by score descending shows misses closest to surfacing.
func printMaliciousMisses(
	runs []*calibrate.PackageRun,
	w calibrate.Weights,
	allow, block float64,
	minCategories int,
	category string,
	top int,
) {
	all := calibrate.MaliciousAllowsWithMinCategories(runs, w, allow, block, minCategories)
	misses := make([]calibrate.Misclassification, 0, len(all))
	for _, m := range all {
		if category == "" || m.Run.Category == category {
			misses = append(misses, m)
		}
	}
	if len(misses) == 0 {
		if category == "" {
			fmt.Println("malicious misses: none")
		} else {
			fmt.Printf("malicious misses [%s]: none\n", category)
		}
		return
	}

	label := category
	if label == "" {
		label = "all"
	}
	fmt.Printf("malicious misses [%s] (allow verdicts, %d total, showing top %d closest to allow=%.2f min_categories=%d):\n",
		label, len(misses), minInt(top, len(misses)), allow, minCategories)
	for i, m := range misses {
		if i >= top {
			break
		}
		cat := m.Run.Category
		if cat == "" {
			cat = "(uncategorised)"
		}
		fmt.Printf("  score=%.2f margin=%.2f  %s@%s  [%s]  rules=%v\n",
			m.Score, allow-m.Score, m.Run.Name, m.Run.Version, cat, m.Rules)
	}
	printRuleHistogramWithTitle(misses, "rules present in these misses (rule -> packages affected):")
}

// printBenignBlocks lists benign packages that got hard-blocked. These are the
// developer-experience killers - every entry here is an `npm install` that
// fails on something legitimate. Production target is zero.
func printBenignBlocks(runs []*calibrate.PackageRun, w calibrate.Weights, allow, block float64, minCategories int, top int) {
	bbs := calibrate.BenignBlocksWithMinCategories(runs, w, allow, block, minCategories)
	if len(bbs) == 0 {
		fmt.Println("benign blocks: none")
		return
	}
	fmt.Printf("benign blocks (HARD FPs, %d total, showing top %d):\n", len(bbs), minInt(top, len(bbs)))
	for i, m := range bbs {
		if i >= top {
			break
		}
		fmt.Printf("  score=%.2f  %s@%s  [%s]  rules=%v\n",
			m.Score, m.Run.Name, m.Run.Version, m.Run.Category, m.Rules)
	}
	printRuleHistogram(bbs)
}

// printBenignWarns lists benign packages that got warned. These are the
// soft-FP cost - install still succeeds but a warning header is shown. A
// sustained high count here makes the channel noise that developers ignore.
func printBenignWarns(runs []*calibrate.PackageRun, w calibrate.Weights, allow, block float64, minCategories int, top int) {
	bws := calibrate.BenignWarnsWithMinCategories(runs, w, allow, block, minCategories)
	if len(bws) == 0 {
		fmt.Println("benign warnings: none")
		return
	}
	fmt.Printf("benign warnings (SOFT FPs, %d total, showing top %d):\n", len(bws), minInt(top, len(bws)))
	for i, m := range bws {
		if i >= top {
			break
		}
		fmt.Printf("  score=%.2f  %s@%s  [%s]  rules=%v\n",
			m.Score, m.Run.Name, m.Run.Version, m.Run.Category, m.Rules)
	}
}

// printRuleHistogram shows which rules are driving the FPs - the first row is
// the prime candidate for a weight cut.
func printRuleHistogram(items []calibrate.Misclassification) {
	printRuleHistogramWithTitle(items, "rules driving the above (rule -> packages affected):")
}

func printRuleHistogramWithTitle(items []calibrate.Misclassification, title string) {
	count := map[string]int{}
	noRules := 0
	for _, m := range items {
		if len(m.Rules) == 0 {
			noRules++
			continue
		}
		for _, r := range m.Rules {
			count[r]++
		}
	}
	type rc struct {
		rule string
		n    int
	}
	ranked := make([]rc, 0, len(count))
	for r, n := range count {
		ranked = append(ranked, rc{r, n})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].n != ranked[j].n {
			return ranked[i].n > ranked[j].n
		}
		return ranked[i].rule < ranked[j].rule
	})
	fmt.Println(title)
	if noRules > 0 {
		fmt.Printf("  %-40s %d\n", "(no rules)", noRules)
	}
	for _, r := range ranked {
		fmt.Printf("  %-40s %d\n", r.rule, r.n)
	}
}

func printPerCategory(runs []*calibrate.PackageRun, w calibrate.Weights, allow, block float64, minCategories int) {
	cat := calibrate.PerCategoryWithMinCategories(runs, w, allow, block, minCategories)
	if len(cat) <= 1 {
		return
	}
	fmt.Println("per-category breakdown:")
	keys := make([]string, 0, len(cat))
	for k := range cat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-20s %s\n", k, cat[k].String())
	}
}

func printFinalStatistics(
	label string,
	trialIndex int,
	objectiveScore float64,
	m calibrate.Metrics,
	allow, block float64,
	minCategories int,
	obj calibrate.ScoreObjective,
) {
	benign := m.Benign()
	malicious := m.Malicious()
	caught := m.MaliciousWarn + m.MaliciousBlock
	fp := m.BenignWarn + m.BenignBlock
	feasible := respectsObjective(m, obj)
	softCap := fmt.Sprintf("%.3f", obj.MaxSoftFPRate)
	if obj.MaxSoftFPRate <= 0 {
		softCap = "disabled"
	}

	fmt.Printf("final statistics (%s):\n", label)
	if trialIndex >= 0 {
		fmt.Printf("  selected_trial=%d objective_score=%.4f metrics=%s\n",
			trialIndex, objectiveScore, m.String())
	}
	fmt.Printf("  config: allow=%.2f block=%.2f min_categories=%d feasible=%t fp_caps: warn<=%s block<=%.3f\n",
		allow, block, minCategories, feasible, softCap, obj.MaxHardFPRate)
	fmt.Printf("  catch=%.3f (%d/%d malicious surfaced)\n",
		m.CatchRate(), caught, malicious)
	fmt.Printf("  warn=%.3f (%d/%d malicious warned)\n",
		rate(m.MaliciousWarn, malicious), m.MaliciousWarn, malicious)
	fmt.Printf("  block=%.3f (%d/%d malicious blocked)\n",
		m.BlockRate(), m.MaliciousBlock, malicious)
	fmt.Printf("  miss=%.3f (%d/%d malicious allowed)\n",
		rate(m.MaliciousAllow, malicious), m.MaliciousAllow, malicious)
	fmt.Printf("  warn_fp=%.3f (%d/%d benign warned)\n",
		m.SoftFPRate(), m.BenignWarn, benign)
	fmt.Printf("  block_fp=%.3f (%d/%d benign blocked)\n",
		m.HardFPRate(), m.BenignBlock, benign)
	fmt.Printf("  total_fp=%.3f (%d/%d benign warned_or_blocked)\n",
		rate(fp, benign), fp, benign)
	fmt.Printf("  warn_precision=%.3f block_precision=%.3f\n",
		m.WarnPrecision(), m.BlockPrecision())
	fmt.Printf("  confusion: B:allow=%d warn=%d block=%d | M:allow=%d warn=%d block=%d\n",
		m.BenignAllow, m.BenignWarn, m.BenignBlock,
		m.MaliciousAllow, m.MaliciousWarn, m.MaliciousBlock)
}

func rate(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
