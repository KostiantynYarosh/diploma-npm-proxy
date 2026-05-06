package calibrate

import (
	"math/rand"
	"sort"
)

// Trial is one configuration evaluated against the corpus.
type Trial struct {
	Index         int
	Weights       Weights
	Allow         float64
	Block         float64
	MinCategories int
	TrainMet      Metrics
	ValMet        Metrics
}

// Score returns the objective value used to rank trials. Higher is better.
func (t Trial) Score(obj ScoreObjective) float64 {
	return t.ValMet.Score(obj)
}

// SearchOptions controls the search loop.
type SearchOptions struct {
	Trials        int     // total random-search trials (Phase A)
	RefineSteps   int     // coordinate-descent passes (Phase B); 0 disables
	StepSize      float64 // grid step for coordinate descent (e.g. 0.05)
	Objective     ScoreObjective
	Seed          int64
	WeightMin     float64 // sampling lower bound
	WeightMax     float64 // sampling upper bound
	AllowRange    [2]float64
	BlockRange    [2]float64
	MinCategories []int
}

// DefaultSearchOptions returns sane defaults: 700 random trials, 3 refinement
// passes at step 0.05 over [0,1]. The objective caps benign-block rate at 1%
// and benign-warn rate at 10%, then maximises catch under both caps.
func DefaultSearchOptions() SearchOptions {
	return SearchOptions{
		Trials:      700,
		RefineSteps: 3,
		StepSize:    0.05,
		Objective: ScoreObjective{
			MaxHardFPRate: 0.01,
			MaxSoftFPRate: 0.10,
		},
		Seed:          1,
		WeightMin:     0.0,
		WeightMax:     1.0,
		AllowRange:    [2]float64{0.10, 0.60},
		BlockRange:    [2]float64{0.40, 0.95},
		MinCategories: []int{MinCategories},
	}
}

// Split divides runs into train/val by deterministic hash so the same corpus
// always splits the same way regardless of corpus order. Stratified per
// label - both classes appear in both splits even with skewed inputs.
func Split(runs []*PackageRun, valFraction float64, seed int64) (train, val []*PackageRun) {
	rng := rand.New(rand.NewSource(seed))
	byLabel := map[Label][]*PackageRun{}
	for _, r := range runs {
		byLabel[r.Label] = append(byLabel[r.Label], r)
	}
	for _, group := range byLabel {
		// Shuffle group deterministically. Sort first to guarantee the same
		// pre-shuffle order regardless of caller-side ordering.
		sort.Slice(group, func(i, j int) bool { return group[i].SHA256 < group[j].SHA256 })
		rng.Shuffle(len(group), func(i, j int) { group[i], group[j] = group[j], group[i] })
		nVal := int(float64(len(group)) * valFraction)
		val = append(val, group[:nVal]...)
		train = append(train, group[nVal:]...)
	}
	return train, val
}

// Evaluate scores a (weights, allow, block) configuration against a slice of
// runs and returns the resulting 2x3 confusion matrix.
func Evaluate(runs []*PackageRun, weights Weights, allow, block float64) Metrics {
	return EvaluateWithMinCategories(runs, weights, allow, block, MinCategories)
}

// EvaluateWithMinCategories scores a configuration with an explicit category
// gate value. This is what lets the calibrator tune min_categories instead of
// treating it as a fixed global.
func EvaluateWithMinCategories(runs []*PackageRun, weights Weights, allow, block float64, minCategories int) Metrics {
	var m Metrics
	for _, r := range runs {
		d := ApplyWithMinCategories(r, weights, allow, block, minCategories)
		m.Tally(r.Label, d.Verdict)
	}
	return m
}

// Search runs random search followed by optional coordinate descent. The best
// Trial under the configured ScoreObjective is returned alongside the full
// trial log so callers can write CSV reports or run held-out evaluation.
func Search(train, val []*PackageRun, base Weights, opts SearchOptions) (best Trial, log []Trial) {
	obj := opts.Objective
	minCategories := normalizeMinCategories(opts.MinCategories)
	haveBest := false

	for _, minCat := range minCategories {
		branchBest, branchLog := searchOneMinCategory(train, val, base, opts, minCat)
		_ = branchBest
		for _, t := range branchLog {
			t.Index = len(log)
			log = append(log, t)
			if !haveBest || t.Score(obj) > best.Score(obj) {
				best = t
				haveBest = true
			}
		}
	}

	return best, log
}

func searchOneMinCategory(train, val []*PackageRun, base Weights, opts SearchOptions, minCategories int) (best Trial, log []Trial) {
	rng := rand.New(rand.NewSource(opts.Seed))
	obj := opts.Objective

	// Phase A: random search.
	for i := 0; i < opts.Trials; i++ {
		w := sampleWeights(rng, base, opts.WeightMin, opts.WeightMax)
		allow := sampleRange(rng, opts.AllowRange)
		block := sampleRange(rng, opts.BlockRange)
		if block <= allow {
			block = allow + opts.StepSize
		}
		t := Trial{
			Index:         len(log),
			Weights:       w,
			Allow:         allow,
			Block:         block,
			MinCategories: minCategories,
			TrainMet:      EvaluateWithMinCategories(train, w, allow, block, minCategories),
			ValMet:        EvaluateWithMinCategories(val, w, allow, block, minCategories),
		}
		log = append(log, t)
		if len(log) == 1 || t.Score(obj) > best.Score(obj) {
			best = t
		}
	}

	if len(log) == 0 {
		return best, log
	}

	// Phase B: coordinate descent starting from the best random trial.
	for pass := 0; pass < opts.RefineSteps; pass++ {
		improved := false
		for _, key := range append([]string{}, TunableRules...) {
			cur := best.Weights[key]
			for v := opts.WeightMin; v <= opts.WeightMax+1e-9; v += opts.StepSize {
				if v == cur {
					continue
				}
				w := best.Weights.Clone()
				w[key] = v
				t := Trial{
					Index:         len(log),
					Weights:       w,
					Allow:         best.Allow,
					Block:         best.Block,
					MinCategories: best.MinCategories,
					TrainMet:      EvaluateWithMinCategories(train, w, best.Allow, best.Block, best.MinCategories),
					ValMet:        EvaluateWithMinCategories(val, w, best.Allow, best.Block, best.MinCategories),
				}
				log = append(log, t)
				if t.Score(obj) > best.Score(obj) {
					best = t
					improved = true
				}
			}
		}
		// Threshold sweep (allow then block).
		for _, axis := range []string{"allow", "block"} {
			r := opts.AllowRange
			if axis == "block" {
				r = opts.BlockRange
			}
			for v := r[0]; v <= r[1]+1e-9; v += opts.StepSize {
				w := best.Weights.Clone()
				allow, block := best.Allow, best.Block
				if axis == "allow" {
					allow = v
				} else {
					block = v
				}
				if block <= allow {
					continue
				}
				t := Trial{
					Index:         len(log),
					Weights:       w,
					Allow:         allow,
					Block:         block,
					MinCategories: best.MinCategories,
					TrainMet:      EvaluateWithMinCategories(train, w, allow, block, best.MinCategories),
					ValMet:        EvaluateWithMinCategories(val, w, allow, block, best.MinCategories),
				}
				log = append(log, t)
				if t.Score(obj) > best.Score(obj) {
					best = t
					improved = true
				}
			}
		}
		if !improved {
			break
		}
	}

	return best, log
}

// sampleWeights draws a fresh weight vector. base is included only for its
// keys - existing values are not used as priors so the random phase explores
// the full hypercube.
func sampleWeights(rng *rand.Rand, base Weights, lo, hi float64) Weights {
	w := make(Weights, len(base))
	for k := range base {
		w[k] = lo + rng.Float64()*(hi-lo)
	}
	return w
}

func sampleRange(rng *rand.Rand, r [2]float64) float64 {
	return r[0] + rng.Float64()*(r[1]-r[0])
}

func normalizeMinCategories(values []int) []int {
	if len(values) == 0 {
		return []int{MinCategories}
	}
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, v := range values {
		if v < 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return []int{MinCategories}
	}
	sort.Ints(out)
	return out
}
