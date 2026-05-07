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
	// BaseAllow/BaseBlock anchor the baseline-seeded coordinate descent. Zero
	// values fall back to the midpoints of AllowRange / BlockRange.
	BaseAllow float64
	BaseBlock float64
	// PriorSigma is the standard deviation used when sampling weights as a
	// truncated normal around the baseline weight vector. Zero falls back to
	// 0.25, which keeps roughly 95% of draws within ±0.5 of baseline.
	PriorSigma float64
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
	sigma := opts.PriorSigma
	if sigma <= 0 {
		sigma = 0.25
	}

	// Phase A: random search seeded by the baseline weight vector. Each weight
	// is drawn from a truncated normal centered on base[k] with sigma=0.25,
	// clipped to [WeightMin, WeightMax]. This keeps random exploration honest
	// about the baseline prior instead of shredding the hand-tuned weights.
	for i := 0; i < opts.Trials; i++ {
		w := sampleWeights(rng, base, opts.WeightMin, opts.WeightMax, sigma)
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

	// Phase B: run coordinate descent from two seeds and keep whichever lands
	// higher. The random-phase winner explores wide priors; the baseline seed
	// preserves the curated weight vector even when Phase A drifted away from
	// it. The combined log is the concatenation - both tracks are recorded.
	randomSeed := best
	bestRandom := refineCoordinateDescent(train, val, randomSeed, &log, opts)

	baseSeed := buildBaselineSeed(train, val, base, opts, minCategories, &log)
	if baseSeed.Score(obj) > best.Score(obj) {
		best = baseSeed
	}
	bestBase := refineCoordinateDescent(train, val, baseSeed, &log, opts)

	if bestBase.Score(obj) > bestRandom.Score(obj) {
		best = bestBase
	} else {
		best = bestRandom
	}

	return best, log
}

// buildBaselineSeed evaluates the curated baseline weights at the configured
// (or midpoint) thresholds and appends the trial to the log so the baseline
// itself is visible in reports. The trial is returned for use as the second
// coordinate-descent seed.
func buildBaselineSeed(train, val []*PackageRun, base Weights, opts SearchOptions, minCategories int, log *[]Trial) Trial {
	allow := opts.BaseAllow
	if allow <= 0 {
		allow = (opts.AllowRange[0] + opts.AllowRange[1]) / 2
	}
	block := opts.BaseBlock
	if block <= 0 {
		block = (opts.BlockRange[0] + opts.BlockRange[1]) / 2
	}
	if block <= allow {
		block = allow + opts.StepSize
	}
	w := base.Clone()
	t := Trial{
		Index:         len(*log),
		Weights:       w,
		Allow:         allow,
		Block:         block,
		MinCategories: minCategories,
		TrainMet:      EvaluateWithMinCategories(train, w, allow, block, minCategories),
		ValMet:        EvaluateWithMinCategories(val, w, allow, block, minCategories),
	}
	*log = append(*log, t)
	return t
}

// refineCoordinateDescent runs opts.RefineSteps passes of coordinate descent
// starting from seed and returns the best trial it found.
func refineCoordinateDescent(train, val []*PackageRun, seed Trial, log *[]Trial, opts SearchOptions) Trial {
	obj := opts.Objective
	best := seed
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
					Index:         len(*log),
					Weights:       w,
					Allow:         best.Allow,
					Block:         best.Block,
					MinCategories: best.MinCategories,
					TrainMet:      EvaluateWithMinCategories(train, w, best.Allow, best.Block, best.MinCategories),
					ValMet:        EvaluateWithMinCategories(val, w, best.Allow, best.Block, best.MinCategories),
				}
				*log = append(*log, t)
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
					Index:         len(*log),
					Weights:       w,
					Allow:         allow,
					Block:         block,
					MinCategories: best.MinCategories,
					TrainMet:      EvaluateWithMinCategories(train, w, allow, block, best.MinCategories),
					ValMet:        EvaluateWithMinCategories(val, w, allow, block, best.MinCategories),
				}
				*log = append(*log, t)
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
	return best
}

// sampleWeights draws a fresh weight vector as a truncated normal around the
// baseline weight vector. For each key the sample is N(base[k], sigma)
// rejection-sampled into [lo, hi]. This anchors random exploration to curated
// priors instead of treating the hypercube as uniform; coordinate descent in
// Phase B is then free to walk anywhere within the global bounds.
func sampleWeights(rng *rand.Rand, base Weights, lo, hi, sigma float64) Weights {
	w := make(Weights, len(base))
	for k, b := range base {
		w[k] = truncatedNormal(rng, b, sigma, lo, hi)
	}
	return w
}

// truncatedNormal draws a sample from N(mean, sigma) clipped to [lo, hi] via
// rejection sampling. After 8 rejections it falls back to a uniform draw on
// [lo, hi] - this prevents pathological loops when mean is far outside the
// bounds (e.g. baseline weight already exceeds hi for a rule).
func truncatedNormal(rng *rand.Rand, mean, sigma, lo, hi float64) float64 {
	if hi <= lo {
		return lo
	}
	if sigma <= 0 {
		if mean < lo {
			return lo
		}
		if mean > hi {
			return hi
		}
		return mean
	}
	for i := 0; i < 8; i++ {
		v := mean + sigma*rng.NormFloat64()
		if v >= lo && v <= hi {
			return v
		}
	}
	return lo + rng.Float64()*(hi-lo)
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
