// Package recheck implements the post-factum re-analysis worker. It scans the
// verdict cache at a configurable interval and re-runs cheap Layer 1 signals
// (OSV, typosquat) against entries that were previously admitted with a
// warning. When the new verdict would be "block" - typically because OSV has
// since published a vulnerability for the cached name@version - the cache
// entry is upgraded and a retroactive-block SIEM event is emitted so that
// downstream consumers can revoke the grant.
package recheck

import (
	"context"
	"log"
	"time"

	"github.com/yourusername/npm-proxy/internal/analyzer/layer1"
	"github.com/yourusername/npm-proxy/internal/cache"
	"github.com/yourusername/npm-proxy/internal/policy"
	"github.com/yourusername/npm-proxy/internal/siem"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// Config controls the recheck loop behaviour.
type Config struct {
	Interval  time.Duration
	BatchSize int
	WarnOnly  bool // recheck only "warn" verdicts; false also rechecks "allow"
}

// Worker iterates cached verdicts periodically and retroactively upgrades them
// to "block" when new intelligence (e.g. a freshly-published OSV advisory)
// would change the decision.
type Worker struct {
	cfg        Config
	cache      *cache.Client
	osv        *layer1.OSVChecker
	typosquat  *layer1.TyposquatChecker
	policyEng  *policy.Engine
	emitter    siem.Emitter
}

func New(
	cfg Config,
	cacheClient *cache.Client,
	osv *layer1.OSVChecker,
	typo *layer1.TyposquatChecker,
	pe *policy.Engine,
	emitter siem.Emitter,
) *Worker {
	return &Worker{
		cfg:       cfg,
		cache:     cacheClient,
		osv:       osv,
		typosquat: typo,
		policyEng: pe,
		emitter:   emitter,
	}
}

// Run blocks on the background loop until the context is cancelled.
func (w *Worker) Run(ctx context.Context) {
	if w.cfg.Interval <= 0 {
		log.Printf("recheck: disabled (interval=%v)", w.cfg.Interval)
		return
	}
	log.Printf("recheck: started interval=%v batch=%d warn_only=%v", w.cfg.Interval, w.cfg.BatchSize, w.cfg.WarnOnly)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	// Run once shortly after startup so operators don't have to wait a full interval.
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			w.runOnce(ctx)
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

func (w *Worker) runOnce(ctx context.Context) {
	match := []string{"warn"}
	if !w.cfg.WarnOnly {
		match = append(match, "allow")
	}
	entries, err := w.cache.ListVerdicts(ctx, match, w.cfg.BatchSize)
	if err != nil {
		log.Printf("recheck: list verdicts: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}

	upgraded := 0
	for _, ce := range entries {
		if ctx.Err() != nil {
			return
		}
		if w.recheckOne(ctx, ce) {
			upgraded++
		}
	}
	log.Printf("recheck: scanned=%d upgraded_to_block=%d", len(entries), upgraded)
}

// recheckOne returns true if the verdict was upgraded to block.
func (w *Worker) recheckOne(ctx context.Context, ce cache.CachedVerdict) bool {
	// Force the next OSV query to hit the network rather than returning a
	// stale "clean" cache result.
	_ = w.cache.InvalidateOSV(ctx, ce.Entry.Name, ce.Entry.Version)

	result := &signal.Result{}
	// Re-run OSV - the main source of new intelligence for a known name@version.
	if sigs, err := w.osv.Check(ctx, ce.Entry.Name, ce.Entry.Version); err == nil {
		for _, s := range sigs {
			result.Add(s)
		}
	}
	// Re-run typosquat so that a refreshed top-N list is also applied.
	if w.typosquat != nil {
		for _, s := range w.typosquat.Check(ctx, ce.Entry.Name) {
			result.Add(s)
		}
	}

	decision := w.policyEng.Decide(result)
	if decision.Verdict != policy.VerdictBlock {
		return false
	}
	// The cached score was originally < block threshold by definition; only
	// persist the upgrade if the *new* decision actually blocks.
	newEntry := ce.Entry
	newEntry.Verdict = "block"
	newEntry.Score = decision.Score
	newEntry.Rules = mergeUnique(ce.Entry.Rules, decision.TriggeredRules)
	newEntry.AnalyzedAt = time.Now().Unix()
	if err := w.cache.SetVerdict(ctx, ce.SHA256, newEntry); err != nil {
		log.Printf("recheck: update verdict %s: %v", ce.SHA256, err)
		return false
	}

	_ = w.emitter.Emit(ctx, siem.Event{
		EventType:      siem.EventPackageVerdict,
		Timestamp:      time.Now().UTC(),
		PackageName:    ce.Entry.Name,
		PackageVersion: ce.Entry.Version,
		SHA256:         ce.SHA256,
		Verdict:        siem.VerdictBlock,
		RiskScore:      decision.Score,
		TriggeredRules: newEntry.Rules,
		CWEIDs:         decision.CWEIDs,
		ResponseCode:   403,
	})
	log.Printf("recheck: upgraded %s@%s to BLOCK (rules=%v)", ce.Entry.Name, ce.Entry.Version, decision.TriggeredRules)
	return true
}

func mergeUnique(existing, extra []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(extra))
	for _, r := range existing {
		seen[r] = struct{}{}
	}
	out := append([]string{}, existing...)
	for _, r := range extra {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}
