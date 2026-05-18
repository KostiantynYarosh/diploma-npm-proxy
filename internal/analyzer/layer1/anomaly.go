package layer1

import (
	"context"
	"time"

	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// AnomalyChecker emits release-frequency anomalies on the publish-history
// metadata. The maintainer-change, unusual-publish-hour, and size-deviation
// detectors were removed after calibration showed they consistently received
// zero weight on the DataDog corpus: their signal-to-FP ratio could not be
// pushed above the strict hard-FP cap and the search routinely zeroed them
// out across multiple operating-point profiles.
type AnomalyChecker struct {
	maxVersionsPerDay int
	versionSpikeScore float64
}

// AnomalyCheckerOptions groups the knobs to avoid an ever-growing positional constructor.
type AnomalyCheckerOptions struct {
	MaxVersionsPerDay int
	VersionSpikeScore float64
}

func NewAnomalyChecker(opts AnomalyCheckerOptions) *AnomalyChecker {
	return &AnomalyChecker{
		maxVersionsPerDay: opts.MaxVersionsPerDay,
		versionSpikeScore: opts.VersionSpikeScore,
	}
}

func (a *AnomalyChecker) Check(_ context.Context, meta *registry.PackageMeta, _ string) []signal.Signal {
	var signals []signal.Signal
	now := time.Now().UTC()

	// Release frequency spike: count versions published in the last 24 h.
	recentCount := 0
	for ver, timeStr := range meta.Time {
		if ver == "created" || ver == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			continue
		}
		if now.Sub(t) < 24*time.Hour {
			recentCount++
		}
	}
	if recentCount > a.maxVersionsPerDay {
		signals = append(signals, signal.Signal{
			Rule:   "anomaly_version_spike",
			Score:  a.versionSpikeScore,
			Detail: "versions_in_last_24h=" + itoa64(int64(recentCount)),
		})
	}

	return signals
}
