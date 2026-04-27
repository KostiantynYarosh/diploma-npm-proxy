package layer1

import (
	"context"
	"sort"
	"time"

	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/semverutil"
	"github.com/yourusername/npm-proxy/internal/signal"
)

type AnomalyChecker struct {
	maxVersionsPerDay     int
	versionSpikeScore     float64
	maintainerChangeScore float64
	unusualHoursScore     float64
	sizeDeviationScore    float64
}

// AnomalyCheckerOptions groups the knobs to avoid an ever-growing positional constructor.
type AnomalyCheckerOptions struct {
	MaxVersionsPerDay     int
	VersionSpikeScore     float64
	MaintainerChangeScore float64
	UnusualHoursScore     float64
	SizeDeviationScore    float64
}

func NewAnomalyChecker(opts AnomalyCheckerOptions) *AnomalyChecker {
	return &AnomalyChecker{
		maxVersionsPerDay:     opts.MaxVersionsPerDay,
		versionSpikeScore:     opts.VersionSpikeScore,
		maintainerChangeScore: opts.MaintainerChangeScore,
		unusualHoursScore:     opts.UnusualHoursScore,
		sizeDeviationScore:    opts.SizeDeviationScore,
	}
}

func (a *AnomalyChecker) Check(_ context.Context, meta *registry.PackageMeta, currentVersion string) []signal.Signal {
	var signals []signal.Signal
	now := time.Now().UTC()

	// 1) Release frequency spike: count versions published in the last 24 h.
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

	// 2) Unusual publish hour for the current version - detect outliers against
	// the package's own historical publish-hour distribution. Requires at
	// least 5 prior publish timestamps to compute a meaningful distribution.
	if currentVersion != "" {
		if s := a.unusualHoursSignal(meta, currentVersion, now); s != nil {
			signals = append(signals, *s)
		}
	}

	// 3) Maintainer-set change between the previous and the current version -
	// only detectable if per-version metadata happens to include maintainers.
	// The npm registry does expose this historically for many packages.
	if currentVersion != "" {
		prev := semverutil.PreviousVersion(allVersions(meta), currentVersion)
		if prev != "" {
			if s := a.maintainerChangeSignal(meta, prev, currentVersion); s != nil {
				signals = append(signals, *s)
			}
		}
	}

	// 4) Package-size deviation: current tarball is outside 3× median of the
	// last 10 released versions. Useful signal for payload smuggling.
	if currentVersion != "" {
		if s := a.sizeDeviationSignal(meta, currentVersion); s != nil {
			signals = append(signals, *s)
		}
	}

	return signals
}

// unusualHoursSignal fires when the current version's publish hour lies in the
// bottom-quartile of the package's historical publish hours - e.g. a package
// habitually released 10:00–18:00 UTC that now gets a release at 03:00 UTC.
func (a *AnomalyChecker) unusualHoursSignal(meta *registry.PackageMeta, currentVersion string, _ time.Time) *signal.Signal {
	currTS, ok := meta.Time[currentVersion]
	if !ok {
		return nil
	}
	currT, err := time.Parse(time.RFC3339, currTS)
	if err != nil {
		return nil
	}

	// Collect the other versions' publish hours (UTC).
	var hours []int
	for ver, ts := range meta.Time {
		if ver == "created" || ver == "modified" || ver == currentVersion {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		hours = append(hours, t.UTC().Hour())
	}
	if len(hours) < 5 {
		return nil
	}

	// Build per-hour frequency table.
	freq := make([]int, 24)
	for _, h := range hours {
		freq[h]++
	}
	total := len(hours)
	currentHour := currT.UTC().Hour()
	// Consider a hour "unusual" if it has seen < 5 % of historical publishes
	// AND the package has at least 20 historical publishes (so the baseline is
	// statistically meaningful).
	if total < 20 {
		return nil
	}
	if float64(freq[currentHour])/float64(total) >= 0.05 {
		return nil
	}

	return &signal.Signal{
		Rule:   "anomaly_unusual_publish_hour",
		Score:  a.unusualHoursScore,
		Detail: "publish_hour=" + itoa64(int64(currentHour)) + "z freq_pct=" + itoa64(int64(100*freq[currentHour]/total)),
	}
}

// maintainerChangeSignal compares the maintainer set between adjacent versions
// when per-version metadata is available.
func (a *AnomalyChecker) maintainerChangeSignal(meta *registry.PackageMeta, prev, curr string) *signal.Signal {
	prevMeta := meta.Versions[prev]
	currMeta := meta.Versions[curr]
	if len(prevMeta.Maintainers) == 0 || len(currMeta.Maintainers) == 0 {
		return nil
	}
	prevSet := make(map[string]struct{}, len(prevMeta.Maintainers))
	for _, m := range prevMeta.Maintainers {
		prevSet[m.Name] = struct{}{}
	}
	for _, m := range currMeta.Maintainers {
		if _, ok := prevSet[m.Name]; !ok {
			return &signal.Signal{
				Rule:   "anomaly_maintainer_change",
				Score:  a.maintainerChangeScore,
				Detail: "new_maintainer=" + m.Name + " in=" + curr,
			}
		}
	}
	return nil
}

// sizeDeviationSignal fires when the current version's unpacked tarball size
// deviates strongly from the median of its peers.
func (a *AnomalyChecker) sizeDeviationSignal(meta *registry.PackageMeta, currentVersion string) *signal.Signal {
	currSize := meta.Versions[currentVersion].Dist.UnpackedSize
	if currSize == 0 {
		return nil
	}
	var sizes []int64
	for ver, v := range meta.Versions {
		if ver == currentVersion || v.Dist.UnpackedSize == 0 {
			continue
		}
		sizes = append(sizes, v.Dist.UnpackedSize)
	}
	if len(sizes) < 5 {
		return nil
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	median := sizes[len(sizes)/2]
	if median == 0 {
		return nil
	}
	ratio := float64(currSize) / float64(median)
	if ratio < 3.0 && ratio > 1.0/3.0 {
		return nil
	}
	return &signal.Signal{
		Rule:   "anomaly_size_deviation",
		Score:  a.sizeDeviationScore,
		Detail: "ratio=" + formatRatio(ratio) + " current=" + itoa64(currSize) + " median=" + itoa64(median),
	}
}

func formatRatio(r float64) string {
	// Quick fixed-point formatter: two decimals without importing fmt/strconv here.
	whole := int64(r)
	frac := int64((r - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	s := itoa64(whole) + "."
	if frac < 10 {
		s += "0"
	}
	s += itoa64(frac)
	return s
}

