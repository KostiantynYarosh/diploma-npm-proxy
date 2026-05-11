package calibrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/yourusername/npm-proxy/internal/analyzer"
	"github.com/yourusername/npm-proxy/internal/analyzer/layer1"
	"github.com/yourusername/npm-proxy/internal/config"
	"github.com/yourusername/npm-proxy/internal/extractor"
	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// CorpusEntry is one labelled tarball plus its associated metadata snapshot.
// Snapshots are mandatory: calibration must be reproducible offline, so each
// entry carries the registry document and OSV verdict that were authoritative
// at corpus-build time. Re-querying npmjs/OSV during calibration would make
// runs non-deterministic and rate-limited.
type CorpusEntry struct {
	Name        string
	Version     string
	PrevVersion string
	TarballPath string
	MetaPath    string // path to PackageMeta JSON snapshot; empty if not available
	OSVVuln     bool   // pre-computed OSV verdict for the snapshot date
	Label       Label
	Category    string // optional sub-classification: "cve_patch", "active_malware", etc.
}

// Runner drives the full analysis pipeline against a corpus, caching the
// resulting signals so the search loop can re-weight them without touching
// the tarballs again.
type Runner struct {
	engine    *analyzer.PostDownloadEngine
	typosquat *layer1.TyposquatChecker
	metadata  *layer1.MetadataChecker
	anomaly   *layer1.AnomalyChecker
	license   *layer1.LicenseChecker
	limits    extractor.Limits
	combo     analyzer.ComboScores

	// StripOSV suppresses the synthetic OSV veto signal so calibration tunes
	// the scored detectors against malicious packages on their own merit. With
	// OSV present every CVE-tagged seed becomes an instant block (recall=1.0
	// for free, but the other rules see no learning gradient on the malicious
	// class). Use this flag when you specifically want to evaluate or
	// calibrate the non-OSV stack.
	StripOSV bool
}

// NewRunner builds the offline pipeline. The OSV checker is intentionally
// omitted - OSV results are baked into the corpus (CorpusEntry.OSVVuln) so
// calibration neither makes API calls nor depends on network availability.
// Layer 1 metadata-querying signals (low_downloads, young_maintainer) require
// network too: they are disabled by passing a nil registry client. Score
// weights for those rules will calibrate to 0 if their signals never fire.
func NewRunner(cfg *config.Config) (*Runner, error) {
	typo, err := layer1.NewTyposquatChecker(
		cfg.Layer1.Top10kPath,
		layer1.TyposquatOptions{
			CloseDistance:       cfg.Layer1.TyposquatCloseDistance,
			CloseScore:          cfg.Layer1.TyposquatCloseScore,
			WarnDistance:        cfg.Layer1.TyposquatWarnDistance,
			WarnScore:           cfg.Layer1.TyposquatWarnScore,
			ASCIIHomoglyphScore: cfg.Layer1.TyposquatASCIIHomoglyphScore,
			CombosquatScore:     cfg.Layer1.TyposquatCombosquatScore,
			ScopeCloseScore:     cfg.Layer1.TyposquatScopeCloseScore,
			ScopeWarnScore:      cfg.Layer1.TyposquatScopeWarnScore,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("init typosquat: %w", err)
	}

	meta := layer1.NewMetadataChecker(nil, layer1.MetadataCheckerOptions{
		NewPackageDays:        cfg.Layer1.MetadataNewPackageDays,
		NewPackageScore:       cfg.Layer1.MetadataNewPackageScore,
		YoungMaintainerDays:   cfg.Layer1.MetadataYoungMaintainerDays,
		YoungMaintainerScore:  cfg.Layer1.MetadataYoungMaintainerScore,
		LowDownloadsThreshold: cfg.Layer1.MetadataLowDownloadsThreshold,
		LowDownloadsScore:     cfg.Layer1.MetadataLowDownloadsScore,
		PopularThreshold:      cfg.Layer1.MetadataPopularThreshold,
		PopularButStaleDays:   cfg.Layer1.MetadataPopularStaleDays,
		PopularButStaleScore:  cfg.Layer1.MetadataPopularStaleScore,
	})

	anomaly := layer1.NewAnomalyChecker(layer1.AnomalyCheckerOptions{
		MaxVersionsPerDay:     cfg.Layer1.AnomalyMaxVersionsPerDay,
		VersionSpikeScore:     cfg.Layer1.AnomalyVersionSpikeScore,
		MaintainerChangeScore: cfg.Layer1.AnomalyMaintainerChangeScore,
		UnusualHoursScore:     cfg.Layer1.AnomalyUnusualHoursScore,
		SizeDeviationScore:    cfg.Layer1.AnomalySizeDeviationScore,
	})

	lic := layer1.NewLicenseChecker(
		cfg.Layer1.LicensePatchChangeScore,
		cfg.Layer1.LicenseMissingPopScore,
		cfg.Layer1.LicensePopularDownloads,
	)

	return &Runner{
		engine:    analyzer.NewPostDownloadEngine(cfg, nil),
		typosquat: typo,
		metadata:  meta,
		anomaly:   anomaly,
		license:   lic,
		combo:     analyzer.ComboScoresFromConfig(cfg),
		// Calibration uses far more permissive extraction limits than
		// production. The proxy's tight ceilings (5 MB/file, 100 MB/tarball)
		// are a defence against zip-bombs at runtime - oversized packages
		// just 403 there. During calibration we *want* to analyse those
		// packages; many real malicious samples (e.g. native-lib carriers,
		// crypto miners) embed multi-MB blobs that would otherwise be
		// silently dropped from the corpus and bias the metrics.
		limits: extractor.Limits{
			MaxFiles:      100000,
			MaxFileBytes:  100 * 1024 * 1024,      // 100 MB
			MaxTotalBytes: 2 * 1024 * 1024 * 1024, // 2 GB
		},
	}, nil
}

// Run executes the full pipeline against one entry, returning a PackageRun
// suitable for caching. Errors that prevent classification (e.g. corrupt
// tarball) are returned so the caller can drop the entry from the corpus
// rather than feeding bad data into search.
func (r *Runner) Run(ctx context.Context, e CorpusEntry) (*PackageRun, error) {
	tarballData, err := os.ReadFile(e.TarballPath)
	if err != nil {
		return nil, fmt.Errorf("read tarball: %w", err)
	}

	hash := sha256.Sum256(tarballData)
	sha := hex.EncodeToString(hash[:])

	meta, err := loadMeta(e.MetaPath)
	if err != nil {
		return nil, fmt.Errorf("load meta: %w", err)
	}

	tree, err := extractor.Extract(tarballData, r.limits)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	result := &signal.Result{}

	// OSV: baked into the corpus, surfaced as a synthetic veto signal so the
	// calibrator sees the same shape the production handler does. StripOSV
	// disables this so the search has to learn from scored detectors alone.
	if e.OSVVuln && !r.StripOSV {
		result.Add(signal.Signal{
			Rule: "osv_known_vulnerability",
			Veto: true,
			CWE:  "CWE-1035",
		})
	}

	// Layer 1 signals that work offline. Network-dependent rules (downloads /
	// maintainer-age / OSV) are disabled - their weights stay at zero unless
	// the corpus is later enriched with those snapshots.
	for _, s := range r.typosquat.Check(ctx, e.Name) {
		result.Add(s)
	}
	if meta != nil {
		for _, s := range r.metadata.Check(ctx, meta, e.Version) {
			result.Add(s)
		}
		for _, s := range r.anomaly.Check(ctx, meta, e.Version) {
			result.Add(s)
		}
		for _, s := range r.license.Check(ctx, meta, e.Version) {
			result.Add(s)
		}
	}

	// Layer 2 + 3 (post-download).
	post, err := r.engine.Analyze(ctx, tree, meta, e.Name, e.Version, e.PrevVersion)
	if err != nil {
		return nil, fmt.Errorf("post-download: %w", err)
	}
	for _, s := range post.Signals {
		result.Add(s)
	}
	analyzer.AddComboSignals(result, r.combo)

	cached := make([]CachedSignal, 0, len(result.Signals))
	for _, s := range result.Signals {
		cached = append(cached, CachedSignal{
			Rule:           s.Rule,
			Score:          s.Score,
			Veto:           s.Veto,
			CWE:            s.CWE,
			Detail:         s.Detail,
			MatchedPackage: s.MatchedPackage,
		})
	}

	return &PackageRun{
		Name:     e.Name,
		Version:  e.Version,
		SHA256:   sha,
		Label:    e.Label,
		Category: e.Category,
		Signals:  cached,
	}, nil
}

func loadMeta(path string) (*registry.PackageMeta, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var meta registry.PackageMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal meta: %w", err)
	}
	return &meta, nil
}
