package analyzer

import (
	"context"
	"log"
	"time"

	"github.com/yourusername/npm-proxy/internal/analyzer/layer2"
	"github.com/yourusername/npm-proxy/internal/analyzer/layer3"
	"github.com/yourusername/npm-proxy/internal/config"
	"github.com/yourusername/npm-proxy/internal/extractor"
	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/signal"
	"golang.org/x/sync/errgroup"
)

// PostDownloadEngine orchestrates Layers 2 and 3 after tarball extraction.
type PostDownloadEngine struct {
	installScripts *layer2.InstallScriptAnalyzer
	capabilities   *layer3.CapabilityAnalyzer
	versionDiff    *layer3.VersionDiffAnalyzer
	sinks          *layer3.SinkAnalyzer
	entropy        *layer3.EntropyAnalyzer
	regClient      *registry.Client
	limits         extractor.Limits
	maxTarball     int64
	deepCheckTimeout time.Duration
}

func NewPostDownloadEngine(cfg *config.Config, regClient *registry.Client) *PostDownloadEngine {
	return &PostDownloadEngine{
		installScripts: layer2.NewInstallScriptAnalyzer(layer2.Scores{
			Present:        cfg.Layer2.InstallScriptPresentScore,
			Base64:         cfg.Layer2.InstallScriptBase64Score,
			ChildProcess:   cfg.Layer2.InstallScriptChildProcessScore,
			Eval:           cfg.Layer2.InstallScriptEvalScore,
			NodeEval:       cfg.Layer2.InstallScriptNodeEvalScore,
			DynamicRequire: cfg.Layer2.InstallScriptDynamicRequireScore,
			ExternalURL:    cfg.Layer2.InstallScriptExternalURLScore,
		}),
		capabilities: layer3.NewCapabilityAnalyzer(
			cfg.Layer3.CapabilityNetScore,
			cfg.Layer3.CapabilityExecScore,
			cfg.Layer3.CapabilityFSSensScore,
			cfg.Layer3.CapabilityDynEvalScore,
			cfg.Layer3.CapabilityEnvReadScore,
		),
		versionDiff: layer3.NewVersionDiffAnalyzer(layer3.VersionDiffOptions{
			ScriptAddedScore:   cfg.Layer3.VersionDiffScriptAddedScore,
			ScriptChangedScore: cfg.Layer3.VersionDiffScriptChangedScore,
			CapExecScore:       cfg.Layer3.VersionDiffCapExecScore,
			CapNetScore:        cfg.Layer3.VersionDiffCapNetScore,
			NewDepScore:        cfg.Layer3.VersionDiffNewDepScore,
			NewDepCap:          cfg.Layer3.VersionDiffNewDepCap,
		}),
		sinks: layer3.NewSinkAnalyzer(cfg.Layer3.SinkAloneScore, cfg.Layer3.SinkObfuscationScore),
		entropy: layer3.NewEntropyAnalyzer(layer3.EntropyOptions{
			Threshold:      cfg.Layer3.EntropyThreshold,
			RatioThreshold: cfg.Layer3.EntropyRatioThreshold,
			MinStringLen:   cfg.Layer3.EntropyMinStringLen,
			HexMinLen:      cfg.Layer3.EntropyHexMinLen,
		}),
		regClient: regClient,
		limits: extractor.Limits{
			MaxFiles:      cfg.Extractor.MaxFiles,
			MaxFileBytes:  cfg.Extractor.MaxFileBytes,
			MaxTotalBytes: cfg.Extractor.MaxTotalBytes,
		},
		maxTarball:       cfg.Proxy.MaxTarballBytes,
		deepCheckTimeout: 8 * time.Second,
	}
}

// Analyze runs all post-download layers and returns aggregated signals.
// meta is the full registry metadata document - used by the version diff without extra fetches.
func (e *PostDownloadEngine) Analyze(
	ctx context.Context,
	tree extractor.FileTree,
	meta *registry.PackageMeta,
	name, version, prevVersion string,
) (*signal.Result, error) {
	result := &signal.Result{}

	// Layer 2 - install scripts (veto-capable; run first).
	for _, s := range e.installScripts.Analyze(ctx, tree) {
		result.Add(s)
	}
	if result.HasVeto() {
		return result, nil
	}

	// Layer 3 - entropy and capabilities run concurrently.
	var (
		capSignals     []signal.Signal
		capList        []string
		entSignals     []signal.Signal
		hasObfuscation bool
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		capSignals, capList = e.capabilities.Analyze(gctx, tree)
		return nil
	})

	g.Go(func() error {
		entSignals, hasObfuscation = e.entropy.Analyze(gctx, tree)
		return nil
	})

	if err := g.Wait(); err != nil {
		return result, err
	}

	for _, s := range capSignals {
		result.Add(s)
	}
	for _, s := range entSignals {
		result.Add(s)
	}

	// Sinks - conditional veto if obfuscation was detected.
	for _, s := range e.sinks.Analyze(ctx, tree, hasObfuscation) {
		result.Add(s)
	}
	if result.HasVeto() {
		return result, nil
	}

	// Version diff - Option B: metadata script diff (zero extra network cost).
	scriptSigs, needsDeepCheck := e.versionDiff.ScriptDiff(meta, prevVersion, version)
	for _, s := range scriptSigs {
		result.Add(s)
	}

	// Dependency diff - also zero network cost when metadata is already present.
	for _, s := range e.versionDiff.DependencyDiff(meta, prevVersion, version) {
		result.Add(s)
	}

	// Option A: if a script change was detected in a patch bump, fetch the previous
	// tarball and compare capability sets for a deeper signal.
	if needsDeepCheck && e.regClient != nil && prevVersion != "" {
		deepCtx, cancel := context.WithTimeout(ctx, e.deepCheckTimeout)
		defer cancel()

		prevCaps := e.fetchPrevCapabilities(deepCtx, meta, name, prevVersion)
		if prevCaps != nil {
			for _, s := range e.versionDiff.CapabilityDiff(prevCaps, capList, prevVersion, version) {
				result.Add(s)
			}
		}
	}

	return result, nil
}

// fetchPrevCapabilities downloads and analyses the previous version's tarball.
// Returns nil on any error so that a slow or unavailable previous version never
// blocks the current request.
func (e *PostDownloadEngine) fetchPrevCapabilities(
	ctx context.Context,
	meta *registry.PackageMeta,
	name, prevVersion string,
) []string {
	prevMeta, ok := meta.Versions[prevVersion]
	if !ok || prevMeta.Dist.TarballURL == "" {
		return nil
	}

	data, err := e.regClient.FetchTarball(ctx, prevMeta.Dist.TarballURL, e.maxTarball)
	if err != nil {
		log.Printf("version_diff: fetch prev tarball %s@%s: %v", name, prevVersion, err)
		return nil
	}

	tree, err := extractor.Extract(data, e.limits)
	if err != nil {
		log.Printf("version_diff: extract prev tarball %s@%s: %v", name, prevVersion, err)
		return nil
	}

	_, caps := e.capabilities.Analyze(ctx, tree)
	return caps
}
