// Package integration exercises the post-download pipeline (Layer 2 + Layer 3 +
// policy engine) against the on-disk fixture packages under test/fixtures/.
// This is end-to-end at the analyzer level - it does not start the HTTP server
// or hit any external network. The goal is to fail fast if a future refactor
// changes a verdict for a fixture that captures a known attack pattern.
package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/npm-proxy/internal/analyzer/layer2"
	"github.com/yourusername/npm-proxy/internal/analyzer/layer3"
	"github.com/yourusername/npm-proxy/internal/extractor"
	"github.com/yourusername/npm-proxy/internal/policy"
	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/signal"
)

const (
	allowThreshold = 0.30
	blockThreshold = 0.70
)

func defaultLimits() extractor.Limits {
	return extractor.Limits{
		MaxFiles:      10000,
		MaxFileBytes:  5 * 1024 * 1024,
		MaxTotalBytes: 100 * 1024 * 1024,
	}
}

func newInstallScripts() *layer2.InstallScriptAnalyzer {
	return layer2.NewInstallScriptAnalyzer(layer2.Scores{
		Present:        0.20,
		Base64:         0.35,
		ChildProcess:   0.20,
		Eval:           0.15,
		NodeEval:       0.15,
		DynamicRequire: 0.10,
		ExternalURL:    0.08,
	})
}

func newCapabilities() *layer3.CapabilityAnalyzer {
	return layer3.NewCapabilityAnalyzer(0.15, 0.30, 0.25, 0.20, 0.10)
}

func newEntropy() *layer3.EntropyAnalyzer {
	return layer3.NewEntropyAnalyzer(layer3.EntropyOptions{
		Threshold:      4.5,
		RatioThreshold: 0.20,
		MinStringLen:   20,
		HexMinLen:      64,
	})
}

func newSinks() *layer3.SinkAnalyzer { return layer3.NewSinkAnalyzer(0.20, 0.55) }

func newVersionDiff() *layer3.VersionDiffAnalyzer {
	return layer3.NewVersionDiffAnalyzer(layer3.VersionDiffOptions{
		ScriptAddedScore:   0.40,
		ScriptChangedScore: 0.25,
		CapExecScore:       0.35,
		CapNetScore:        0.25,
		NewDepScore:        0.10,
		NewDepCap:          0.35,
	})
}

// buildTarballFromDir packs the given fixture directory into a gzip-compressed
// tarball that mirrors the npm publish format (entries prefixed with "package/").
// We build the archive in-memory so the tests do not depend on the host's tar
// utility being installed.
func buildTarballFromDir(t *testing.T, dir string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		// npm tarballs root every entry under "package/"; the fixture layout
		// already contains a "package/" subdirectory, so the relative path is
		// already in the correct form on disk - just normalise separators.
		entryName := filepath.ToSlash(rel)

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		hdr := &tar.Header{
			Name:    entryName,
			Mode:    0o644,
			Size:    int64(len(data)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.Copy(tw, bytes.NewReader(data)); err != nil {
			return err
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk fixture %s: %v", dir, walkErr)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// runPostDownload reproduces the post-download stages of the production engine
// (analyzer/engine.go) against an extracted FileTree. It deliberately does not
// import internal/analyzer to avoid pulling in the registry/cache plumbing -
// the goal is to assert that policy verdicts on fixtures stay stable.
func runPostDownload(t *testing.T, tree extractor.FileTree) *signal.Result {
	t.Helper()
	ctx := context.Background()
	result := &signal.Result{}

	// Layer 2 - install scripts.
	for _, s := range newInstallScripts().Analyze(ctx, tree) {
		result.Add(s)
	}
	if result.HasVeto() {
		return result
	}

	// Layer 3 - capabilities + entropy + sinks.
	capSigs, _ := newCapabilities().Analyze(ctx, tree)
	for _, s := range capSigs {
		result.Add(s)
	}
	entSigs, hasObf := newEntropy().Analyze(ctx, tree)
	for _, s := range entSigs {
		result.Add(s)
	}
	for _, s := range newSinks().Analyze(ctx, tree, hasObf) {
		result.Add(s)
	}
	return result
}

func decideForFixture(t *testing.T, fixtureDir string) policy.Decision {
	t.Helper()

	data := buildTarballFromDir(t, fixtureDir)
	tree, err := extractor.Extract(data, defaultLimits())
	if err != nil {
		t.Fatalf("extract %s: %v", fixtureDir, err)
	}

	result := runPostDownload(t, tree)
	// minCategories=0 → tests bypass the multi-category gate so a single
	// detector firing in a fixture (e.g. install-script-only) still yields
	// the expected warn/block. Production reads the gate from config.
	return policy.NewEngine(allowThreshold, blockThreshold, 0).Decide(result)
}

func TestPipeline_CleanPackageAllows(t *testing.T) {
	d := decideForFixture(t, "../fixtures/clean-package")
	if d.Verdict != policy.VerdictAllow {
		t.Fatalf("expected ALLOW for clean-package, got %s (score=%.2f rules=%v)", d.Verdict, d.Score, d.TriggeredRules)
	}
}

func TestPipeline_MaliciousInstallScriptVetoes(t *testing.T) {
	d := decideForFixture(t, "../fixtures/malicious-install-script")
	if d.Verdict != policy.VerdictBlock {
		t.Fatalf("expected BLOCK for curl|sh postinstall, got %s (score=%.2f rules=%v)", d.Verdict, d.Score, d.TriggeredRules)
	}
	// The veto rule should name the lifecycle hook so SIEM/operators can act.
	if !containsRulePrefix(d.TriggeredRules, "install_script_curl_pipe") {
		t.Errorf("expected veto rule install_script_curl_pipe_*, got %v", d.TriggeredRules)
	}
}

func TestPipeline_ObfuscatedEvalSurfacesAtLeastWarn(t *testing.T) {
	// The obfuscated-eval fixture combines a base64-decoded payload (high
	// entropy + base64 detection) with eval(). Sink+obfuscation used to be
	// a hard veto, but minified popular bundles legitimately match the same
	// pattern, so it is now a heavy scored signal. We assert the policy
	// engine still surfaces it (warn or block), not a specific verdict.
	d := decideForFixture(t, "../fixtures/obfuscated-eval")
	if d.Verdict == policy.VerdictAllow {
		t.Fatalf("expected WARN or BLOCK for obfuscated-eval, got ALLOW (score=%.2f rules=%v)", d.Score, d.TriggeredRules)
	}
	if !containsRulePrefix(d.TriggeredRules, "sink_with_obfuscation") {
		t.Errorf("expected sink_with_obfuscation among triggered rules, got %v", d.TriggeredRules)
	}
}

// TestPipeline_NewExecInPatchTriggersVersionDiff exercises the version_diff
// path: v1 has no exec capability, v1.0.1 introduces child_process. With the
// versionDiff signal in patch context we expect at least WARN (score >= 0.30).
func TestPipeline_NewExecInPatchTriggersVersionDiff(t *testing.T) {
	ctx := context.Background()

	currTree, err := extractor.Extract(
		buildTarballFromDir(t, "../fixtures/new-exec-in-patch/v1.0.1"),
		defaultLimits(),
	)
	if err != nil {
		t.Fatalf("extract v1.0.1: %v", err)
	}

	// Construct synthetic registry metadata so version_diff has both versions.
	meta := &registry.PackageMeta{
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {Scripts: map[string]string{}},
			"1.0.1": {Scripts: map[string]string{}},
		},
	}

	result := &signal.Result{}
	for _, s := range newInstallScripts().Analyze(ctx, currTree) {
		result.Add(s)
	}
	capSigs, currCaps := newCapabilities().Analyze(ctx, currTree)
	for _, s := range capSigs {
		result.Add(s)
	}

	// The previous version had no exec capability.
	prevCaps := []string{}
	for _, s := range newVersionDiff().CapabilityDiff(prevCaps, currCaps, "1.0.0", "1.0.1") {
		result.Add(s)
	}
	// Dependency / script diff don't apply here (scripts unchanged).
	for _, s := range newVersionDiff().DependencyDiff(meta, "1.0.0", "1.0.1") {
		result.Add(s)
	}

	d := policy.NewEngine(allowThreshold, blockThreshold, 0).Decide(result)
	// The fixture has child_process exec → capability_exec (0.30) plus
	// version_diff_new_exec_in_patch (0.35) → score ≥ 0.65, comfortably above
	// the WARN threshold and at or above BLOCK depending on tuning.
	if d.Verdict == policy.VerdictAllow {
		t.Fatalf("expected non-allow verdict for new exec capability in patch, got allow (score=%.2f rules=%v)", d.Score, d.TriggeredRules)
	}
	if !containsRulePrefix(d.TriggeredRules, "version_diff_new_exec_in_patch") {
		t.Errorf("expected version_diff_new_exec_in_patch in triggered rules, got %v", d.TriggeredRules)
	}
}

func containsRulePrefix(rules []string, prefix string) bool {
	for _, r := range rules {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}
