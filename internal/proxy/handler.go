package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/yourusername/npm-proxy/internal/analyzer"
	"github.com/yourusername/npm-proxy/internal/analyzer/layer1"
	"github.com/yourusername/npm-proxy/internal/cache"
	"github.com/yourusername/npm-proxy/internal/config"
	"github.com/yourusername/npm-proxy/internal/extractor"
	"github.com/yourusername/npm-proxy/internal/integrity"
	"github.com/yourusername/npm-proxy/internal/policy"
	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/semverutil"
	"github.com/yourusername/npm-proxy/internal/siem"
	"github.com/yourusername/npm-proxy/internal/signal"
	"golang.org/x/sync/errgroup"
)

// reTarball matches /<scope>/<package>/-/<tarball>.tgz or /<package>/-/<tarball>.tgz
var reTarball = regexp.MustCompile(`^/(@[^/]+/[^/]+|[^/]+)/-/([^/]+\.tgz)$`)

type Handler struct {
	cfg            *config.Config
	registryClient *registry.Client
	cacheClient    *cache.Client
	siemEmitter    siem.Emitter
	engine         *analyzer.PostDownloadEngine
	policyEngine   *policy.Engine
	osvChecker     *layer1.OSVChecker
	typosquat      *layer1.TyposquatChecker
	metadata       *layer1.MetadataChecker
	anomaly        *layer1.AnomalyChecker
	license        *layer1.LicenseChecker
	reverseProxy   *httputil.ReverseProxy
}

func NewHandler(
	cfg *config.Config,
	regClient *registry.Client,
	cacheClient *cache.Client,
	siemEmitter siem.Emitter,
	engine *analyzer.PostDownloadEngine,
	policyEngine *policy.Engine,
	osv *layer1.OSVChecker,
	typo *layer1.TyposquatChecker,
	meta *layer1.MetadataChecker,
	anomaly *layer1.AnomalyChecker,
	lic *layer1.LicenseChecker,
) *Handler {
	upstream, _ := url.Parse(cfg.Proxy.UpstreamURL)
	rp := httputil.NewSingleHostReverseProxy(upstream)
	defaultDirector := rp.Director
	rp.Director = func(req *http.Request) {
		defaultDirector(req)
		req.Host = upstream.Host
	}

	return &Handler{
		cfg:            cfg,
		registryClient: regClient,
		cacheClient:    cacheClient,
		siemEmitter:    siemEmitter,
		engine:         engine,
		policyEngine:   policyEngine,
		osvChecker:     osv,
		typosquat:      typo,
		metadata:       meta,
		anomaly:        anomaly,
		license:        lic,
		reverseProxy:   rp,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	m := reTarball.FindStringSubmatch(r.URL.Path)
	if m == nil {
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	name := m[1]
	sourceIP := r.RemoteAddr

	if err := h.handleTarball(w, r, name, sourceIP); err != nil {
		log.Printf("proxy: error handling %s: %v", r.URL.Path, err)
	}
}

func (h *Handler) handleTarball(w http.ResponseWriter, r *http.Request, name, sourceIP string) error {
	ctx := r.Context()
	start := time.Now()

	// Fetch registry metadata (needed by Layer 1 and integrity check).
	meta, err := h.registryClient.FetchPackageMeta(ctx, name)
	if err != nil {
		h.emitEvent(ctx, siem.Event{
			EventType:    siem.EventUpstreamDown,
			PackageName:  name,
			SourceIP:     sourceIP,
			ResponseCode: 502,
		})
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return nil
	}

	version, requested := resolveVersion(meta, name, r.URL.Path)
	if requested != "" && version != requested {
		// User asked for a specific version that the registry no longer
		// exposes (e.g. unpublished after a malware incident). Refuse rather
		// than silently substituting a different tarball.
		http.Error(w, fmt.Sprintf("version %s not available", requested), http.StatusNotFound)
		return nil
	}

	// Layer 1 pre-download checks (concurrent).
	l1Result := &signal.Result{}
	{
		g, gctx := errgroup.WithContext(ctx)

		g.Go(func() error {
			sigs, err := h.osvChecker.Check(gctx, name, version)
			for _, s := range sigs {
				l1Result.Add(s)
			}
			return err
		})
		g.Go(func() error {
			for _, s := range h.typosquat.Check(gctx, name) {
				l1Result.Add(s)
			}
			return nil
		})
		g.Go(func() error {
			for _, s := range h.metadata.Check(gctx, meta, version) {
				l1Result.Add(s)
			}
			return nil
		})
		g.Go(func() error {
			for _, s := range h.anomaly.Check(gctx, meta, version) {
				l1Result.Add(s)
			}
			return nil
		})
		g.Go(func() error {
			for _, s := range h.license.Check(gctx, meta, version) {
				l1Result.Add(s)
			}
			return nil
		})

		_ = g.Wait() // OSV errors are non-fatal
	}

	l1Decision := h.policyEngine.Decide(l1Result)
	if l1Decision.Verdict == policy.VerdictBlock {
		h.respondBlock(ctx, w, name, version, "", sourceIP, l1Decision, time.Since(start))
		return nil
	}

	// Fetch tarball.
	versionMeta := meta.Versions[version]
	tarballURL := versionMeta.Dist.TarballURL
	if tarballURL == "" {
		tarballURL = fmt.Sprintf("%s/%s/-/%s", h.cfg.Proxy.UpstreamURL, name, tarballFilename(r.URL.Path))
	}

	tarballData, err := h.registryClient.FetchTarball(ctx, tarballURL, h.cfg.Proxy.MaxTarballBytes)
	if err != nil {
		h.emitEvent(ctx, siem.Event{
			EventType:      siem.EventUpstreamDown,
			PackageName:    name,
			PackageVersion: version,
			SourceIP:       sourceIP,
			ResponseCode:   502,
		})
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return nil
	}

	// Integrity check.
	if err := integrity.Verify(tarballData, versionMeta.Dist.Shasum, versionMeta.Dist.Integrity); err != nil {
		h.emitEvent(ctx, siem.Event{
			EventType:      siem.EventIntegrityMismatch,
			PackageName:    name,
			PackageVersion: version,
			SourceIP:       sourceIP,
			ResponseCode:   403,
		})
		http.Error(w, "integrity check failed", http.StatusForbidden)
		return nil
	}

	// Redis cache lookup.
	rawHash := sha256.Sum256(tarballData)
	sha256hex := hex.EncodeToString(rawHash[:])

	cached, cacheErr := h.cacheClient.GetVerdict(ctx, sha256hex)
	if cacheErr != nil {
		// A transient Redis error is non-fatal - we fall back to a fresh
		// analysis. Log so that operators can spot a flapping cache instead
		// of silently paying the full pipeline cost on every request.
		log.Printf("proxy: cache lookup failed for %s: %v - falling through to fresh analysis", sha256hex, cacheErr)
	} else if cached != nil {
		h.respondFromCache(w, ctx, name, version, sha256hex, sourceIP, cached, tarballData, time.Since(start))
		return nil
	}

	// In-memory extraction.
	limits := extractor.Limits{
		MaxFiles:      h.cfg.Extractor.MaxFiles,
		MaxFileBytes:  h.cfg.Extractor.MaxFileBytes,
		MaxTotalBytes: h.cfg.Extractor.MaxTotalBytes,
	}
	tree, err := extractor.Extract(tarballData, limits)
	if err != nil {
		h.emitEvent(ctx, siem.Event{
			EventType:      siem.EventResourceLimit,
			PackageName:    name,
			PackageVersion: version,
			SHA256:         sha256hex,
			SourceIP:       sourceIP,
			ResponseCode:   403,
		})
		http.Error(w, "tarball rejected: "+err.Error(), http.StatusForbidden)
		return nil
	}

	// Post-download analysis with timeout.
	analysisCtx, cancel := context.WithTimeout(ctx, h.cfg.Proxy.AnalysisTimeout)
	defer cancel()

	prevVersion := previousVersionFromMeta(meta, version)
	postResult, err := h.engine.Analyze(analysisCtx, tree, meta, name, version, prevVersion)
	if err != nil || analysisCtx.Err() != nil {
		h.emitEvent(ctx, siem.Event{
			EventType:      siem.EventAnalysisTimeout,
			PackageName:    name,
			PackageVersion: version,
			SHA256:         sha256hex,
			SourceIP:       sourceIP,
			ResponseCode:   403,
		})
		http.Error(w, "analysis timeout", http.StatusForbidden)
		return nil
	}

	// Merge Layer 1 + post-download signals.
	finalResult := &signal.Result{}
	for _, s := range l1Result.Signals {
		finalResult.Add(s)
	}
	for _, s := range postResult.Signals {
		finalResult.Add(s)
	}

	decision := h.policyEngine.Decide(finalResult)
	durationMs := time.Since(start).Milliseconds()

	_ = h.cacheClient.SetVerdict(ctx, sha256hex, cache.VerdictEntry{
		Score:      decision.Score,
		Verdict:    decision.Verdict.String(),
		AnalyzedAt: time.Now().Unix(),
		Version:    version,
		Name:       name,
		Rules:      decision.TriggeredRules,
	})

	h.emitEvent(ctx, siem.Event{
		EventType:          siem.EventPackageVerdict,
		PackageName:        name,
		PackageVersion:     version,
		SHA256:             sha256hex,
		Verdict:            decision.Verdict.SIEMVerdict(),
		RiskScore:          decision.Score,
		TriggeredRules:     decision.TriggeredRules,
		CWEIDs:             decision.CWEIDs,
		ResponseCode:       decision.HTTPStatus,
		AnalysisDurationMs: durationMs,
		SourceIP:           sourceIP,
	})

	if decision.Verdict == policy.VerdictBlock {
		http.Error(w, "package blocked by security policy", http.StatusForbidden)
		return nil
	}
	if decision.Verdict == policy.VerdictWarn {
		w.Header().Set("X-Security-Warning", decision.WarningHeader)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarballData)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(tarballData); err != nil {
		log.Printf("proxy: write response: %v", err)
	}
	return nil
}

func (h *Handler) respondBlock(
	ctx context.Context,
	w http.ResponseWriter,
	name, version, sha256hex, sourceIP string,
	d policy.Decision,
	dur time.Duration,
) {
	h.emitEvent(ctx, siem.Event{
		EventType:          siem.EventPackageVerdict,
		PackageName:        name,
		PackageVersion:     version,
		SHA256:             sha256hex,
		Verdict:            siem.VerdictBlock,
		RiskScore:          d.Score,
		TriggeredRules:     d.TriggeredRules,
		CWEIDs:             d.CWEIDs,
		ResponseCode:       403,
		AnalysisDurationMs: dur.Milliseconds(),
		SourceIP:           sourceIP,
	})
	http.Error(w, "package blocked by security policy", http.StatusForbidden)
}

func (h *Handler) respondFromCache(
	w http.ResponseWriter,
	ctx context.Context,
	name, version, sha256hex, sourceIP string,
	cached *cache.VerdictEntry,
	tarballData []byte,
	dur time.Duration,
) {
	h.emitEvent(ctx, siem.Event{
		EventType:          siem.EventPackageVerdict,
		PackageName:        name,
		PackageVersion:     version,
		SHA256:             sha256hex,
		Verdict:            siem.Verdict(cached.Verdict),
		RiskScore:          cached.Score,
		TriggeredRules:     cached.Rules,
		ResponseCode:       200,
		AnalysisDurationMs: dur.Milliseconds(),
		SourceIP:           sourceIP,
	})

	if cached.Verdict == string(siem.VerdictBlock) {
		http.Error(w, "package blocked by security policy (cached)", http.StatusForbidden)
		return
	}
	if cached.Verdict == string(siem.VerdictWarn) {
		w.Header().Set("X-Security-Warning", fmt.Sprintf("score=%.2f (cached)", cached.Score))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarballData)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(tarballData); err != nil {
		log.Printf("proxy: write cached response: %v", err)
	}
}

func (h *Handler) emitEvent(ctx context.Context, e siem.Event) {
	e.Timestamp = time.Now().UTC()
	_ = h.siemEmitter.Emit(ctx, e)
}

// resolveVersion returns (resolved, requested). requested is the version
// parsed from the tarball URL (empty if URL was not a tarball path).
// resolved is the version we will analyse: requested if it exists in the
// registry metadata, otherwise the dist-tags.latest fallback. Caller must
// reject requests where requested != "" and requested != resolved.
func resolveVersion(meta *registry.PackageMeta, name, urlPath string) (resolved, requested string) {
	requested = versionFromTarballPath(name, urlPath)
	if requested != "" && meta != nil {
		if _, ok := meta.Versions[requested]; ok {
			return requested, requested
		}
	}
	if meta != nil {
		if v, ok := meta.DistTags["latest"]; ok {
			return v, requested
		}
	}
	return "unknown", requested
}

// versionFromTarballPath extracts the version from a tarball URL path of the
// form /<name>/-/<basename>-<version>.tgz. For scoped packages the tarball
// basename uses only the unscoped part of the package name (e.g. @foo/bar →
// bar-1.0.0.tgz).
func versionFromTarballPath(name, urlPath string) string {
	m := reTarball.FindStringSubmatch(urlPath)
	if m == nil {
		return ""
	}
	filename := strings.TrimSuffix(m[2], ".tgz")
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	prefix := base + "-"
	if !strings.HasPrefix(filename, prefix) {
		return ""
	}
	return filename[len(prefix):]
}

func tarballFilename(urlPath string) string {
	m := reTarball.FindStringSubmatch(urlPath)
	if m == nil {
		return ""
	}
	return m[2]
}

func previousVersionFromMeta(meta *registry.PackageMeta, current string) string {
	available := make([]string, 0, len(meta.Versions))
	for v := range meta.Versions {
		available = append(available, v)
	}
	return semverutil.PreviousVersion(available, current)
}
