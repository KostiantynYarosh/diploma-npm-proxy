package layer1

import (
	"context"

	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/semverutil"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// LicenseChecker emits a single signal: license_patch_change. The
// license_missing rule was removed after calibration consistently zeroed it
// across multiple profile runs - missing-license alone has too little
// discriminative power on real npm corpus to survive the FP cap.
type LicenseChecker struct {
	patchChangeScore float64
}

func NewLicenseChecker(patchChangeScore float64) *LicenseChecker {
	return &LicenseChecker{patchChangeScore: patchChangeScore}
}

func (l *LicenseChecker) Check(_ context.Context, meta *registry.PackageMeta, version string) []signal.Signal {
	current, ok := meta.Versions[version]
	if !ok {
		return nil
	}

	prevVer := semverutil.PreviousVersion(allVersions(meta), version)
	if prevVer == "" {
		return nil
	}
	prev, ok := meta.Versions[prevVer]
	if !ok || prev.License == "" || current.License == "" {
		return nil
	}
	if prev.License == current.License {
		return nil
	}
	if !semverutil.IsPatchBump(prevVer, version) {
		return nil
	}
	return []signal.Signal{{
		Rule:  "license_patch_change",
		Score: l.patchChangeScore,
	}}
}

// allVersions returns every version key present in the metadata's versions map -
// the canonical input for semverutil.PreviousVersion.
func allVersions(meta *registry.PackageMeta) []string {
	out := make([]string, 0, len(meta.Versions))
	for v := range meta.Versions {
		out = append(out, v)
	}
	return out
}
