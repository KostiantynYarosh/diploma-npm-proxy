package layer1

import (
	"context"
	"strings"

	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/semverutil"
	"github.com/yourusername/npm-proxy/internal/signal"
)

type LicenseChecker struct {
	patchChangeScore    float64
	missingPopScore     float64
	popularDownloads    int
}

func NewLicenseChecker(patchChangeScore, missingPopScore float64, popularDownloads int) *LicenseChecker {
	return &LicenseChecker{
		patchChangeScore: patchChangeScore,
		missingPopScore:  missingPopScore,
		popularDownloads: popularDownloads,
	}
}

func (l *LicenseChecker) Check(_ context.Context, meta *registry.PackageMeta, version string) []signal.Signal {
	var signals []signal.Signal

	current, ok := meta.Versions[version]
	if !ok {
		return nil
	}

	// Missing license field in current version.
	if strings.TrimSpace(current.License) == "" {
		signals = append(signals, signal.Signal{
			Rule:  "license_missing",
			Score: l.missingPopScore,
		})
	}

	// License changed between this version and the previous one.
	prevVer := semverutil.PreviousVersion(allVersions(meta), version)
	if prevVer != "" {
		if prev, ok := meta.Versions[prevVer]; ok {
			if prev.License != "" && current.License != "" && prev.License != current.License {
				// Score higher if the change happens in a patch version bump.
				if semverutil.IsPatchBump(prevVer, version) {
					signals = append(signals, signal.Signal{
						Rule:  "license_patch_change",
						Score: l.patchChangeScore,
					})
				}
			}
		}
	}

	return signals
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
