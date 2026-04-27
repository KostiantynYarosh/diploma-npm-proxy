// Package semverutil centralises npm-style version parsing and comparison so
// detectors share a single, robust implementation that understands pre-releases
// and build metadata. Naive ad-hoc string splits (which earlier detector code
// used) silently mishandled versions like "1.0.0-rc1" - this package wraps
// Masterminds/semver to remove that footgun in one place.
package semverutil

import (
	"sort"

	"github.com/Masterminds/semver/v3"
)

// IsPatchBump reports whether next is the immediate patch successor of prev:
// same major and minor, with next.Patch == prev.Patch + 1. Pre-release suffixes
// are ignored for the comparison itself but malformed versions return false.
func IsPatchBump(prev, next string) bool {
	p, err := semver.NewVersion(prev)
	if err != nil {
		return false
	}
	n, err := semver.NewVersion(next)
	if err != nil {
		return false
	}
	return p.Major() == n.Major() && p.Minor() == n.Minor() && n.Patch() == p.Patch()+1
}

// PreviousVersion returns the highest semver-preceding version present in
// `available` relative to `current`, or "" if none exists. Stable releases
// rank above pre-releases for the same X.Y.Z, matching npm's notion of
// "the last published patch before a given version". Unparseable strings in
// the input are skipped silently rather than failing the whole comparison.
func PreviousVersion(available []string, current string) string {
	curr, err := semver.NewVersion(current)
	if err != nil {
		return ""
	}

	var parsed []*semver.Version
	for _, v := range available {
		if v == current {
			continue
		}
		pv, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if pv.LessThan(curr) {
			parsed = append(parsed, pv)
		}
	}
	if len(parsed) == 0 {
		return ""
	}
	sort.Sort(semver.Collection(parsed))
	return parsed[len(parsed)-1].Original()
}
