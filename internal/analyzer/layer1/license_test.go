package layer1

import (
	"context"
	"testing"
	"time"

	"github.com/yourusername/npm-proxy/internal/registry"
)

func TestLicense_MissingFires(t *testing.T) {
	l := NewLicenseChecker(0.15, 0.10, 0)
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"1.0.0": time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		},
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {License: ""},
		},
	}
	sigs := l.Check(context.Background(), meta, "1.0.0")
	found := false
	for _, s := range sigs {
		if s.Rule == "license_missing" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected license_missing, got %+v", sigs)
	}
}

func TestLicense_PatchChangeFires(t *testing.T) {
	l := NewLicenseChecker(0.15, 0.10, 0)
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"1.0.0": now.Add(-2 * 24 * time.Hour).Format(time.RFC3339),
			"1.0.1": now.Add(-1 * 24 * time.Hour).Format(time.RFC3339),
		},
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {License: "MIT"},
			"1.0.1": {License: "GPL-3.0"},
		},
	}
	sigs := l.Check(context.Background(), meta, "1.0.1")
	found := false
	for _, s := range sigs {
		if s.Rule == "license_patch_change" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected license_patch_change, got %+v", sigs)
	}
}

func TestLicense_NoChangeNoSignal(t *testing.T) {
	l := NewLicenseChecker(0.15, 0.10, 0)
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"1.0.0": now.Add(-2 * 24 * time.Hour).Format(time.RFC3339),
			"1.0.1": now.Add(-1 * 24 * time.Hour).Format(time.RFC3339),
		},
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {License: "MIT"},
			"1.0.1": {License: "MIT"},
		},
	}
	sigs := l.Check(context.Background(), meta, "1.0.1")
	if len(sigs) != 0 {
		t.Errorf("expected no signals for unchanged MIT license, got %+v", sigs)
	}
}
