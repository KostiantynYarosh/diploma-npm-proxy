package layer1

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yourusername/npm-proxy/internal/registry"
)

func TestAnomaly_VersionSpikeFires(t *testing.T) {
	a := NewAnomalyChecker(AnomalyCheckerOptions{
		MaxVersionsPerDay: 3,
		VersionSpikeScore: 0.2,
	})
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"created": now.Add(-365 * 24 * time.Hour).Format(time.RFC3339),
			"1.0.0":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"1.0.1":   now.Add(-2 * time.Hour).Format(time.RFC3339),
			"1.0.2":   now.Add(-3 * time.Hour).Format(time.RFC3339),
			"1.0.3":   now.Add(-4 * time.Hour).Format(time.RFC3339),
			"1.0.4":   now.Add(-5 * time.Hour).Format(time.RFC3339),
		},
	}
	sigs := a.Check(context.Background(), meta, "1.0.4")
	found := false
	for _, s := range sigs {
		if s.Rule == "anomaly_version_spike" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected anomaly_version_spike, got %+v", sigs)
	}
}

func TestAnomaly_MaintainerChangeFires(t *testing.T) {
	a := NewAnomalyChecker(AnomalyCheckerOptions{
		MaintainerChangeScore: 0.3,
	})
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"created": now.Add(-365 * 24 * time.Hour).Format(time.RFC3339),
			"1.0.0":   now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
			"1.0.1":   now.Add(-1 * 24 * time.Hour).Format(time.RFC3339),
		},
		Versions: map[string]registry.VersionMeta{
			"1.0.0": {Maintainers: []registry.Maintainer{{Name: "alice"}}},
			"1.0.1": {Maintainers: []registry.Maintainer{{Name: "bob"}}},
		},
	}
	sigs := a.Check(context.Background(), meta, "1.0.1")
	found := false
	for _, s := range sigs {
		if s.Rule == "anomaly_maintainer_change" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected anomaly_maintainer_change, got %+v", sigs)
	}
}

func TestAnomaly_SizeDeviationFires(t *testing.T) {
	a := NewAnomalyChecker(AnomalyCheckerOptions{
		SizeDeviationScore: 0.15,
	})
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"created": now.Add(-365 * 24 * time.Hour).Format(time.RFC3339),
		},
		Versions: map[string]registry.VersionMeta{
			"1.0.5": {Dist: registry.DistInfo{UnpackedSize: 1_000_000}}, // 10× median
			"1.0.0": {Dist: registry.DistInfo{UnpackedSize: 100_000}},
			"1.0.1": {Dist: registry.DistInfo{UnpackedSize: 100_000}},
			"1.0.2": {Dist: registry.DistInfo{UnpackedSize: 100_000}},
			"1.0.3": {Dist: registry.DistInfo{UnpackedSize: 100_000}},
			"1.0.4": {Dist: registry.DistInfo{UnpackedSize: 100_000}},
		},
	}
	for v := range meta.Versions {
		meta.Time[v] = now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	}
	sigs := a.Check(context.Background(), meta, "1.0.5")
	found := false
	for _, s := range sigs {
		if s.Rule == "anomaly_size_deviation" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected anomaly_size_deviation, got %+v", sigs)
	}
}

func TestAnomaly_UnusualPublishHourFires(t *testing.T) {
	a := NewAnomalyChecker(AnomalyCheckerOptions{
		UnusualHoursScore: 0.1,
	})
	// Build a history of 25 publishes all at 14:00 UTC, then publish at 03:00 UTC.
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"created": now.Add(-365 * 24 * time.Hour).Format(time.RFC3339),
		},
	}
	base := time.Date(2024, 1, 1, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		ver := fmt.Sprintf("0.%d.0", i)
		meta.Time[ver] = base.Add(time.Duration(i) * 24 * time.Hour).Format(time.RFC3339)
	}
	meta.Time["9.9.9"] = time.Date(2025, 6, 1, 3, 0, 0, 0, time.UTC).Format(time.RFC3339)
	sigs := a.Check(context.Background(), meta, "9.9.9")
	found := false
	for _, s := range sigs {
		if s.Rule == "anomaly_unusual_publish_hour" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected anomaly_unusual_publish_hour, got %+v", sigs)
	}
}
