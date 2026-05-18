package layer1

import (
	"context"
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

func TestAnomaly_NoSpikeBelowThreshold(t *testing.T) {
	a := NewAnomalyChecker(AnomalyCheckerOptions{
		MaxVersionsPerDay: 10,
		VersionSpikeScore: 0.2,
	})
	now := time.Now().UTC()
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"1.0.0": now.Add(-1 * time.Hour).Format(time.RFC3339),
			"1.0.1": now.Add(-3 * time.Hour).Format(time.RFC3339),
		},
	}
	sigs := a.Check(context.Background(), meta, "1.0.1")
	if len(sigs) != 0 {
		t.Errorf("expected no signals below maxVersionsPerDay, got %+v", sigs)
	}
}
