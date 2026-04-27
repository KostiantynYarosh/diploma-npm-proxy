package layer1

import (
	"context"
	"testing"
	"time"

	"github.com/yourusername/npm-proxy/internal/registry"
)

// fakeRegistry satisfies registryQuerier without touching the network.
type fakeRegistry struct {
	downloads map[string]int64
	userAge   map[string]time.Time
	err       error
}

func (f *fakeRegistry) FetchMonthlyDownloads(_ context.Context, name string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.downloads[name], nil
}
func (f *fakeRegistry) FetchUserCreatedAt(_ context.Context, username string) (time.Time, error) {
	if f.err != nil {
		return time.Time{}, f.err
	}
	return f.userAge[username], nil
}

func TestMetadata_NewPackageFires(t *testing.T) {
	m := NewMetadataChecker(nil, MetadataCheckerOptions{
		NewPackageDays:  7,
		NewPackageScore: 0.2,
	})
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"created": time.Now().UTC().Add(-2 * 24 * time.Hour).Format(time.RFC3339),
		},
	}
	sigs := m.Check(context.Background(), meta, "1.0.0")
	if len(sigs) == 0 || sigs[0].Rule != "metadata_new_package" {
		t.Fatalf("expected metadata_new_package, got %+v", sigs)
	}
}

func TestMetadata_OldPackageDoesNotFire(t *testing.T) {
	m := NewMetadataChecker(nil, MetadataCheckerOptions{
		NewPackageDays:  7,
		NewPackageScore: 0.2,
	})
	meta := &registry.PackageMeta{
		Time: map[string]string{
			"created": time.Now().UTC().Add(-365 * 24 * time.Hour).Format(time.RFC3339),
		},
		Maintainers: []registry.Maintainer{{Name: "a"}, {Name: "b"}},
	}
	sigs := m.Check(context.Background(), meta, "1.0.0")
	for _, s := range sigs {
		if s.Rule == "metadata_new_package" {
			t.Errorf("should not have fired metadata_new_package for old package")
		}
	}
}

func TestMetadata_YoungMaintainerFires(t *testing.T) {
	fake := &fakeRegistry{
		userAge: map[string]time.Time{"newbie": time.Now().UTC().Add(-10 * 24 * time.Hour)},
	}
	m := NewMetadataChecker(fake, MetadataCheckerOptions{
		NewPackageDays:       7,
		YoungMaintainerDays:  30,
		YoungMaintainerScore: 0.25,
	})
	meta := &registry.PackageMeta{
		Name:        "somepkg",
		Time:        map[string]string{"created": time.Now().UTC().Add(-365 * 24 * time.Hour).Format(time.RFC3339)},
		Maintainers: []registry.Maintainer{{Name: "newbie"}},
	}
	sigs := m.Check(context.Background(), meta, "1.0.0")
	found := false
	for _, s := range sigs {
		if s.Rule == "metadata_young_maintainer" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected metadata_young_maintainer signal, got %+v", sigs)
	}
}
