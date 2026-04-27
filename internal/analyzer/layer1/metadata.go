package layer1

import (
	"context"
	"sync"
	"time"

	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// registryQuerier is the subset of registry.Client that MetadataChecker needs.
// Declared as an interface to keep the checker testable without a network
// dependency and to allow a nil client (signals that require network data
// simply do not fire).
type registryQuerier interface {
	FetchMonthlyDownloads(ctx context.Context, name string) (int64, error)
	FetchUserCreatedAt(ctx context.Context, username string) (time.Time, error)
}

type MetadataChecker struct {
	client                 registryQuerier
	newPackageDays         int
	newPackageScore        float64
	youngMaintainerDays    int
	youngMaintainerScore   float64
	lowDownloadsThreshold  int64
	lowDownloadsScore      float64
	popularThreshold       int64 // downloads above which "few versions published" is a stale-signal trigger
	popularButStaleDays    int   // no publish for > this many days on a popular package
	popularButStaleScore   float64
	netTimeout             time.Duration
}

// MetadataCheckerOptions groups the configurable knobs so callers don't
// drown in positional parameters.
type MetadataCheckerOptions struct {
	NewPackageDays        int
	NewPackageScore       float64
	YoungMaintainerDays   int
	YoungMaintainerScore  float64
	LowDownloadsThreshold int64
	LowDownloadsScore     float64
	PopularThreshold      int64
	PopularButStaleDays   int
	PopularButStaleScore  float64
	NetTimeout            time.Duration
}

// NewMetadataChecker constructs a MetadataChecker. A nil client disables the
// network-dependent signals (downloads/activity ratio and maintainer age);
// the rest of the checker still runs on metadata already fetched upstream.
func NewMetadataChecker(client registryQuerier, opts MetadataCheckerOptions) *MetadataChecker {
	if opts.NetTimeout <= 0 {
		opts.NetTimeout = 3 * time.Second
	}
	return &MetadataChecker{
		client:                client,
		newPackageDays:        opts.NewPackageDays,
		newPackageScore:       opts.NewPackageScore,
		youngMaintainerDays:   opts.YoungMaintainerDays,
		youngMaintainerScore:  opts.YoungMaintainerScore,
		lowDownloadsThreshold: opts.LowDownloadsThreshold,
		lowDownloadsScore:     opts.LowDownloadsScore,
		popularThreshold:      opts.PopularThreshold,
		popularButStaleDays:   opts.PopularButStaleDays,
		popularButStaleScore:  opts.PopularButStaleScore,
		netTimeout:            opts.NetTimeout,
	}
}

func (m *MetadataChecker) Check(ctx context.Context, meta *registry.PackageMeta, _ string) []signal.Signal {
	var signals []signal.Signal
	now := time.Now().UTC()

	// Basic metadata signals that don't require extra network calls.
	if created, ok := meta.Time["created"]; ok {
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			if now.Sub(t) < time.Duration(m.newPackageDays)*24*time.Hour {
				signals = append(signals, signal.Signal{
					Rule:   "metadata_new_package",
					Score:  m.newPackageScore,
					Detail: "created_at=" + created,
				})
			}
		}
	}

	if len(meta.Maintainers) == 1 {
		signals = append(signals, signal.Signal{
			Rule:  "metadata_single_maintainer",
			Score: 0.05,
		})
	}

	if m.client == nil {
		return signals
	}

	// Network-dependent signals: fetch concurrently with a bounded context so
	// a slow user-profile endpoint cannot stall the pipeline.
	netCtx, cancel := context.WithTimeout(ctx, m.netTimeout)
	defer cancel()

	var (
		mu       sync.Mutex
		extra    []signal.Signal
		wg       sync.WaitGroup
	)

	// Downloads and activity-ratio check.
	wg.Add(1)
	go func() {
		defer wg.Done()
		dl, err := m.client.FetchMonthlyDownloads(netCtx, meta.Name)
		if err != nil {
			return
		}
		if m.lowDownloadsThreshold > 0 && dl < m.lowDownloadsThreshold {
			mu.Lock()
			extra = append(extra, signal.Signal{
				Rule:   "metadata_low_downloads",
				Score:  m.lowDownloadsScore,
				Detail: "monthly_downloads=" + itoa64(dl),
			})
			mu.Unlock()
		}
		// Popular-but-stale: package has high downloads but has not seen a
		// publish in a long time - heightens risk that a recent re-publish is
		// an account takeover rather than maintenance.
		if m.popularThreshold > 0 && dl >= m.popularThreshold {
			latestPublish := latestPublishTime(meta)
			if !latestPublish.IsZero() && now.Sub(latestPublish) > time.Duration(m.popularButStaleDays)*24*time.Hour {
				mu.Lock()
				extra = append(extra, signal.Signal{
					Rule:   "metadata_popular_but_stale",
					Score:  m.popularButStaleScore,
					Detail: "monthly_downloads=" + itoa64(dl) + " last_publish=" + latestPublish.Format(time.RFC3339),
				})
				mu.Unlock()
			}
		}
	}()

	// Maintainer age - check each maintainer concurrently.
	for _, mnt := range meta.Maintainers {
		if mnt.Name == "" {
			continue
		}
		wg.Add(1)
		go func(username string) {
			defer wg.Done()
			created, err := m.client.FetchUserCreatedAt(netCtx, username)
			if err != nil {
				return
			}
			if now.Sub(created) < time.Duration(m.youngMaintainerDays)*24*time.Hour {
				mu.Lock()
				extra = append(extra, signal.Signal{
					Rule:   "metadata_young_maintainer",
					Score:  m.youngMaintainerScore,
					Detail: "maintainer=" + username + " created=" + created.Format(time.RFC3339),
				})
				mu.Unlock()
			}
		}(mnt.Name)
	}

	wg.Wait()
	signals = append(signals, extra...)
	return signals
}

func latestPublishTime(meta *registry.PackageMeta) time.Time {
	var latest time.Time
	for ver, ts := range meta.Time {
		if ver == "created" || ver == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}

func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [24]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
