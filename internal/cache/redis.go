package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	prefixVerdict = "pkg:"
	prefixOSV     = "osv:"
)

// VerdictEntry is the cached result of a full analysis run.
type VerdictEntry struct {
	Score      float64  `json:"score"`
	Verdict    string   `json:"verdict"`
	AnalyzedAt int64    `json:"analyzed_at"`
	Version    string   `json:"version"`
	Name       string   `json:"name"`
	Rules      []string `json:"triggered_rules,omitempty"`
}

// Client wraps go-redis and provides domain-specific cache operations.
type Client struct {
	rdb        *redis.Client
	verdictTTL time.Duration
	osvTTL     time.Duration
}

func New(addr, password string, db int, verdictTTLHours, osvTTLHours int) *Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &Client{
		rdb:        rdb,
		verdictTTL: time.Duration(verdictTTLHours) * time.Hour,
		osvTTL:     time.Duration(osvTTLHours) * time.Hour,
	}
}

func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// GetVerdict returns a cached verdict for the given tarball SHA-256, or nil if not found.
func (c *Client) GetVerdict(ctx context.Context, sha256 string) (*VerdictEntry, error) {
	data, err := c.rdb.Get(ctx, prefixVerdict+sha256).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cache get verdict: %w", err)
	}
	var entry VerdictEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("cache unmarshal verdict: %w", err)
	}
	return &entry, nil
}

// SetVerdict stores a verdict entry keyed by tarball SHA-256.
func (c *Client) SetVerdict(ctx context.Context, sha256 string, entry VerdictEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, prefixVerdict+sha256, data, c.verdictTTL).Err()
}

// CachedVerdict pairs a VerdictEntry with the SHA-256 key it was stored under.
type CachedVerdict struct {
	SHA256 string
	Entry  VerdictEntry
}

// ListVerdicts iterates the verdict cache and returns entries whose verdict
// matches one of the requested states ("allow", "warn", "block"). The scan
// uses Redis SCAN so it does not block other commands, and terminates once
// `limit` entries have been collected (0 = no limit).
func (c *Client) ListVerdicts(ctx context.Context, match []string, limit int) ([]CachedVerdict, error) {
	matchSet := make(map[string]struct{}, len(match))
	for _, m := range match {
		matchSet[m] = struct{}{}
	}

	var (
		cursor uint64
		out    []CachedVerdict
	)
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, prefixVerdict+"*", 100).Result()
		if err != nil {
			return out, fmt.Errorf("cache scan verdicts: %w", err)
		}
		for _, key := range keys {
			data, err := c.rdb.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}
			var entry VerdictEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				continue
			}
			if len(matchSet) > 0 {
				if _, ok := matchSet[entry.Verdict]; !ok {
					continue
				}
			}
			// Strip the "pkg:" prefix so callers get the bare SHA-256.
			sha := key
			if len(sha) > len(prefixVerdict) {
				sha = sha[len(prefixVerdict):]
			}
			out = append(out, CachedVerdict{SHA256: sha, Entry: entry})
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
		cursor = next
		if cursor == 0 {
			return out, nil
		}
	}
}

// InvalidateOSV removes the OSV cache entry for name@version, forcing the next
// lookup to hit the OSV API directly. Used by the recheck worker to pull fresh
// vulnerability data even when TTL has not yet expired.
func (c *Client) InvalidateOSV(ctx context.Context, name, version string) error {
	return c.rdb.Del(ctx, prefixOSV+name+"@"+version).Err()
}

// GetOSV returns a cached OSV check result (true = vulnerable, false = clean).
// Returns (false, false, nil) on cache miss.
func (c *Client) GetOSV(ctx context.Context, name, version string) (bool, bool, error) {
	key := prefixOSV + name + "@" + version
	val, err := c.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return val == "1", true, nil
}

// SetOSV caches the OSV result for name@version.
func (c *Client) SetOSV(ctx context.Context, name, version string, vulnerable bool) error {
	key := prefixOSV + name + "@" + version
	val := "0"
	if vulnerable {
		val = "1"
	}
	return c.rdb.Set(ctx, key, val, c.osvTTL).Err()
}

func (c *Client) Close() error {
	return c.rdb.Close()
}
