package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DistInfo holds integrity and size fields from npm registry metadata.
type DistInfo struct {
	Shasum       string `json:"shasum"`
	Integrity    string `json:"integrity"`
	TarballURL   string `json:"tarball"`
	UnpackedSize int64  `json:"unpackedSize"`
}

// VersionMeta is a subset of the per-version object from the npm registry.
type VersionMeta struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	Scripts         map[string]string `json:"scripts"`
	License         string            `json:"license"`
	Dist            DistInfo          `json:"dist"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Maintainers     []Maintainer      `json:"maintainers"`
}

// PackageMeta is a subset of the top-level npm metadata document.
type PackageMeta struct {
	Name        string                 `json:"name"`
	Time        map[string]string      `json:"time"`   // version → RFC3339 publish time
	Versions    map[string]VersionMeta `json:"versions"`
	DistTags    map[string]string      `json:"dist-tags"`
	Maintainers []Maintainer           `json:"maintainers"`
}

type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Client struct {
	http        *http.Client
	upstreamURL string
	maxRetries  int
}

func New(upstreamURL string, connectTimeout, totalTimeout time.Duration, maxRetries int) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: connectTimeout,
		}).DialContext,
		TLSHandshakeTimeout: connectTimeout,
	}
	return &Client{
		http: &http.Client{
			Transport: transport,
			Timeout:   totalTimeout,
		},
		upstreamURL: upstreamURL,
		maxRetries:  maxRetries,
	}
}

// FetchTarball downloads the tarball and returns the raw bytes.
// The caller must enforce size limits via io.LimitReader before passing the reader.
func (c *Client) FetchTarball(ctx context.Context, tarballURL string, limit int64) ([]byte, error) {
	return c.getBytes(ctx, tarballURL, limit)
}

// FetchPackageMeta fetches the full package metadata document.
func (c *Client) FetchPackageMeta(ctx context.Context, name string) (*PackageMeta, error) {
	url := fmt.Sprintf("%s/%s", c.upstreamURL, name)
	data, err := c.getBytes(ctx, url, 10*1024*1024) // 10 MB metadata limit
	if err != nil {
		return nil, err
	}
	var meta PackageMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse package meta: %w", err)
	}
	return &meta, nil
}

// FetchVersionMeta fetches metadata for a specific version.
func (c *Client) FetchVersionMeta(ctx context.Context, name, version string) (*VersionMeta, error) {
	url := fmt.Sprintf("%s/%s/%s", c.upstreamURL, name, version)
	data, err := c.getBytes(ctx, url, 2*1024*1024)
	if err != nil {
		return nil, err
	}
	var meta VersionMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse version meta: %w", err)
	}
	return &meta, nil
}

// DownloadsPoint is the response shape of api.npmjs.org/downloads/point/<range>/<pkg>.
type DownloadsPoint struct {
	Downloads int64  `json:"downloads"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Package   string `json:"package"`
}

// FetchMonthlyDownloads returns the number of downloads for the package in the
// last month, querying api.npmjs.org (a separate host from the registry).
func (c *Client) FetchMonthlyDownloads(ctx context.Context, name string) (int64, error) {
	// api.npmjs.org is the canonical host for download metrics.
	url := fmt.Sprintf("https://api.npmjs.org/downloads/point/last-month/%s", name)
	data, err := c.doGet(ctx, url, 64*1024)
	if err != nil {
		return 0, err
	}
	var dp DownloadsPoint
	if err := json.Unmarshal(data, &dp); err != nil {
		return 0, fmt.Errorf("parse downloads point: %w", err)
	}
	return dp.Downloads, nil
}

// UserInfo is a subset of the npm user profile document.
type UserInfo struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Created struct {
		RFC  string `json:"rfc3339"`
		Date string `json:"$date"` // some registries return this form
	} `json:"created"`
	// The legacy _time object is sometimes populated instead.
	Time string `json:"time"`
}

// FetchUserCreatedAt returns the account creation timestamp for an npm user, if available.
func (c *Client) FetchUserCreatedAt(ctx context.Context, username string) (time.Time, error) {
	url := fmt.Sprintf("%s/-/user/org.couchdb.user:%s", c.upstreamURL, username)
	data, err := c.doGet(ctx, url, 512*1024)
	if err != nil {
		return time.Time{}, err
	}
	// The user document sometimes exposes a top-level "created" string, but the
	// widely available fallback is "time.created" in the underlying CouchDB doc.
	// We unmarshal into a generic map to accommodate variance.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return time.Time{}, err
	}
	// Common shapes: {"created": "<rfc>"} or {"time": {"created": "<rfc>"}}.
	if s, ok := raw["created"].(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, nil
		}
	}
	if tm, ok := raw["time"].(map[string]any); ok {
		if s, ok := tm["created"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("user creation time not available")
}

// ProxyRequest forwards a request transparently and returns the response.
func (c *Client) ProxyRequest(ctx context.Context, method, url string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return c.http.Do(req)
}

func (c *Client) getBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 500 * time.Millisecond):
			}
		}

		data, err := c.doGet(ctx, url, limit)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("fetch %s after %d attempts: %w", url, c.maxRetries+1, lastErr)
}

func (c *Client) doGet(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned %d for %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
