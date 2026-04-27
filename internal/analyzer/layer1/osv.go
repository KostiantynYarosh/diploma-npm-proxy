package layer1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/yourusername/npm-proxy/internal/signal"
)

const (
	osvURL = "https://api.osv.dev/v1/query"
	// CWE-1035: Use of Components with Known Vulnerabilities. Standard MITRE
	// CWE for matched OSV advisories so SIEM correlation has a stable taxonomy.
	osvCWE = "CWE-1035"
)

type osvCache interface {
	GetOSV(ctx context.Context, name, version string) (vulnerable bool, found bool, err error)
	SetOSV(ctx context.Context, name, version string, vulnerable bool) error
}

type OSVChecker struct {
	cache  osvCache
	client *http.Client
	apiURL string
}

func NewOSVChecker(cache osvCache, apiURL string, timeout time.Duration) *OSVChecker {
	if apiURL == "" {
		apiURL = osvURL
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &OSVChecker{
		cache:  cache,
		client: &http.Client{Timeout: timeout},
		apiURL: apiURL,
	}
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

func (o *OSVChecker) Check(ctx context.Context, name, version string) ([]signal.Signal, error) {
	// Check Redis cache first.
	if o.cache != nil {
		vuln, found, err := o.cache.GetOSV(ctx, name, version)
		switch {
		case err != nil:
			// Cache miss vs. transient: distinguish via log so operators see
			// flapping Redis behavior rather than silently paying every API
			// call. Fall through to the OSV API regardless.
			log.Printf("osv: cache lookup failed for %s@%s: %v - querying OSV API", name, version, err)
		case found && vuln:
			return []signal.Signal{{Rule: "osv_known_vulnerability", Veto: true, CWE: osvCWE}}, nil
		case found:
			return nil, nil
		}
	}

	query := osvQuery{
		Package: osvPackage{Name: name, Ecosystem: "npm"},
		Version: version,
	}
	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned %d", resp.StatusCode)
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}

	vulnerable := len(osvResp.Vulns) > 0

	if o.cache != nil {
		if err := o.cache.SetOSV(ctx, name, version, vulnerable); err != nil {
			log.Printf("osv: cache write failed for %s@%s: %v", name, version, err)
		}
	}

	if vulnerable {
		return []signal.Signal{{Rule: "osv_known_vulnerability", Veto: true, CWE: osvCWE}}, nil
	}
	return nil, nil
}
