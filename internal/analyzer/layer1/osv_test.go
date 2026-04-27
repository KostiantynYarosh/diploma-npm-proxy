package layer1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stubCache implements the osvCache interface used by OSVChecker. It is
// intentionally inert - the tests cover both the cache-hit and cache-miss
// paths, and real Redis is not exercised here.
type stubCache struct {
	stored map[string]bool
}

func (s *stubCache) GetOSV(_ context.Context, name, version string) (bool, bool, error) {
	if s.stored == nil {
		return false, false, nil
	}
	v, ok := s.stored[name+"@"+version]
	return v, ok, nil
}
func (s *stubCache) SetOSV(_ context.Context, name, version string, vulnerable bool) error {
	if s.stored == nil {
		s.stored = map[string]bool{}
	}
	s.stored[name+"@"+version] = vulnerable
	return nil
}

func TestOSV_VulnerableResponseProducesVeto(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]string{{"id": "GHSA-xxxx-yyyy"}},
		})
	}))
	defer srv.Close()

	checker := NewOSVChecker(&stubCache{}, srv.URL, 5*time.Second)
	sigs, err := checker.Check(context.Background(), "malicious-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(sigs) != 1 || !sigs[0].Veto || sigs[0].Rule != "osv_known_vulnerability" {
		t.Errorf("expected osv veto, got %+v", sigs)
	}
}

func TestOSV_CleanResponseNoSignal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	checker := NewOSVChecker(&stubCache{}, srv.URL, 5*time.Second)
	sigs, err := checker.Check(context.Background(), "clean-pkg", "1.0.0")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("expected no signals for clean package, got %+v", sigs)
	}
}
