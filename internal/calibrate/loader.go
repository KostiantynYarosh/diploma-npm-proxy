package calibrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LabelEntry is the on-disk schema for labels.jsonl. One JSON object per line.
type LabelEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	PrevVersion string `json:"prev_version,omitempty"`
	Tarball     string `json:"tarball"`               // path relative to labels.jsonl directory
	Meta        string `json:"meta,omitempty"`        // path to PackageMeta JSON snapshot
	OSVVuln     bool   `json:"osv_vulnerable,omitempty"` // true if OSV considered this vulnerable on snapshot date
	Source      string `json:"source,omitempty"`      // free-form provenance, e.g. "ghsa:GHSA-mh6f-..."
	Category    string `json:"category,omitempty"`    // cve_patch | active_malware | typosquat | benign | ...
}

// LoadCorpus reads benign and malicious labels.jsonl files under root and
// returns CorpusEntry slices. Expected layout:
//
//	root/
//	  benign/labels.jsonl
//	  benign/<tarballs>
//	  malicious/labels.jsonl
//	  malicious/<tarballs>
func LoadCorpus(root string) ([]CorpusEntry, error) {
	benign, err := loadSplit(filepath.Join(root, "benign"), LabelBenign)
	if err != nil {
		return nil, fmt.Errorf("load benign: %w", err)
	}
	malicious, err := loadSplit(filepath.Join(root, "malicious"), LabelMalicious)
	if err != nil {
		return nil, fmt.Errorf("load malicious: %w", err)
	}
	out := make([]CorpusEntry, 0, len(benign)+len(malicious))
	out = append(out, benign...)
	out = append(out, malicious...)
	if len(out) == 0 {
		return nil, fmt.Errorf("empty corpus under %s", root)
	}
	return out, nil
}

func loadSplit(dir string, label Label) ([]CorpusEntry, error) {
	manifestPath := filepath.Join(dir, "labels.jsonl")
	f, err := os.Open(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // empty split is allowed during partial-build experiments
		}
		return nil, err
	}
	defer f.Close()

	var entries []CorpusEntry
	dec := json.NewDecoder(f)
	for dec.More() {
		var le LabelEntry
		if err := dec.Decode(&le); err != nil {
			return nil, fmt.Errorf("%s: decode entry: %w", manifestPath, err)
		}
		if le.Name == "" || le.Version == "" || le.Tarball == "" {
			return nil, fmt.Errorf("%s: entry missing required field: %+v", manifestPath, le)
		}
		entries = append(entries, CorpusEntry{
			Name:        le.Name,
			Version:     le.Version,
			PrevVersion: le.PrevVersion,
			TarballPath: resolveRel(dir, le.Tarball),
			MetaPath:    resolveRelOptional(dir, le.Meta),
			OSVVuln:     le.OSVVuln,
			Label:       label,
			Category:    le.Category,
		})
	}
	return entries, nil
}

func resolveRel(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

func resolveRelOptional(base, p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	return resolveRel(base, p)
}
