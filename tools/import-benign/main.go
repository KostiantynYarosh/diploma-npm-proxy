// import-benign downloads the top-N most popular npm packages (latest version
// each) into dataset/benign/. The output is the negative-class half of the
// calibration corpus - what we use to measure false-positive rates.
//
// Malicious specimens come from import-datadog. We deliberately don't curate
// our own malicious YAML seed list any more: real attack samples live in the
// DataDog dataset, not in npm registry, so a list-driven tool there was
// always an awkward fit.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dest        = "dataset/benign"
	defaultList = "configs/top10k.txt"
	// httpTimeout is intentionally large: native-CLI/native-binding packages
	// (puppeteer, playwright, electron) routinely ship 100-250 MB tarballs and
	// the npm CDN can be slow on them. A shorter timeout silently truncates
	// the benign corpus to small packages, biasing the FP-rate metric.
	httpTimeout  = 5 * time.Minute
	metaLimit    = 100 * 1024 * 1024
	tarballLimit = 500 * 1024 * 1024 // 500 MB — matches the production proxy envelope for large native packages
)

type registryDoc struct {
	Versions map[string]struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	} `json:"versions"`
	DistTags map[string]string `json:"dist-tags"`
}

type searchResp struct {
	Objects []struct {
		Package struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"package"`
	} `json:"objects"`
}

type label struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Tarball  string `json:"tarball"`
	Meta     string `json:"meta"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

func main() {
	top := flag.Int("top", 500, "fetch the top-N most popular npm packages for FP testing")
	listPath := flag.String("list", defaultList, "newline-delimited package list; comments beginning with # are ignored")
	concurrency := flag.Int("concurrency", 3, "parallel package downloads")
	refresh := flag.Bool("refresh", false, "re-download packages already present in labels.jsonl")
	flag.Parse()
	if *concurrency < 1 {
		*concurrency = 1
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		log.Fatalf("mkdir dest: %v", err)
	}

	httpc := &http.Client{Timeout: httpTimeout}
	ctx := context.Background()

	names, err := loadPackageList(*listPath, *top)
	if err != nil || len(names) < *top {
		if err != nil {
			log.Printf("load package list %s: %v", *listPath, err)
		} else {
			log.Printf("package list %s has only %d names, need %d", *listPath, len(names), *top)
		}
		if genErr := generatePackageList(ctx, *listPath, *top); genErr != nil {
			log.Printf("generate package list: %v; falling back to npm search", genErr)
			names = fetchPopularNames(ctx, httpc, *top)
			log.Printf("fetched %d package names from npm search", len(names))
		} else {
			names, err = loadPackageList(*listPath, *top)
			if err != nil {
				log.Fatalf("load generated package list %s: %v", *listPath, err)
			}
			log.Printf("loaded %d package names from generated %s", len(names), *listPath)
		}
	} else {
		log.Printf("loaded %d package names from %s", len(names), *listPath)
	}
	if len(names) == 0 {
		log.Fatalf("no package names to import")
	}

	existing, err := loadExistingLabels(filepath.Join(dest, "labels.jsonl"))
	if err != nil {
		log.Fatalf("load existing labels: %v", err)
	}
	pending := make([]string, 0, len(names))
	skippedExisting := 0
	for _, name := range names {
		if !*refresh {
			if _, ok := existing[name]; ok {
				skippedExisting++
				continue
			}
		}
		pending = append(pending, name)
	}
	if skippedExisting > 0 {
		log.Printf("skipped %d packages already present in labels.jsonl", skippedExisting)
	}
	if len(pending) == 0 {
		log.Printf("done: 0 imported, 0 skipped; all %d requested packages already present", len(names))
		return
	}

	labelsFile, err := os.OpenFile(filepath.Join(dest, "labels.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("open labels: %v", err)
	}
	defer labelsFile.Close()
	enc := json.NewEncoder(labelsFile)

	var (
		mu       sync.Mutex
		imported int
		skipped  int
	)
	total := len(pending)
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for _, name := range pending {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()

			version, tarballURL, metaBody, err := fetchLatest(ctx, httpc, name)
			if err != nil {
				log.Printf("skip %s: %v", name, err)
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}
			tarballBody, err := httpGetBytes(ctx, httpc, tarballURL, tarballLimit)
			if err != nil {
				log.Printf("skip %s: tarball: %v", name, err)
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}

			safe := strings.ReplaceAll(name, "/", "_")
			tarball := fmt.Sprintf("%s@%s.tgz", safe, version)
			metaName := fmt.Sprintf("%s.meta.json", safe)

			if err := os.WriteFile(filepath.Join(dest, tarball), tarballBody, 0o644); err != nil {
				log.Printf("write tarball %s: %v", tarball, err)
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}
			if err := os.WriteFile(filepath.Join(dest, metaName), metaBody, 0o644); err != nil {
				log.Printf("write meta %s: %v", metaName, err)
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}

			mu.Lock()
			defer mu.Unlock()
			if err := enc.Encode(label{
				Name:     name,
				Version:  version,
				Tarball:  tarball,
				Meta:     metaName,
				Source:   "npm-search-popularity",
				Category: "popular",
			}); err != nil {
				log.Printf("write label %s: %v", name, err)
				skipped++
				return
			}
			imported++
			if imported%50 == 0 {
				log.Printf("imported %d/%d", imported, total)
			}
		}(name)
	}
	wg.Wait()

	log.Printf("done: %d imported, %d skipped, %d already-present, %d requested", imported, skipped, skippedExisting, len(names))
}

func loadPackageList(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	names := make([]string, 0, limit)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		names = append(names, line)
		if len(names) >= limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

func generatePackageList(ctx context.Context, path string, target int) error {
	if target < 1 {
		target = 1
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	log.Printf("generating package list via tools/gen-top10k: target=%d out=%s", target, path)
	cmd := exec.CommandContext(ctx, "go", "run", "./tools/gen-top10k", "-out", path, "-target", strconv.Itoa(target))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadExistingLabels(path string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for {
		var l label
		if err := dec.Decode(&l); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if l.Name != "" {
			out[l.Name] = struct{}{}
		}
	}
	return out, nil
}

// fetchPopularNames pages the npm search API by descending popularity and
// returns up to n unique names.
func fetchPopularNames(ctx context.Context, c *http.Client, n int) []string {
	const pageSize = 250
	seen := map[string]bool{}
	var out []string
	for from := 0; len(out) < n && from < 5000; from += pageSize {
		size := pageSize
		if from+size > 5000 {
			size = 5000 - from
		}
		url := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=boost-exact:false&size=%d&from=%d&popularity=1.0", size, from)
		body, err := httpGetBytes(ctx, c, url, 4*1024*1024)
		if err != nil {
			log.Printf("search page %d: %v", from, err)
			break
		}
		var r searchResp
		if err := json.Unmarshal(body, &r); err != nil {
			log.Printf("search page %d parse: %v", from, err)
			break
		}
		if len(r.Objects) == 0 {
			break
		}
		for _, o := range r.Objects {
			if seen[o.Package.Name] {
				continue
			}
			seen[o.Package.Name] = true
			out = append(out, o.Package.Name)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}

// fetchLatest returns (version, tarballURL, fullMetaBytes) for the latest
// dist-tag of a package.
func fetchLatest(ctx context.Context, c *http.Client, name string) (string, string, []byte, error) {
	body, err := httpGetBytes(ctx, c, "https://registry.npmjs.org/"+name, metaLimit)
	if err != nil {
		return "", "", nil, err
	}
	var doc registryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", nil, fmt.Errorf("parse meta: %w", err)
	}
	version := doc.DistTags["latest"]
	if version == "" {
		return "", "", nil, fmt.Errorf("no dist-tags.latest")
	}
	v, ok := doc.Versions[version]
	if !ok || v.Dist.Tarball == "" {
		return "", "", nil, fmt.Errorf("no tarball for latest %s", version)
	}
	return version, v.Dist.Tarball, body, nil
}

func httpGetBytes(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := readLimited(resp.Body, limit)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return body, readErr
			}
			lastErr = fmt.Errorf("%s: %d", url, resp.StatusCode)
			if resp.StatusCode != 429 && resp.StatusCode < 500 {
				return nil, lastErr
			}
		}

		wait := time.Duration(1<<attempt) * time.Second
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
		log.Printf("retry %d/6 after %v: %v", attempt+1, wait, lastErr)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, lastErr
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return body, nil
}
