// import-datadog ingests the DataDog malicious-software-packages-dataset
// (https://github.com/DataDog/malicious-software-packages-dataset) into our
// calibration corpus.
//
// Layout expected under -src:
//
//   samples/npm/manifest.json
//   samples/npm/compromised_lib/<pkg>/<version>/<date>-<pkg>-v<version>.zip
//   samples/npm/malicious_intent/<pkg>/<version>/<date>-<pkg>-v<version>.zip
//
// Every zip is password-protected with "infected" (industry convention to
// prevent accidental detonation). The tool decrypts in memory and writes a
// canonical npm tarball to <dest>/<safe>@<version>.tgz, then appends a
// labels.jsonl entry tagged with category=compromised_lib or malicious_intent.
//
// Two physical formats are tolerated inside the zip:
//   1. A single *.tgz at any depth — copied as-is.
//   2. A directory tree of raw package files — repacked into a npm-shaped
//      tarball ("package/<file>" prefix, gzip-compressed) on the fly. This
//      covers older entries that pre-date the dataset's tarball convention.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/yeka/zip"
)

const datadogPassword = "infected"

type fileBlob struct {
	name string
	body []byte
}

type entry struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Tarball  string `json:"tarball"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

// dest is hardcoded — this tool only ever appends to the malicious split of
// the calibration corpus. -src is the only meaningful knob.
const dest = "dataset/malicious"

func main() {
	src := flag.String("src", "", "path to a clone of the DataDog malicious-software-packages-dataset repo (or a directory containing samples/npm)")
	flag.Parse()
	if *src == "" {
		log.Fatal("-src is required")
	}

	root := locateNpmRoot(*src)
	if root == "" {
		log.Fatalf("could not find samples/npm under %s", *src)
	}
	log.Printf("scanning %s", root)

	if err := os.MkdirAll(dest, 0o755); err != nil {
		log.Fatalf("mkdir dest: %v", err)
	}

	labelsPath := filepath.Join(dest, "labels.jsonl")
	labelsFile, err := os.OpenFile(labelsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("open labels: %v", err)
	}
	defer labelsFile.Close()

	imported := 0
	skipped := 0
	seen := make(map[string]bool)

	categories := []string{"compromised_lib", "malicious_intent"}
	for _, cat := range categories {
		catRoot := filepath.Join(root, cat)
		if _, err := os.Stat(catRoot); err != nil {
			log.Printf("skip category %s: %v", cat, err)
			continue
		}
		err := filepath.WalkDir(catRoot, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".zip") {
				return nil
			}

			// Path layout: catRoot/<pkg>/<version>/<file>.zip
			rel, err := filepath.Rel(catRoot, p)
			if err != nil {
				skipped++
				return nil
			}
			parts := strings.Split(filepath.ToSlash(rel), "/")
			if len(parts) < 3 {
				log.Printf("skip %s: unexpected path depth", rel)
				skipped++
				return nil
			}
			pkgName := parts[0]
			pkgVersion := parts[1]

			tarballData, err := decryptToTarball(p, pkgName, pkgVersion)
			if err != nil {
				log.Printf("skip %s@%s (%s): %v", pkgName, pkgVersion, cat, err)
				skipped++
				return nil
			}

			hash := sha256.Sum256(tarballData)
			key := hex.EncodeToString(hash[:])
			if seen[key] {
				return nil
			}
			seen[key] = true

			safe := strings.ReplaceAll(pkgName, "/", "_")
			outName := fmt.Sprintf("%s@%s.tgz", safe, pkgVersion)
			if err := os.WriteFile(filepath.Join(dest, outName), tarballData, 0o644); err != nil {
				log.Printf("write %s: %v", outName, err)
				skipped++
				return nil
			}
			e := entry{
				Name:     pkgName,
				Version:  pkgVersion,
				Tarball:  outName,
				Source:   "datadog:" + d.Name(),
				Category: cat,
			}
			if err := json.NewEncoder(labelsFile).Encode(e); err != nil {
				log.Printf("write label: %v", err)
				skipped++
				return nil
			}
			imported++
			if imported%100 == 0 {
				log.Printf("imported %d so far", imported)
			}
			return nil
		})
		if err != nil {
			log.Printf("walk %s: %v", cat, err)
		}
	}

	log.Printf("done: %d imported, %d skipped, appended to %s", imported, skipped, labelsPath)
}

// locateNpmRoot looks for a samples/npm directory under src. Accepts the
// repo root, the samples dir, or the npm dir itself.
func locateNpmRoot(src string) string {
	candidates := []string{
		filepath.Join(src, "samples", "npm"),
		filepath.Join(src, "npm"),
		src,
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			// Heuristic: npm root has at least one of the two category dirs.
			for _, sub := range []string{"compromised_lib", "malicious_intent"} {
				if st2, err := os.Stat(filepath.Join(c, sub)); err == nil && st2.IsDir() {
					return c
				}
			}
		}
	}
	return ""
}

// decryptToTarball opens the password-protected zip, decrypts every file in
// memory, and yields a single npm-shaped tarball. If the zip already contains
// a *.tgz, that is returned verbatim. Otherwise raw package files are
// re-packed into a tar.gz with the conventional "package/" prefix.
func decryptToTarball(zipPath, pkgName, pkgVersion string) ([]byte, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	var blobs []fileBlob
	var existingTarball []byte

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword(datadogPassword)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Name, err)
		}
		if strings.HasSuffix(strings.ToLower(f.Name), ".tgz") || strings.HasSuffix(strings.ToLower(f.Name), ".tar.gz") {
			existingTarball = body
			break
		}
		blobs = append(blobs, fileBlob{name: f.Name, body: body})
	}

	if existingTarball != nil {
		return existingTarball, nil
	}
	if len(blobs) == 0 {
		return nil, fmt.Errorf("zip is empty after filtering")
	}
	return repackAsTarball(blobs)
}

// repackAsTarball wraps a flat set of files into the npm tarball convention:
// a single gzip-compressed tar where every entry is prefixed with "package/".
// The first leading directory component is stripped (DataDog zips usually
// embed one) so we don't get "package/<orig-dir>/<files>" double-nesting.
func repackAsTarball(blobs []fileBlob) ([]byte, error) {
	prefix := commonPrefix(blobs)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, b := range blobs {
		rel := strings.TrimPrefix(b.name, prefix)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			continue
		}
		hdr := &tar.Header{
			Name: path.Join("package", rel),
			Mode: 0o644,
			Size: int64(len(b.body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// commonPrefix returns the longest leading path component shared by every
// blob name (including the trailing slash), so that "<dir>/file" entries
// collapse to "file" before we re-prefix with "package/".
func commonPrefix(blobs []fileBlob) string {
	if len(blobs) == 0 {
		return ""
	}
	first := filepath.ToSlash(blobs[0].name)
	idx := strings.IndexByte(first, '/')
	if idx < 0 {
		return ""
	}
	candidate := first[:idx+1]
	for _, b := range blobs[1:] {
		if !strings.HasPrefix(filepath.ToSlash(b.name), candidate) {
			return ""
		}
	}
	return candidate
}
