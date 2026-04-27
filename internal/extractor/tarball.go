package extractor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// FileTree holds extracted file contents keyed by sanitized path.
type FileTree map[string][]byte

// Limits controls extraction safety bounds.
type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// Extract unpacks a gzipped npm tarball from data into an in-memory FileTree.
// It enforces path traversal prevention and all size limits.
func Extract(data []byte, limits Limits) (FileTree, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	tree := make(FileTree)
	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		clean, err := sanitizePath(hdr.Name)
		if err != nil {
			return nil, fmt.Errorf("path traversal in %q: %w", hdr.Name, err)
		}

		if len(tree) >= limits.MaxFiles {
			return nil, fmt.Errorf("exceeded max file count %d", limits.MaxFiles)
		}

		if hdr.Size > limits.MaxFileBytes {
			return nil, fmt.Errorf("file %s exceeds max size %d bytes", clean, limits.MaxFileBytes)
		}

		content, err := io.ReadAll(io.LimitReader(tr, limits.MaxFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", clean, err)
		}
		if int64(len(content)) > limits.MaxFileBytes {
			return nil, fmt.Errorf("file %s exceeds max size %d bytes", clean, limits.MaxFileBytes)
		}

		totalBytes += int64(len(content))
		if totalBytes > limits.MaxTotalBytes {
			return nil, fmt.Errorf("exceeded max total uncompressed size %d bytes", limits.MaxTotalBytes)
		}

		tree[clean] = content
	}

	return tree, nil
}

// sanitizePath cleans a tar entry path and rejects any path traversal attempts.
func sanitizePath(raw string) (string, error) {
	// npm tarballs prefix every entry with "package/"
	clean := filepath.ToSlash(filepath.Clean(raw))
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("path traversal sequence detected")
	}
	if strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("absolute path not allowed")
	}
	return clean, nil
}
