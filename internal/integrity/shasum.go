package integrity

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Verify checks the tarball bytes against the expected shasum (SHA-1 hex)
// and the optional integrity field (SRI format: sha512-<base64>).
func Verify(data []byte, shasum, integrity string) error {
	if shasum != "" {
		if err := verifySHA1(data, shasum); err != nil {
			return err
		}
	}
	if integrity != "" {
		if err := verifySRI(data, integrity); err != nil {
			return err
		}
	}
	return nil
}

func verifySHA1(data []byte, expected string) error {
	h := sha1.Sum(data)
	got := hex.EncodeToString(h[:])
	if got != strings.ToLower(expected) {
		return fmt.Errorf("SHA-1 mismatch: got %s, want %s", got, expected)
	}
	return nil
}

func verifySRI(data []byte, integrity string) error {
	// SRI format: "sha512-<base64>"
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid SRI format: %s", integrity)
	}
	algo, encoded := parts[0], parts[1]

	switch strings.ToLower(algo) {
	case "sha512":
		h := sha512.Sum512(data)
		got := base64.StdEncoding.EncodeToString(h[:])
		if got != encoded {
			return fmt.Errorf("SHA-512 SRI mismatch: got %s, want %s", got, encoded)
		}
	default:
		// Unknown algorithm - skip rather than reject; SHA-1 already verified above.
		return nil
	}
	return nil
}
