// gen-top10k fetches popular npm package names via the npm registry search API
// and writes them, one per line, to the target file. The list is used by the
// typosquatting detector as the reference set of well-known packages.
//
// Usage:
//
//	go run ./cmd/gen-top10k -out configs/top10k.txt -target 10000
//
// Strategy: iterate short alphanumeric seed queries and aggregate results,
// ranked by weekly download count. The npm registry search API returns at
// most 250 results per request and enforces a soft ceiling around 10k
// per query; combining queries yields broader coverage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type searchResponse struct {
	Objects []struct {
		Downloads struct {
			Weekly int64 `json:"weekly"`
		} `json:"downloads"`
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"objects"`
}

func main() {
	outPath := flag.String("out", "configs/top10k.txt", "output file path")
	target := flag.Int("target", 10000, "desired number of unique packages")
	flag.Parse()

	client := &http.Client{Timeout: 30 * time.Second}

	// Seeds chosen to maximize coverage. The npm search API rejects text
	// parameters shorter than 2 characters, so we use bigrams and short words.
	seeds := []string{
		"aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "al", "am", "an", "ap", "ar", "as", "at", "au", "av", "aw", "ax", "ay", "az",
		"ba", "be", "bi", "bl", "bo", "br", "bu", "by",
		"ca", "ce", "ch", "ci", "cl", "co", "cr", "cu", "cy",
		"da", "de", "di", "do", "dr", "du", "dy",
		"ea", "eb", "ec", "ed", "ef", "el", "em", "en", "ep", "er", "es", "et", "ev", "ex",
		"fa", "fe", "fi", "fl", "fo", "fr", "fu",
		"ga", "ge", "gi", "gl", "go", "gr", "gu",
		"ha", "he", "hi", "ho", "ht", "hu", "hy",
		"ic", "id", "ig", "il", "im", "in", "io", "ip", "ir", "is", "it", "iv",
		"ja", "je", "jo", "js", "ju",
		"ka", "ke", "ki", "kn",
		"la", "le", "li", "lo", "lu", "ly",
		"ma", "me", "mi", "mo", "mu", "my",
		"na", "ne", "ni", "no", "nu",
		"ob", "oc", "of", "ok", "ol", "om", "on", "op", "or", "os", "ou", "ov", "ow",
		"pa", "pe", "ph", "pi", "pl", "po", "pr", "pu", "py",
		"qu",
		"ra", "re", "ri", "ro", "ru",
		"sa", "sc", "se", "sh", "si", "sk", "sl", "sm", "sn", "so", "sp", "sq", "st", "su", "sw", "sy",
		"ta", "te", "th", "ti", "to", "tr", "tu", "tv", "tw", "ty",
		"ub", "ui", "ul", "un", "up", "ur", "us", "ut",
		"va", "ve", "vi", "vo", "vu",
		"wa", "we", "wh", "wi", "wo", "wr",
		"xm", "xp",
		"ya", "ye", "yi",
		"za", "ze", "zi", "zo",
	}

	type entry struct {
		name      string
		downloads int64
	}
	best := map[string]int64{}

	for _, q := range seeds {
		// Paginate up to 2000 results per seed (8 pages × 250).
		for from := 0; from < 2000; from += 250 {
			u := fmt.Sprintf(
				"https://registry.npmjs.org/-/v1/search?text=%s&size=250&from=%d&popularity=1.0",
				url.QueryEscape(q), from,
			)
			var (
				resp *http.Response
				body []byte
				err  error
			)
			// Retry with exponential backoff on 429/5xx.
			for retry := 0; retry < 5; retry++ {
				resp, err = client.Get(u)
				if err != nil {
					log.Printf("seed %q from %d HTTP error: %v", q, from, err)
					time.Sleep(time.Duration(1<<retry) * time.Second)
					continue
				}
				body, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode == 429 || resp.StatusCode >= 500 {
					wait := time.Duration(2<<retry) * time.Second
					log.Printf("seed %q from %d status=%d; backing off %v", q, from, resp.StatusCode, wait)
					time.Sleep(wait)
					continue
				}
				break
			}
			if err != nil || resp == nil {
				break
			}
			if resp.StatusCode != 200 {
				log.Printf("seed %q from %d final status=%d body=%.200s", q, from, resp.StatusCode, string(body))
				break
			}
			var sr searchResponse
			if err := json.Unmarshal(body, &sr); err != nil {
				log.Printf("seed %q from %d json error: %v body=%.200s", q, from, err, string(body))
				break
			}
			if len(sr.Objects) == 0 {
				break
			}
			for _, o := range sr.Objects {
				n := strings.TrimSpace(o.Package.Name)
				if n == "" {
					continue
				}
				if d, ok := best[n]; !ok || o.Downloads.Weekly > d {
					best[n] = o.Downloads.Weekly
				}
			}
			log.Printf("seed=%q from=%d got=%d total_unique=%d", q, from, len(sr.Objects), len(best))
			if len(sr.Objects) < 250 {
				break
			}
			// Soft throttle to be polite to the registry (Cloudflare triggers 1015 at ~10 rps).
			time.Sleep(400 * time.Millisecond)
		}
		if len(best) >= *target*2 {
			// We have enough to rank; no need to keep hitting the API.
			break
		}
	}

	entries := make([]entry, 0, len(best))
	for n, d := range best {
		entries = append(entries, entry{name: n, downloads: d})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].downloads > entries[j].downloads
	})
	if len(entries) > *target {
		entries = entries[:*target]
	}
	// Sort final slice alphabetically for a stable, diff-friendly file.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})

	f, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create %s: %v", *outPath, err)
	}
	defer f.Close()

	fmt.Fprintf(f, "# Auto-generated list of popular npm packages ranked by weekly downloads.\n")
	fmt.Fprintf(f, "# Source: registry.npmjs.org search API; regenerate via `go run ./cmd/gen-top10k`.\n")
	fmt.Fprintf(f, "# Generated: %s UTC\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "# Count: %d\n", len(entries))
	for _, e := range entries {
		fmt.Fprintln(f, e.name)
	}
	log.Printf("wrote %d packages to %s", len(entries), *outPath)
}
