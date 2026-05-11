package calibrate

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/yourusername/npm-proxy/internal/config"
	"gopkg.in/yaml.v3"
)

// WriteCSV dumps every trial as one row. Columns reflect the 2x3 metrics
// split by tier so the dissertation can build separate tables for the strict
// block tier (block_precision/block_recall/hard_fp) and the permissive warn
// tier (warn_precision/warn_recall/soft_fp), plus the aggregate catch and the
// full benign/malicious confusion counts. Followed by every weight key seen
// in the log (sorted).
func WriteCSV(path string, log []Trial, obj ScoreObjective) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	keySet := map[string]struct{}{}
	for _, t := range log {
		for k := range t.Weights {
			keySet[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	header := append([]string{
		"trial", "score", "allow", "block", "min_categories",
		"val_catch",
		"val_block_recall", "val_block_precision", "val_hard_fp",
		"val_warn_recall", "val_warn_precision", "val_soft_fp",
		"benign_allow", "benign_warn", "benign_block",
		"malicious_allow", "malicious_warn", "malicious_block",
	}, keys...)
	if err := w.Write(header); err != nil {
		return err
	}

	for _, t := range log {
		m := t.ValMet
		row := []string{
			strconv.Itoa(t.Index),
			fmt.Sprintf("%.4f", t.Score(obj)),
			fmt.Sprintf("%.3f", t.Allow),
			fmt.Sprintf("%.3f", t.Block),
			strconv.Itoa(t.MinCategories),
			fmt.Sprintf("%.4f", m.CatchRate()),
			fmt.Sprintf("%.4f", m.BlockRate()),
			fmt.Sprintf("%.4f", m.BlockPrecision()),
			fmt.Sprintf("%.4f", m.HardFPRate()),
			fmt.Sprintf("%.4f", m.WarnRecall()),
			fmt.Sprintf("%.4f", m.WarnPrecision()),
			fmt.Sprintf("%.4f", m.SoftFPRate()),
			strconv.Itoa(m.BenignAllow),
			strconv.Itoa(m.BenignWarn),
			strconv.Itoa(m.BenignBlock),
			strconv.Itoa(m.MaliciousAllow),
			strconv.Itoa(m.MaliciousWarn),
			strconv.Itoa(m.MaliciousBlock),
		}
		for _, k := range keys {
			row = append(row, fmt.Sprintf("%.4f", t.Weights[k]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// WriteCalibratedConfig serialises the config to YAML at path. The caller
// should have applied the best Trial's weights and thresholds via
// Weights.ApplyToConfig before calling this.
func WriteCalibratedConfig(path string, cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
