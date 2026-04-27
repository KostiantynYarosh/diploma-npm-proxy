package layer3

import (
	"context"
	"regexp"
	"strings"

	"github.com/yourusername/npm-proxy/internal/signal"
	"github.com/yourusername/npm-proxy/internal/extractor"
)

var (
	reEval           = regexp.MustCompile(`\beval\s*\(`)
	reNewFunction    = regexp.MustCompile(`new\s+Function\s*\(`)
	reVMRunThis      = regexp.MustCompile(`vm\.runInThisContext\s*\(`)
	reVMRunNew       = regexp.MustCompile(`vm\.runInNewContext\s*\(`)
	reDynRequire     = regexp.MustCompile(`require\s*\(\s*(?:[^'"` + "`" + `\s][^)]*)\)`)
)

type SinkAnalyzer struct {
	aloneScore float64
}

func NewSinkAnalyzer(aloneScore float64) *SinkAnalyzer {
	return &SinkAnalyzer{aloneScore: aloneScore}
}

// Analyze finds dangerous sink calls. If a sink is found together with an obfuscation
// signal (hasObfuscation=true), it returns a veto. Alone, it contributes a score.
func (s *SinkAnalyzer) Analyze(_ context.Context, tree extractor.FileTree, hasObfuscation bool) []signal.Signal {
	patterns := []struct {
		re   *regexp.Regexp
		rule string
	}{
		{reEval, "sink_eval"},
		{reNewFunction, "sink_new_function"},
		{reVMRunThis, "sink_vm_run_this_context"},
		{reVMRunNew, "sink_vm_run_new_context"},
		{reDynRequire, "sink_dynamic_require"},
	}

	var signals []signal.Signal

	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		src := string(content)
		for _, p := range patterns {
			if !p.re.MatchString(src) {
				continue
			}
			if hasObfuscation {
				// Sink + obfuscation = veto.
				return []signal.Signal{{
					Rule: p.rule + "_with_obfuscation",
					Veto: true,
					CWE:  "CWE-94",
				}}
			}
			signals = appendIfNotPresent(signals, signal.Signal{
				Rule:  p.rule,
				Score: s.aloneScore,
				CWE:   "CWE-94",
			})
		}
	}

	return signals
}

func appendIfNotPresent(signals []signal.Signal, s signal.Signal) []signal.Signal {
	for _, existing := range signals {
		if existing.Rule == s.Rule {
			return signals
		}
	}
	return append(signals, s)
}

// HasSinks returns true if any dangerous sink pattern is present in the file tree.
func HasSinks(tree extractor.FileTree) bool {
	patterns := []*regexp.Regexp{reEval, reNewFunction, reVMRunThis, reVMRunNew, reDynRequire}
	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		src := string(content)
		for _, re := range patterns {
			if re.MatchString(src) {
				return true
			}
		}
	}
	return false
}

// unused import guard
var _ = strings.Contains
