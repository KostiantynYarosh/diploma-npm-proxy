package layer3

import (
	"context"
	"regexp"
	"strings"

	"github.com/yourusername/npm-proxy/internal/signal"
	"github.com/yourusername/npm-proxy/internal/extractor"
)

var (
	// reEval rejects method calls (obj.eval(...)) and identifier prefixes
	// (safeEval(...)) so only bare eval(...) calls match. Many libraries
	// expose .eval() on parser/AST objects without invoking the global one.
	reEval        = regexp.MustCompile(`(?:^|[^.\w$])eval\s*\(`)
	reNewFunction = regexp.MustCompile(`new\s+Function\s*\(`)
	reVMRunThis   = regexp.MustCompile(`vm\.runInThisContext\s*\(`)
	reVMRunNew    = regexp.MustCompile(`vm\.runInNewContext\s*\(`)
	reDynRequire  = regexp.MustCompile(`require\s*\(\s*(?:[^'"` + "`" + `\s][^)]*)\)`)
)

type SinkAnalyzer struct {
	aloneScore        float64
	obfuscationScore  float64
}

func NewSinkAnalyzer(aloneScore, obfuscationScore float64) *SinkAnalyzer {
	return &SinkAnalyzer{aloneScore: aloneScore, obfuscationScore: obfuscationScore}
}

// Analyze finds dangerous sink calls and reports them as scored signals. A
// sink found alongside an obfuscation signal earns the heavier
// obfuscationScore but is no longer an automatic veto - many minified popular
// bundles (e.g. dhtmlx-gantt, loginradius-sdk) legitimately combine high
// entropy with eval/new Function shims, and a hard veto on that pattern
// would block them on every install. The policy engine still aggregates the
// score and may block via the normal threshold path.
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

	// When obfuscation is detected we collapse all sink hits into a single
	// "sink_with_obfuscation" rule (Detail carries the specific sink type)
	// so the calibrator has one weight to tune instead of five identical
	// ones. Without obfuscation we keep per-sink rule names because they
	// rarely co-occur and the granularity is useful in reports.
	//
	// Source is run through stripComments + stripStringContents before regex
	// scanning so docstrings, log messages, and "do not use eval()" warnings
	// in code do not produce phantom sink hits. Real calls are preserved.
	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		scrubbed := stripStringContents(stripComments(string(content)))
		for _, p := range patterns {
			if !p.re.MatchString(scrubbed) {
				continue
			}
			if hasObfuscation {
				signals = appendIfNotPresent(signals, signal.Signal{
					Rule:   "sink_with_obfuscation",
					Score:  s.obfuscationScore,
					CWE:    "CWE-94",
					Detail: p.rule,
				})
				// One sink + obf signal is enough; don't keep adding
				// per-sink dupes for the same package.
				continue
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

// HasSinks returns true if any dangerous sink pattern is present in the file
// tree. Sources are scrubbed of comments and string contents before scanning
// so the same precision rules as Analyze apply here.
func HasSinks(tree extractor.FileTree) bool {
	patterns := []*regexp.Regexp{reEval, reNewFunction, reVMRunThis, reVMRunNew, reDynRequire}
	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		scrubbed := stripStringContents(stripComments(string(content)))
		for _, re := range patterns {
			if re.MatchString(scrubbed) {
				return true
			}
		}
	}
	return false
}

// unused import guard
var _ = strings.Contains
