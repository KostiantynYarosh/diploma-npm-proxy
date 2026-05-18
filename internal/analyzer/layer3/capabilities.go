package layer3

import (
	"context"
	"regexp"
	"strings"

	"github.com/yourusername/npm-proxy/internal/extractor"
	"github.com/yourusername/npm-proxy/internal/signal"
)

// Capability categories. CapNet is detected but no longer emits a standalone
// signal: calibration zeroed `capability_net_access` across every profile
// because plain network access fires on too many legitimate packages
// (frameworks, HTTP clients, telemetry libs). The capability is still tracked
// here because version-diff comparison needs it to flag a *newly introduced*
// network call in a patch release - see version_diff_new_net_in_patch.
const (
	CapNet     = "net_access"
	CapExec    = "exec"
	CapDynEval = "dynamic_eval"
	CapEnvRead = "env_read"
)

// Import-shape patterns. They MUST be matched on a comments-stripped (but
// strings-preserved) source: the literal module name has to be visible. Both
// require('mod') / require("mod") and ESM `from 'mod'` / `from "mod"` are
// covered. Unicode and escape sequences inside the module string are not
// supported - npm rejects those names anyway.
var (
	reImportNet = regexp.MustCompile(
		`require\s*\(\s*['"](?:http|https|net|dgram|tls)['"]\s*\)` +
			`|from\s+['"](?:http|https|net|dgram|tls)['"]`)
	reImportExec = regexp.MustCompile(
		`require\s*\(\s*['"]child_process['"]\s*\)` +
			`|from\s+['"]child_process['"]`)
)

// Call-shape patterns. They are matched on a fully-stripped source (comments
// + string contents blanked) so things like "// uses eval(" or
// 'message: "do not use eval()"' do not produce phantom hits.
var (
	reEvalCall    = regexp.MustCompile(`(?:^|[^.\w$])eval\s*\(`)
	reNewFuncCall = regexp.MustCompile(`new\s+Function\s*\(`)
	reVMRunCall   = regexp.MustCompile(`vm\s*\.\s*runIn(?:This|New)Context\s*\(`)
	reProcessEnv  = regexp.MustCompile(`process\s*\.\s*env\b`)
)

type CapabilityAnalyzer struct {
	execScore    float64
	dynEvalScore float64
	envReadScore float64
}

func NewCapabilityAnalyzer(exec, dynEval, envRead float64) *CapabilityAnalyzer {
	return &CapabilityAnalyzer{
		execScore:    exec,
		dynEvalScore: dynEval,
		envReadScore: envRead,
	}
}

// Analyze scans all JS/TS files in the tree and returns detected capability
// signals plus the full list of detected capabilities (including CapNet,
// which has no own signal but feeds version-diff). The caller caches both.
func (a *CapabilityAnalyzer) Analyze(_ context.Context, tree extractor.FileTree) ([]signal.Signal, []string) {
	caps := make(map[string]bool)

	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		detectCapabilities(string(content), caps)
		if len(caps) == len(allCaps) {
			break
		}
	}

	var signals []signal.Signal
	var capList []string

	scoreMap := map[string]struct {
		score float64
		rule  string
		cwe   string
	}{
		CapExec:    {a.execScore, "capability_exec", "CWE-78"},
		CapDynEval: {a.dynEvalScore, "capability_dynamic_eval", "CWE-94"},
		CapEnvRead: {a.envReadScore, "capability_env_read", ""},
	}

	for cap, detected := range caps {
		if !detected {
			continue
		}
		capList = append(capList, cap)
		if info, ok := scoreMap[cap]; ok {
			signals = append(signals, signal.Signal{
				Rule:  info.rule,
				Score: info.score,
				CWE:   info.cwe,
			})
		}
	}

	return signals, capList
}

var allCaps = []string{CapNet, CapExec, CapDynEval, CapEnvRead}

// detectCapabilities walks one source file and updates the capability set.
// Two scrubbed views of the source are used:
//
//   - noComments: comments removed but string literals intact - used for
//     import-shape patterns whose match depends on the literal module name
//     (require('child_process'), import http from 'http', ...).
//   - noStrings : on top of noComments, string contents blanked - used for
//     call-shape patterns (eval(, new Function(, vm.run...) and identifier
//     lookups (process.env). This kills "// uses eval" and
//     "msg = 'do not eval()'" false hits without dropping real call sites.
//
// This is the substitute for full AST analysis: cheap, deterministic, and
// removes the dominant false-match source on the npm corpus.
func detectCapabilities(src string, caps map[string]bool) {
	noComments := stripComments(src)
	noStrings := stripStringContents(noComments)

	if !caps[CapNet] && reImportNet.MatchString(noComments) {
		caps[CapNet] = true
	}
	if !caps[CapExec] && reImportExec.MatchString(noComments) {
		caps[CapExec] = true
	}

	if !caps[CapDynEval] &&
		(reEvalCall.MatchString(noStrings) ||
			reNewFuncCall.MatchString(noStrings) ||
			reVMRunCall.MatchString(noStrings)) {
		caps[CapDynEval] = true
	}

	if !caps[CapEnvRead] && reProcessEnv.MatchString(noStrings) {
		caps[CapEnvRead] = true
	}
}

func isJSFile(path string) bool {
	return strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".mjs") ||
		strings.HasSuffix(path, ".cjs") ||
		strings.HasSuffix(path, ".ts")
}
