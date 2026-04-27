package layer2

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/yourusername/npm-proxy/internal/extractor"
	"github.com/yourusername/npm-proxy/internal/signal"
)

var (
	reCurlPipe    = regexp.MustCompile(`curl\s+[^\s]+\s*\|\s*(ba)?sh`)
	reWgetPipe    = regexp.MustCompile(`wget\s+[^\s]+\s*\|\s*(ba)?sh`)
	reBase64Exec  = regexp.MustCompile(`base64\s+-d`)
	reNodeEval    = regexp.MustCompile(`node\s+-e\s+`)
	reExternalURL = regexp.MustCompile(`https?://[^\s'"]+`)
	reChildProc   = regexp.MustCompile(`(require\s*\(\s*['"]child_process['"]\s*\)|child_process)`)
	reEvalCall    = regexp.MustCompile(`\beval\s*\(`)
	reDynamicReq  = regexp.MustCompile(`require\s*\(\s*[^'"` + "`" + `]`)
)

var lifecycleScripts = []string{"preinstall", "install", "postinstall", "preuninstall", "prepare"}

type packageJSON struct {
	Scripts map[string]string `json:"scripts"`
}

// Scores groups every score-bearing rule weight for the install-script analyzer.
// Weights come from configs/proxy.yaml so they can be tuned without recompilation.
type Scores struct {
	Present         float64
	Base64          float64
	ChildProcess    float64
	Eval            float64
	NodeEval        float64
	DynamicRequire  float64
	ExternalURL     float64
}

type InstallScriptAnalyzer struct {
	scores Scores
}

func NewInstallScriptAnalyzer(scores Scores) *InstallScriptAnalyzer {
	return &InstallScriptAnalyzer{scores: scores}
}

func (a *InstallScriptAnalyzer) Analyze(_ context.Context, tree extractor.FileTree) []signal.Signal {
	pkg := findPackageJSON(tree)
	if pkg == nil {
		return nil
	}

	var signals []signal.Signal
	hasScript := false

	for _, hook := range lifecycleScripts {
		script, ok := pkg.Scripts[hook]
		if !ok || strings.TrimSpace(script) == "" {
			continue
		}
		hasScript = true
		signals = append(signals, a.regexPass(hook, script)...)
	}

	// Veto immediately if any veto signal was produced (pipe-to-shell patterns).
	for _, s := range signals {
		if s.Veto {
			return signals
		}
	}

	if hasScript && len(signals) == 0 {
		signals = append(signals, signal.Signal{
			Rule:  "install_script_present",
			Score: a.scores.Present,
			CWE:   "CWE-506",
		})
	}
	return signals
}

// regexPass scans one lifecycle script value. Only pipe-to-shell patterns produce a veto;
// all other dangerous patterns contribute scored signals whose weights come from config.
func (a *InstallScriptAnalyzer) regexPass(hook, script string) []signal.Signal {
	var signals []signal.Signal

	// Veto-level: pipe-to-shell is the only pattern with no legitimate use in npm scripts.
	if reCurlPipe.MatchString(script) {
		return []signal.Signal{{Rule: "install_script_curl_pipe_" + hook, Veto: true, CWE: "CWE-506"}}
	}
	if reWgetPipe.MatchString(script) {
		return []signal.Signal{{Rule: "install_script_wget_pipe_" + hook, Veto: true, CWE: "CWE-506"}}
	}

	// Scored signals - legitimate packages can use these, so contribute to the aggregate score.
	if reBase64Exec.MatchString(script) {
		signals = append(signals, signal.Signal{Rule: "install_script_base64_decode_" + hook, Score: a.scores.Base64, CWE: "CWE-506"})
	}
	if reChildProc.MatchString(script) {
		signals = append(signals, signal.Signal{Rule: "install_script_child_process_" + hook, Score: a.scores.ChildProcess, CWE: "CWE-506"})
	}
	if reEvalCall.MatchString(script) {
		signals = append(signals, signal.Signal{Rule: "install_script_eval_" + hook, Score: a.scores.Eval, CWE: "CWE-506"})
	}
	if reNodeEval.MatchString(script) {
		signals = append(signals, signal.Signal{Rule: "install_script_node_eval_" + hook, Score: a.scores.NodeEval, CWE: "CWE-506"})
	}
	if reDynamicReq.MatchString(script) {
		signals = append(signals, signal.Signal{Rule: "install_script_dynamic_require_" + hook, Score: a.scores.DynamicRequire, CWE: "CWE-506"})
	}
	if reExternalURL.MatchString(script) {
		signals = append(signals, signal.Signal{Rule: "install_script_external_url_" + hook, Score: a.scores.ExternalURL, CWE: "CWE-506"})
	}

	return signals
}

func findPackageJSON(tree extractor.FileTree) *packageJSON {
	for path, content := range tree {
		if strings.HasSuffix(path, "package/package.json") || path == "package.json" {
			var pkg packageJSON
			if err := json.Unmarshal(content, &pkg); err == nil {
				return &pkg
			}
		}
	}
	return nil
}
